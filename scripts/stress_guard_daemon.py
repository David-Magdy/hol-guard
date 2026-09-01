#!/usr/bin/env python3
"""Exercise a fresh Guard daemon against a populated local store."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from http.client import HTTPResponse
from pathlib import Path
from typing import cast

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.append(str(_REPO_ROOT))

from codex_plugin_scanner.guard.daemon.discovery import load_authenticated_daemon_state  # noqa: E402
from codex_plugin_scanner.guard.daemon.lifecycle_journal import load_daemon_lifecycle_events  # noqa: E402
from codex_plugin_scanner.guard.daemon.manager import (  # noqa: E402
    ensure_guard_daemon,
    guard_daemon_process_count,
    load_guard_daemon_auth_token,
    retire_all_guard_daemons_for_home,
)
from codex_plugin_scanner.guard.native_runtime import native_runtime_status  # noqa: E402
from codex_plugin_scanner.guard.store import GuardStore  # noqa: E402
from scripts.native_slo_adapter import process_resources  # noqa: E402
from scripts.native_slo_contract import clear_proof_environment, proof_environment_violations  # noqa: E402

_SOAK_MIN_REQUESTS = 100_000
_SOAK_MIN_RECEIPTS = 250_000
_SOAK_MAX_THREADS = 128
_SOAK_MAX_FILE_DESCRIPTORS = 512
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_WARMUP_CONCURRENCY = 64


@dataclass(frozen=True, slots=True)
class StressResult:
    requests: int
    receipts: int
    responses: int
    errors: int
    p95_ms: float
    max_ms: float
    health_checks: int
    health_failures: int
    pid_stable: bool
    daemon_process_count: int | None
    max_hook_latency_ms: float
    database_bytes: int
    lifecycle_events: tuple[str, ...]
    max_threads: int
    max_file_descriptors: int
    rss_baseline_bytes: int
    rss_peak_bytes: int
    rss_growth: float

    @property
    def passed(self) -> bool:
        return (
            self.responses == self.requests
            and self.errors == 0
            and self.health_checks > 0
            and self.health_failures == 0
            and self.pid_stable
            and self.daemon_process_count == 1
            and self.max_ms < self.max_hook_latency_ms
        )

    @property
    def soak_passed(self) -> bool:
        """Apply the bounded 100k soak contract to a completed run."""

        return (
            self.passed
            and self.requests >= _SOAK_MIN_REQUESTS
            and self.receipts >= _SOAK_MIN_RECEIPTS
            and self.rss_baseline_bytes > 0
            and self.rss_growth <= 0.10
            and 0 < self.max_threads <= _SOAK_MAX_THREADS
            and 0 < self.max_file_descriptors <= _SOAK_MAX_FILE_DESCRIPTORS
        )


def _process_resources(pid: int) -> tuple[int, int, int] | None:
    """Read current aggregate process-tree resources without retaining command data."""

    resources = process_resources(pid)
    if resources is None:
        return None
    return resources.rss_bytes, resources.threads, resources.file_descriptors


def _wait_for_process_resources(pid: int, *, timeout_seconds: float = 2.0) -> tuple[int, int, int] | None:
    """Wait briefly for a newly spawned daemon to publish measurable resources."""

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        resources = _process_resources(pid)
        if resources is not None:
            return resources
        time.sleep(0.01)
    return _process_resources(pid)


def _stabilized_process_resources(pid: int) -> tuple[int, int, int] | None:
    """Capture a post-warmup ceiling so lazy worker startup is not counted as a leak."""

    samples: list[tuple[int, int, int]] = []
    for _ in range(3):
        resources = _wait_for_process_resources(pid)
        if resources is not None:
            samples.append(resources)
        time.sleep(0.1)
    if not samples:
        return None
    return (
        max(sample[0] for sample in samples),
        max(sample[1] for sample in samples),
        max(sample[2] for sample in samples),
    )


def _count_fixture_receipts(store: GuardStore) -> int:
    """Return the committed fixture count; never trust the requested count alone."""

    connection = sqlite3.connect(store.path, timeout=30)
    try:
        row = connection.execute(
            "select count(*) from runtime_receipts where receipt_id like 'stress-%'"
        ).fetchone()
    finally:
        connection.close()
    if not row or not isinstance(row[0], int):
        raise RuntimeError("Could not verify the stress receipt fixture.")
    return row[0]


def _stop_native_runtime(guard_home: Path) -> None:
    """Stop the exact package-bound resident before its temporary state is removed."""

    status = native_runtime_status()
    identity = status.identity
    if identity is None:
        return
    try:
        _ = subprocess.run(
            (
                str(identity.path),
                "resident-stop",
                "--state-dir",
                str(guard_home / "native-runtime"),
            ),
            check=False,
            capture_output=True,
            timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        # The stress result is still evaluated from the daemon's observed
        # state. Never allow cleanup diagnostics to mask that result.
        return


def seed_receipts(store: GuardStore, *, count: int) -> None:
    """Populate the high-volume receipt table in one bounded fixture transaction."""

    if count <= 0:
        return
    connection = sqlite3.connect(store.path, timeout=30)
    try:
        _ = connection.execute(
            """
            with recursive fixture(value) as (
              select 1
              union all
              select value + 1 from fixture where value < ?
            )
            insert into runtime_receipts (
              receipt_id,
              harness,
              artifact_id,
              artifact_hash,
              policy_decision,
              changed_capabilities_json,
              provenance_summary,
              timestamp
            )
            select
              printf('stress-%09d', value),
              'stress',
              'stress-artifact',
              printf('%064d', value),
              'allow',
              '[]',
              'stress-fixture',
              '2026-07-25T00:00:00+00:00'
            from fixture
            """,
            (count,),
        )
        connection.commit()
    finally:
        connection.close()


@dataclass
class _StressExecution:
    endpoint: str
    auth_token: str
    initial_pid: int
    latencies_ms: list[float] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    health_checks: int = 0
    health_failures: int = 0
    pid_stable: bool = True
    process_count: int | None = None
    rss_baseline_bytes: int = 0
    rss_peak_bytes: int = 0
    max_threads: int = 0
    max_file_descriptors: int = 0


def _stress_request(endpoint: str, auth_token: str) -> float:
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo stress"},
            }
        ).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": auth_token},
        method="POST",
    )
    started = time.monotonic()
    with cast(HTTPResponse, urllib.request.urlopen(request, timeout=6)) as response:
        body = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(body) > _MAX_RESPONSE_BYTES:
        raise RuntimeError("Hook response exceeded the bounded stress limit.")
    payload = cast(object, json.loads(body.decode("utf-8")))
    if not isinstance(payload, dict):
        raise RuntimeError("Hook response was not an object.")
    return (time.monotonic() - started) * 1000


def _stress_warmup(endpoint: str, auth_token: str, count: int) -> None:
    with ThreadPoolExecutor(max_workers=count) as executor:
        futures = [executor.submit(_stress_request, endpoint, auth_token) for _ in range(count)]
        for future in futures:
            future.result(timeout=6)


def _record_resources(execution: _StressExecution, resources: tuple[int, int, int] | None) -> None:
    if resources is None:
        return
    execution.rss_peak_bytes = max(execution.rss_peak_bytes, resources[0])
    execution.max_threads = max(execution.max_threads, resources[1])
    execution.max_file_descriptors = max(execution.max_file_descriptors, resources[2])


def _sample_stress_runtime(execution: _StressExecution) -> None:
    execution.health_checks += 1
    if not _health_is_ready(execution.endpoint.split("/v1/", 1)[0]):
        execution.health_failures += 1
    _record_resources(execution, _process_resources(execution.initial_pid))


def _collect_batch(execution: _StressExecution, futures: list[Future[float]]) -> None:
    for future in futures:
        try:
            execution.latencies_ms.append(future.result())
        except Exception as error:
            execution.errors.append(type(error).__name__)


def _run_stress_batches(execution: _StressExecution, request_count: int) -> None:
    max_workers = min(request_count, 32)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for start in range(0, request_count, max_workers):
            futures = [
                executor.submit(_stress_request, execution.endpoint, execution.auth_token)
                for _ in range(min(max_workers, request_count - start))
            ]
            while not all(future.done() for future in futures):
                _sample_stress_runtime(execution)
                time.sleep(0.05)
            _collect_batch(execution, futures)


def _initialize_stress_resources(execution: _StressExecution) -> None:
    resources = _stabilized_process_resources(execution.initial_pid)
    if resources is None:
        return
    execution.rss_baseline_bytes = resources[0]
    execution.rss_peak_bytes = resources[0]
    execution.max_threads = resources[1]
    execution.max_file_descriptors = resources[2]


def _update_pid_stability(execution: _StressExecution, guard_home: Path) -> None:
    state = load_authenticated_daemon_state(guard_home)
    execution.pid_stable = (
        execution.pid_stable
        and state is not None
        and state.get("pid") == execution.initial_pid
        and _pid_is_running(execution.initial_pid)
    )


def _settle_stress_runtime(execution: _StressExecution, guard_home: Path, settle_seconds: float) -> None:
    deadline = time.monotonic() + settle_seconds
    while time.monotonic() < deadline:
        _sample_stress_runtime(execution)
        _update_pid_stability(execution, guard_home)
        time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))


def _finalize_stress_runtime(execution: _StressExecution, guard_home: Path) -> None:
    _sample_stress_runtime(execution)
    _update_pid_stability(execution, guard_home)
    execution.process_count = guard_daemon_process_count(guard_home)
    _record_resources(execution, _process_resources(execution.initial_pid))


def _prepare_stress_execution(root: Path, receipt_count: int) -> tuple[GuardStore, _StressExecution, Path]:
    guard_home = root / "guard-home"
    home = root / "home"
    workspace = root / "workspace"
    home.mkdir()
    workspace.mkdir()
    store = GuardStore(guard_home, prime_policy_integrity=False)
    seed_receipts(store, count=receipt_count)
    committed_receipts = _count_fixture_receipts(store)
    if committed_receipts != receipt_count:
        raise RuntimeError(
            f"Stress fixture count mismatch: requested={receipt_count} committed={committed_receipts}."
        )
    daemon_url = ensure_guard_daemon(guard_home, home_dir=home)
    state = load_authenticated_daemon_state(guard_home)
    auth_token = load_guard_daemon_auth_token(guard_home)
    if state is None or auth_token is None:
        raise RuntimeError("Fresh daemon did not publish authenticated state.")
    query = urllib.parse.urlencode({"guard-home": guard_home, "home": home, "workspace": workspace})
    execution = _StressExecution(
        endpoint=f"{daemon_url}/v1/hooks/pi?{query}",
        auth_token=auth_token,
        initial_pid=cast(int, state["pid"]),
    )
    return store, execution, guard_home


def _stress_result(
    execution: _StressExecution,
    store: GuardStore,
    guard_home: Path,
    *,
    request_count: int,
    receipt_count: int,
    max_hook_latency_ms: float,
) -> StressResult:
    latencies = sorted(execution.latencies_ms)
    p95_index = min(len(latencies) - 1, int(len(latencies) * 0.95))
    events = load_daemon_lifecycle_events(guard_home)
    return StressResult(
        requests=request_count,
        receipts=receipt_count,
        responses=len(latencies),
        errors=len(execution.errors),
        p95_ms=round(latencies[p95_index], 2) if latencies else 0.0,
        max_ms=round(max(latencies), 2) if latencies else 0.0,
        health_checks=execution.health_checks,
        health_failures=execution.health_failures,
        pid_stable=execution.pid_stable,
        daemon_process_count=execution.process_count,
        max_hook_latency_ms=max_hook_latency_ms,
        database_bytes=store.path.stat().st_size,
        lifecycle_events=tuple(str(event["event"]) for event in events),
        max_threads=execution.max_threads,
        max_file_descriptors=execution.max_file_descriptors,
        rss_baseline_bytes=execution.rss_baseline_bytes,
        rss_peak_bytes=execution.rss_peak_bytes,
        rss_growth=(
            round(max(0, execution.rss_peak_bytes - execution.rss_baseline_bytes) / execution.rss_baseline_bytes, 6)
            if execution.rss_baseline_bytes
            else 0.0
        ),
    )


def run_stress(
    *,
    request_count: int,
    receipt_count: int,
    settle_seconds: float,
    max_hook_latency_ms: float = 4_500.0,
) -> StressResult:
    if request_count <= 0:
        raise ValueError("request_count must be positive")
    if receipt_count < 0:
        raise ValueError("receipt_count must be non-negative")
    if settle_seconds < 0:
        raise ValueError("settle_seconds must be non-negative")
    if max_hook_latency_ms <= 0:
        raise ValueError("max_hook_latency_ms must be positive")

    with tempfile.TemporaryDirectory(prefix="hol-guard-daemon-stress-") as temporary:
        root = Path(temporary)
        store, execution, guard_home = _prepare_stress_execution(root, receipt_count)
        try:
            execution.health_checks += 1
            if not _health_is_ready(execution.endpoint.split("/v1/", 1)[0]):
                execution.health_failures += 1
            warmup_count = min(_WARMUP_CONCURRENCY, max(4, request_count))
            _stress_warmup(execution.endpoint, execution.auth_token, warmup_count)
            _initialize_stress_resources(execution)
            _run_stress_batches(execution, request_count)
            _settle_stress_runtime(execution, guard_home, settle_seconds)
            _finalize_stress_runtime(execution, guard_home)
        finally:
            _stop_native_runtime(guard_home)
            _ = retire_all_guard_daemons_for_home(guard_home)
        return _stress_result(
            execution,
            store,
            guard_home,
            request_count=request_count,
            receipt_count=receipt_count,
            max_hook_latency_ms=max_hook_latency_ms,
        )


def _health_is_ready(daemon_url: str) -> bool:
    try:
        with cast(
            HTTPResponse,
            urllib.request.urlopen(f"{daemon_url}/healthz", timeout=0.5),
        ) as response:
            payload = cast(object, json.loads(response.read().decode("utf-8")))
    except Exception:
        return False
    if not isinstance(payload, dict):
        return False
    return cast(dict[object, object], payload).get("ok") is True


def _pid_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--requests", type=int, default=50)
    _ = parser.add_argument("--receipts", type=int, default=250_000)
    _ = parser.add_argument("--settle-seconds", type=float, default=60.0)
    _ = parser.add_argument("--max-hook-latency-ms", type=float, default=4_500.0)
    _ = parser.add_argument("--enforce-soak", action="store_true")
    _ = parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if args.enforce_soak:
        if args.requests < _SOAK_MIN_REQUESTS or args.receipts < _SOAK_MIN_RECEIPTS:
            parser.error("--enforce-soak requires at least 100000 requests and 250000 receipts")
        _ = clear_proof_environment()
        violations = proof_environment_violations()
        if violations:
            parser.error(f"native proof environment is not clean: {', '.join(violations)}")
    result = run_stress(
        request_count=cast(int, args.requests),
        receipt_count=cast(int, args.receipts),
        settle_seconds=cast(float, args.settle_seconds),
        max_hook_latency_ms=cast(float, args.max_hook_latency_ms),
    )
    payload = {**asdict(result), "passed": result.passed, "soak_passed": result.soak_passed}
    rendered = json.dumps(payload, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.write_text(rendered + "\n", encoding="utf-8")
    return 0 if (result.soak_passed if args.enforce_soak else result.passed) else 1


if __name__ == "__main__":
    raise SystemExit(main())
