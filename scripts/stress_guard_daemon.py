#!/usr/bin/env python3
"""Exercise a fresh Guard daemon against a populated local store."""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from http.client import HTTPResponse
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.daemon.discovery import load_authenticated_daemon_state
from codex_plugin_scanner.guard.daemon.lifecycle_journal import load_daemon_lifecycle_events
from codex_plugin_scanner.guard.daemon.manager import (
    ensure_guard_daemon,
    guard_daemon_process_count,
    load_guard_daemon_auth_token,
    retire_all_guard_daemons_for_home,
)
from codex_plugin_scanner.guard.store import GuardStore


@dataclass(frozen=True, slots=True)
class StressResult:
    requests: int
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
        guard_home = root / "guard-home"
        home = root / "home"
        workspace = root / "workspace"
        home.mkdir()
        workspace.mkdir()
        store = GuardStore(guard_home, prime_policy_integrity=False)
        seed_receipts(store, count=receipt_count)
        daemon_url = ensure_guard_daemon(guard_home, home_dir=home)
        state = load_authenticated_daemon_state(guard_home)
        auth_token = load_guard_daemon_auth_token(guard_home)
        if state is None or auth_token is None:
            raise RuntimeError("Fresh daemon did not publish authenticated state.")
        initial_pid = cast(int, state["pid"])
        query = urllib.parse.urlencode(
            {
                "guard-home": str(guard_home),
                "home": str(home),
                "workspace": str(workspace),
            }
        )
        endpoint = f"{daemon_url}/v1/hooks/pi?{query}"
        latencies_ms: list[float] = []
        errors: list[str] = []
        response_count = 0
        response_lock = threading.Lock()

        def review(index: int) -> None:
            nonlocal response_count
            request = urllib.request.Request(
                endpoint,
                data=json.dumps(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "Bash",
                        "tool_input": {"command": f"echo stress-{index}"},
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": auth_token,
                },
                method="POST",
            )
            started = time.monotonic()
            try:
                with cast(HTTPResponse, urllib.request.urlopen(request, timeout=6)) as response:
                    payload = cast(object, json.loads(response.read().decode("utf-8")))
                if not isinstance(payload, dict):
                    raise RuntimeError("Hook response was not an object.")
                elapsed_ms = (time.monotonic() - started) * 1000
                with response_lock:
                    latencies_ms.append(elapsed_ms)
                    response_count += 1
            except Exception as error:
                with response_lock:
                    errors.append(type(error).__name__)

        health_checks = 0
        health_failures = 0
        pid_stable = True
        process_count: int | None = None
        try:
            with ThreadPoolExecutor(max_workers=request_count) as executor:
                futures = [executor.submit(review, index) for index in range(request_count)]
                while any(not future.done() for future in futures):
                    health_checks += 1
                    if not _health_is_ready(daemon_url):
                        health_failures += 1
                    time.sleep(0.05)
                for future in futures:
                    future.result()
            settle_deadline = time.monotonic() + settle_seconds
            while time.monotonic() < settle_deadline:
                health_checks += 1
                if not _health_is_ready(daemon_url):
                    health_failures += 1
                current_state = load_authenticated_daemon_state(guard_home)
                pid_stable = (
                    pid_stable
                    and current_state is not None
                    and current_state.get("pid") == initial_pid
                    and _pid_is_running(initial_pid)
                )
                time.sleep(min(0.25, max(0.0, settle_deadline - time.monotonic())))
            health_checks += 1
            if not _health_is_ready(daemon_url):
                health_failures += 1
            final_state = load_authenticated_daemon_state(guard_home)
            pid_stable = (
                pid_stable
                and final_state is not None
                and final_state.get("pid") == initial_pid
                and _pid_is_running(initial_pid)
            )
            process_count = guard_daemon_process_count(guard_home)
        finally:
            _ = retire_all_guard_daemons_for_home(guard_home)

        sorted_latencies = sorted(latencies_ms)
        p95_index = min(len(sorted_latencies) - 1, int(len(sorted_latencies) * 0.95))
        events = load_daemon_lifecycle_events(guard_home)
        return StressResult(
            requests=request_count,
            responses=response_count,
            errors=len(errors),
            p95_ms=round(sorted_latencies[p95_index], 2) if sorted_latencies else 0.0,
            max_ms=round(max(sorted_latencies), 2) if sorted_latencies else 0.0,
            health_checks=health_checks,
            health_failures=health_failures,
            pid_stable=pid_stable,
            daemon_process_count=process_count,
            max_hook_latency_ms=max_hook_latency_ms,
            database_bytes=store.path.stat().st_size,
            lifecycle_events=tuple(str(event["event"]) for event in events),
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
    args = parser.parse_args()
    result = run_stress(
        request_count=cast(int, args.requests),
        receipt_count=cast(int, args.receipts),
        settle_seconds=cast(float, args.settle_seconds),
        max_hook_latency_ms=cast(float, args.max_hook_latency_ms),
    )
    payload = {**asdict(result), "passed": result.passed}
    print(json.dumps(payload, sort_keys=True))
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
