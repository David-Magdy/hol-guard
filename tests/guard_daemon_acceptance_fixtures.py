"""Deterministic workload fixtures for the daemon admission acceptance gate."""

from __future__ import annotations

import json
import os
import resource
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import TypedDict, cast

from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "guard-daemon-acceptance" / "workloads.json"


class ClientSpec(TypedDict):
    harness: str
    client: str
    requests: int
    concurrency: int


class WorkloadSpec(TypedDict):
    id: str
    clients: list[ClientSpec]
    secret_stride: int


@dataclass(frozen=True, slots=True)
class WorkloadResult:
    fixture_id: str
    requests: int
    routine_allowed: int
    secrets_denied: int
    capacity_denials: int
    generic_failures: int
    pid_stable: bool
    workers_stable: bool
    queue_bounded: bool
    rss_growth_bytes: int
    p95_ms: float
    p99_ms: float
    browser_launches: int
    inbox_requests: int
    dispatch_counts: dict[str, int]


def load_correctness_workloads() -> tuple[WorkloadSpec, ...]:
    payload = cast(dict[str, object], json.loads(FIXTURE_PATH.read_text(encoding="utf-8")))
    return tuple(cast(list[WorkloadSpec], payload["correctness"]))


def run_workload(spec: WorkloadSpec) -> WorkloadResult:
    """Run a bounded workload through the production admission scheduler."""

    request_count = sum(client["requests"] for client in spec["clients"])
    max_workers = sum(client["concurrency"] for client in spec["clients"])
    scheduler = RuntimeHookScheduler(
        active_limit=max(8, max_workers),
        per_harness_active_limit=max(8, max_workers),
        queued_limit=request_count,
        per_harness_queued_limit=request_count,
        per_client_queued_limit=request_count,
        retained_bytes_limit=max(1024, request_count * 16),
    )
    initial_pid = os.getpid()
    initial_workers = threading.active_count()
    initial_rss = _rss_bytes()
    outcomes: Counter[str] = Counter()
    dispatch: Counter[str] = Counter()
    latencies_ms: list[float] = []
    lock = threading.Lock()

    def review(harness: str, client: str, index: int) -> None:
        started = time.monotonic()
        admission = scheduler.acquire(
            harness=harness,
            client_key=client,
            lane="decision",
            payload_bytes=16,
            deadline=started + 10,
        )
        if admission.permit is None:
            outcome = admission.reason_code or "generic_failure"
        else:
            try:
                # Fixture labels carry no command, path, prompt, or secret material.
                outcome = "secret_denied" if index % spec["secret_stride"] == 0 else "routine_allowed"
                with lock:
                    dispatch[harness] += 1
            finally:
                admission.permit.release()
        elapsed_ms = (time.monotonic() - started) * 1000
        with lock:
            outcomes[outcome] += 1
            latencies_ms.append(elapsed_ms)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(review, client["harness"], client["client"], index)
            for client in spec["clients"]
            for index in range(client["requests"])
        ]
        for future in futures:
            future.result(timeout=15)

    ordered = sorted(latencies_ms)
    stats = scheduler.stats()
    return WorkloadResult(
        fixture_id=spec["id"],
        requests=request_count,
        routine_allowed=outcomes["routine_allowed"],
        secrets_denied=outcomes["secret_denied"],
        capacity_denials=sum(value for key, value in outcomes.items() if key.startswith("daemon_hook_")),
        generic_failures=outcomes["generic_failure"],
        pid_stable=os.getpid() == initial_pid,
        workers_stable=threading.active_count() <= initial_workers + 1,
        queue_bounded=stats["queued"] <= stats["queued_limit"] and stats["retained_bytes"] == 0,
        rss_growth_bytes=max(0, _rss_bytes() - initial_rss),
        p95_ms=_percentile(ordered, 0.95),
        p99_ms=_percentile(ordered, 0.99),
        browser_launches=0,
        inbox_requests=0,
        dispatch_counts=dict(dispatch),
    )


def _percentile(ordered: list[float], fraction: float) -> float:
    if not ordered:
        return 0.0
    index = min(len(ordered) - 1, max(0, int(len(ordered) * fraction)))
    return round(ordered[index], 3)


def _rss_bytes() -> int:
    maximum_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(maximum_rss if os.uname().sysname == "Darwin" else maximum_rss * 1024)
