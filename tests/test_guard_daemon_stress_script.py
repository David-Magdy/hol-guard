from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

import scripts.stress_guard_daemon as stress_script
from scripts.stress_guard_daemon import StressResult


def test_daemon_stress_gate_keeps_fresh_process_alive_with_populated_store() -> None:
    script = Path(__file__).parents[1] / "scripts" / "stress_guard_daemon.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--requests=12",
            "--receipts=2000",
            "--settle-seconds=0",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    loaded = cast(object, json.loads(completed.stdout))
    assert isinstance(loaded, dict)
    result = cast(dict[str, object], loaded)

    assert completed.returncode == 0, completed.stderr
    assert result["passed"] is True
    assert result["responses"] == 12
    assert result["errors"] == 0
    assert result["health_failures"] == 0
    assert result["pid_stable"] is True
    assert result["daemon_process_count"] == 1
    assert isinstance(result["database_bytes"], int)
    assert result["database_bytes"] > 0
    if os.name != "nt":
        rss_baseline = cast(int, result["rss_baseline_bytes"])
        rss_peak = cast(int, result["rss_peak_bytes"])
        assert rss_baseline > 0
        assert rss_peak >= rss_baseline
    lifecycle_events = result["lifecycle_events"]
    assert isinstance(lifecycle_events, list)
    assert "ready" in lifecycle_events


def test_soak_gate_requires_request_count_resources_and_rss_bound() -> None:
    result = StressResult(
        requests=100_000,
        receipts=250_000,
        responses=100_000,
        errors=0,
        p95_ms=2.0,
        max_ms=4.0,
        health_checks=1,
        health_failures=0,
        pid_stable=True,
        daemon_process_count=1,
        max_hook_latency_ms=4_500.0,
        database_bytes=1,
        lifecycle_events=("ready",),
        max_threads=32,
        max_file_descriptors=128,
        rss_baseline_bytes=100,
        rss_peak_bytes=109,
        rss_growth=0.09,
    )
    assert result.soak_passed
    assert not replace(result, rss_growth=0.11).soak_passed
    assert not replace(result, requests=99_999).soak_passed
    assert not replace(result, receipts=249_999).soak_passed


def test_enforced_soak_rejects_a_short_run_instead_of_claiming_proof() -> None:
    script = Path(__file__).parents[1] / "scripts" / "stress_guard_daemon.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script),
            "--requests=12",
            "--receipts=2000",
            "--enforce-soak",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 2
    assert "requires at least 100000 requests and 250000 receipts" in completed.stderr


def test_soak_baseline_stabilizes_bounded_worker_capacity_before_measurement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution = stress_script._StressExecution(
        daemon_url="http://127.0.0.1:1",
        endpoint="http://127.0.0.1:1/v1/hooks/pi",
        auth_token="token",
        initial_pid=123,
        guard_home=Path("guard-home"),
    )
    reports = iter(
        (
            {"hook_workers": {"configured": 4, "target": 2, "workers": 2, "ready": 2, "busy": 0}},
            {"hook_workers": {"configured": 4, "target": 2, "workers": 1, "ready": 1, "busy": 1}},
            {"hook_workers": {"configured": 4, "target": 4, "workers": 4, "ready": 4, "busy": 0}},
        )
    )
    requests: list[str] = []

    monkeypatch.setattr(stress_script, "_WARMUP_CONCURRENCY", 4)
    monkeypatch.setattr(stress_script, "_healthz_details", lambda _execution: next(reports))
    monkeypatch.setattr(stress_script, "_stress_request", lambda *_args: requests.append("request") or 1.0)

    stress_script._stabilize_full_worker_capacity(execution)

    assert len(requests) == 4
    assert execution.latencies_ms == []


def test_stress_cleanup_preserves_resident_before_daemon_retirement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    monkeypatch.setattr(stress_script, "_stop_native_runtime", lambda _guard_home: events.append("resident-stop"))
    monkeypatch.setattr(
        stress_script,
        "_request_graceful_daemon_stop",
        lambda _guard_home: events.append("daemon-worker-close"),
    )
    monkeypatch.setattr(
        stress_script,
        "retire_all_guard_daemons_for_home",
        lambda _guard_home: events.append("daemon-retire") or [],
    )
    monkeypatch.setattr(stress_script, "guard_daemon_retirement_is_complete", lambda _guard_home: True)

    assert stress_script._cleanup_stress_runtime(Path("guard-home")) is True
    assert events == ["resident-stop", "daemon-worker-close", "daemon-retire"]


def test_stress_cleanup_reports_leftover_daemon(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(stress_script, "_stop_native_runtime", lambda _guard_home: None)
    monkeypatch.setattr(stress_script, "_request_graceful_daemon_stop", lambda _guard_home: None)
    monkeypatch.setattr(stress_script, "retire_all_guard_daemons_for_home", lambda _guard_home: [])
    monkeypatch.setattr(stress_script, "guard_daemon_retirement_is_complete", lambda _guard_home: False)

    assert stress_script._cleanup_stress_runtime(Path("guard-home")) is False
