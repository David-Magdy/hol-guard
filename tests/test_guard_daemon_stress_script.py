from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import cast

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
        assert result["rss_baseline_bytes"] > 0
        assert result["rss_peak_bytes"] >= result["rss_baseline_bytes"]
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
