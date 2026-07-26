from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import cast


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
    lifecycle_events = result["lifecycle_events"]
    assert isinstance(lifecycle_events, list)
    assert "ready" in lifecycle_events
