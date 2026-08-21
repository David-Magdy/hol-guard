from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_managed_controls_release_gate() -> None:
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "scripts/ci/managed_controls_release_gate.py"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
