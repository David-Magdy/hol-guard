from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_LAUNCHER = _REPOSITORY_ROOT / "scripts" / "mdm" / "run-local-lab-container.py"


def test_local_mdm_container_launcher_disables_network() -> None:
    completed = subprocess.run(
        [sys.executable, str(_LAUNCHER), "--dry-run"],
        check=False,
        cwd=_REPOSITORY_ROOT,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    commands = json.loads(completed.stdout)
    assert commands["build"] == [
        "docker",
        "build",
        "--tag",
        "hol-guard-mdm-local-lab:local",
        "--file",
        str(_REPOSITORY_ROOT / "scripts" / "mdm" / "Dockerfile.local-lab"),
        str(_REPOSITORY_ROOT),
    ]
    assert commands["run"] == [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--mount",
        f"type=bind,src={_REPOSITORY_ROOT},dst=/hol-guard-source,readonly",
        "hol-guard-mdm-local-lab:local",
        "--json",
    ]
