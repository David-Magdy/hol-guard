#!/usr/bin/env python3
"""Install an exact HOL Guard wheel with pipx and prove the Secrets CLI works."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def run(args: list[str], *, env: dict[str, str], allowed: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, env=env, check=False, capture_output=True, text=True)
    if result.returncode not in allowed:
        raise RuntimeError(
            f"command failed with {result.returncode}: {args[:4]}\n"
            f"stdout={result.stdout[-2000:]}\nstderr={result.stderr[-2000:]}"
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    parsed = parser.parse_args()
    wheel = parsed.wheel.resolve()
    if not wheel.is_file():
        raise SystemExit("wheel does not exist")

    with tempfile.TemporaryDirectory(prefix="guard-secrets-pipx-") as temporary:
        root = Path(temporary)
        home = root / "pipx-home"
        binary = root / "pipx-bin"
        environment = dict(os.environ)
        environment.update(
            {
                "PIPX_HOME": str(home),
                "PIPX_BIN_DIR": str(binary),
                "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                "PIP_NO_INPUT": "1",
            }
        )
        run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "pipx"], env=environment)
        run(
            [
                sys.executable,
                "-m",
                "pipx",
                "install",
                "--force",
                "--python",
                sys.executable,
                str(wheel),
            ],
            env=environment,
        )
        guard = binary / ("hol-guard.exe" if os.name == "nt" else "hol-guard")
        if not guard.is_file():
            raise RuntimeError("pipx did not expose the hol-guard command in the isolated bin directory")
        project = root / "project with spaces Ω"
        project.mkdir()
        initialized = run(["git", "-C", str(project), "init"], env=environment)
        if initialized.returncode != 0:
            raise RuntimeError("Git repository initialization failed")
        doctor = run([str(guard), "secrets", "doctor", str(project), "--json"], env=environment)
        payload = json.loads(doctor.stdout)
        if payload.get("schema") != "guard-secrets-setup-doctor.v1" or not payload.get("ready"):
            raise RuntimeError("pipx-installed setup doctor did not report the test repository as ready")
        rules = json.loads(run([str(guard), "secrets", "rules", "--json"], env=environment).stdout)
        if not rules.get("rules"):
            raise RuntimeError("pipx-installed detector catalog is empty")
        uninstall = run([sys.executable, "-m", "pipx", "uninstall", "hol-guard"], env=environment)
        if uninstall.returncode != 0 or guard.exists():
            raise RuntimeError("pipx uninstall did not remove the isolated command")

    print("HOL Guard Secrets isolated pipx smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
