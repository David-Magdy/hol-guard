#!/usr/bin/env python3
"""Exercise the installed HOL Guard Secrets wheel through real Git operations."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path


def _run(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    expected: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode not in expected:
        raise RuntimeError(
            f"command failed with {result.returncode}: {args[0]} {args[1:3]}\n"
            f"stdout={result.stdout[-2000:]}\nstderr={result.stderr[-2000:]}"
        )
    return result


def _token() -> str:
    return "".join(("gh", "p_", "Ab3d", "Ef5h", "Ij7l", "Mn9p", "Qr2t", "Uv4x", "Yz6B", "cd8F"))


def _venv_python(root: Path) -> Path:
    return root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _venv_bin(root: Path) -> Path:
    return root / ("Scripts" if os.name == "nt" else "bin")


def _guard_command(root: Path) -> Path:
    return _venv_bin(root) / ("hol-guard.exe" if os.name == "nt" else "hol-guard")


def _git(root: Path, *args: str, env: dict[str, str] | None = None, expected: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[str]:
    return _run(["git", "-C", str(root), *args], env=env, expected=expected)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    args = parser.parse_args()
    wheel = args.wheel.resolve()
    if not wheel.is_file():
        raise SystemExit("wheel does not exist")

    with tempfile.TemporaryDirectory(prefix="guard-secrets-platform-") as temporary:
        base = Path(temporary)
        environment_root = base / "isolated environment"
        venv.EnvBuilder(with_pip=True, clear=True).create(environment_root)
        python = _venv_python(environment_root)
        _run([str(python), "-m", "pip", "install", "--disable-pip-version-check", str(wheel)])
        guard = _guard_command(environment_root)
        if not guard.is_file():
            raise RuntimeError("installed wheel did not expose the hol-guard command")

        root = base / "repository with spaces Ω"
        root.mkdir()
        _git(root, "init")
        _git(root, "config", "user.email", "guard-smoke@example.invalid")
        _git(root, "config", "user.name", "Guard Smoke")

        doctor = _run([str(guard), "secrets", "doctor", str(root), "--json"])
        doctor_payload = json.loads(doctor.stdout)
        if doctor_payload.get("schema") != "guard-secrets-setup-doctor.v1" or not doctor_payload.get("ready"):
            raise RuntimeError("installed setup doctor did not report the initialized repository as ready")
        doctor_text = json.dumps(doctor_payload)
        if str(root) in doctor_text or str(base) in doctor_text:
            raise RuntimeError("setup doctor disclosed an absolute path")

        rules = _run([str(guard), "secrets", "rules", "--json"])
        rules_payload = json.loads(rules.stdout)
        if not rules_payload.get("rules"):
            raise RuntimeError("installed detector catalog is empty")

        benign = root / "notes Ω.txt"
        benign.write_bytes(b"\xef\xbb\xbfbenign=true\r\n")
        clean = _run([str(guard), "secrets", "scan", str(root), "--json"])
        if json.loads(clean.stdout).get("truncated"):
            raise RuntimeError("complete working-tree smoke scan reported partial coverage")

        _git(root, "add", "notes Ω.txt")
        _git(root, "commit", "-m", "benign baseline")
        _run([str(guard), "secrets", "install-hook", str(root), "--json"])

        token = _token()
        secret_path = root / "config with spaces.env"
        secret_path.write_text(f"GITHUB_TOKEN={token}\n", encoding="utf-8")
        _git(root, "add", "config with spaces.env")
        secret_path.write_text("GITHUB_TOKEN=not-a-secret\n", encoding="utf-8")

        inherited = dict(os.environ)
        inherited["PATH"] = str(_venv_bin(environment_root)) + os.pathsep + inherited.get("PATH", "")
        decoy = base / "decoy"
        decoy.mkdir()
        _git(decoy, "init")
        inherited["GIT_DIR"] = str(decoy / ".git")
        inherited["GIT_WORK_TREE"] = str(decoy)
        inherited["GIT_CONFIG_COUNT"] = "1"
        inherited["GIT_CONFIG_KEY_0"] = "credential.helper"
        inherited["GIT_CONFIG_VALUE_0"] = "!false"

        staged = _run(
            [str(guard), "secrets", "scan", str(root), "--staged", "--fail-on-findings", "--json"],
            env=inherited,
            expected=(3,),
        )
        staged_payload = json.loads(staged.stdout)
        combined = staged.stdout + staged.stderr
        if staged_payload.get("finding_count") != 1 or token in combined:
            raise RuntimeError("staged scan did not block or redacted output disclosed the candidate")

        commit = _git(root, "commit", "-m", "must be blocked", env=inherited, expected=(3,))
        if token in commit.stdout + commit.stderr:
            raise RuntimeError("pre-commit output disclosed the candidate")

        secret_path.write_text(f"GITHUB_TOKEN={token}\n", encoding="utf-8")
        _git(root, "add", "config with spaces.env")
        _run([str(guard), "secrets", "uninstall-hook", str(root), "--json"])
        _git(root, "commit", "-m", "history fixture")
        secret_path.write_text("GITHUB_TOKEN=rotated\n", encoding="utf-8")
        _git(root, "add", "config with spaces.env")
        _git(root, "commit", "-m", "remove current value")

        history = _run(
            [str(guard), "secrets", "scan", str(root), "--history", "--max-commits", "10", "--json"],
            expected=(2,),
        )
        history_payload = json.loads(history.stdout)
        if history_payload.get("finding_count", 0) < 1:
            raise RuntimeError("bounded history scan did not find the prior committed credential")
        if token in history.stdout + history.stderr:
            raise RuntimeError("history output disclosed the candidate")

    print("HOL Guard Secrets installed-wheel platform smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
