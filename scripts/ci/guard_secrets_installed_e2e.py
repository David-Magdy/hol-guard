#!/usr/bin/env python3
"""Black-box HOL Guard Secrets smoke test for a freshly installed wheel."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def _run(
    command: list[str],
    *,
    cwd: Path,
    expected: set[int] = frozenset({0}),
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=90,
    )
    if completed.returncode not in expected:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {command!r}\n"
            f"stdout={completed.stdout[-2000:]}\nstderr={completed.stderr[-2000:]}"
        )
    return completed


def _guard_command() -> list[str]:
    executable = shutil.which("hol-guard")
    if executable:
        return [executable]
    return [sys.executable, "-m", "codex_plugin_scanner.guard.cli"]


def _git(root: Path, *args: str, expected: set[int] = frozenset({0})) -> subprocess.CompletedProcess[str]:
    return _run(["git", *args], cwd=root, expected=expected)


def _synthetic_github_token() -> str:
    return "".join(
        (
            "gh",
            "p_",
            "Ab3d",
            "Ef5h",
            "Ij7l",
            "Mn9p",
            "Qr2t",
            "Uv4x",
            "Yz6B",
            "cd8F",
            "gh1J",
            "kl3N",
        )
    )


def _invoke(root: Path, *args: str, expected: set[int] = frozenset({0})) -> subprocess.CompletedProcess[str]:
    return _run([*_guard_command(), *args], cwd=root, expected=expected)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="guard secrets e2e ") as temporary:
        root = Path(temporary) / "unicode-δ repository"
        root.mkdir()
        _git(root, "init")
        _git(root, "config", "user.email", "e2e@example.test")
        _git(root, "config", "user.name", "Secrets E2E")

        clean = root / "README.md"
        clean.write_text("clean repository\n", encoding="utf-8")
        _git(root, "add", "README.md")
        _git(root, "commit", "-m", "initial clean commit")

        doctor = _invoke(root, "secrets", "doctor", "--json")
        doctor_payload = json.loads(doctor.stdout)
        if doctor_payload.get("repository_detected") is not True:
            raise RuntimeError("doctor did not detect the repository")
        if doctor_payload.get("privacy", {}).get("credentials_included") is not False:
            raise RuntimeError("doctor privacy contract is not fail-closed")

        rules = _invoke(root, "secrets", "rules", "--json")
        if not json.loads(rules.stdout).get("rules"):
            raise RuntimeError("detector catalog is empty")

        working = _invoke(root, "secrets", "scan", ".", "--json")
        if json.loads(working.stdout).get("finding_count") != 0:
            raise RuntimeError("clean working tree produced a finding")

        utf16_token = _synthetic_github_token()
        utf16_path = root / "unicode-secret.txt"
        utf16_path.write_text(f"TOKEN={utf16_token}\n", encoding="utf-16")
        utf16 = _invoke(
            root,
            "secrets",
            "scan",
            ".",
            "--json",
            "--fail-on-findings",
            expected={3},
        )
        if utf16_token in utf16.stdout or utf16_token in utf16.stderr:
            raise RuntimeError("raw credential appeared in UTF-16 scan output")
        if json.loads(utf16.stdout).get("finding_count", 0) < 1:
            raise RuntimeError("UTF-16 credential was not detected")
        utf16_path.unlink()

        staged_token = _synthetic_github_token()
        secret_path = root / "staged-secret.env"
        secret_path.write_text(f"GITHUB_TOKEN={staged_token}\n", encoding="utf-8")
        _git(root, "add", "staged-secret.env")
        staged = _invoke(
            root,
            "secrets",
            "scan",
            "--staged",
            "--json",
            "--fail-on-findings",
            expected={3},
        )
        if staged_token in staged.stdout or staged_token in staged.stderr:
            raise RuntimeError("raw credential appeared in staged scan output")
        if json.loads(staged.stdout).get("finding_count", 0) < 1:
            raise RuntimeError("staged credential was not detected")

        _invoke(root, "secrets", "install-hook")
        blocked = _git(root, "commit", "-m", "must be blocked", expected={1})
        combined = blocked.stdout + blocked.stderr
        if staged_token in combined:
            raise RuntimeError("raw credential appeared in pre-commit output")

        _git(root, "reset", "HEAD", "staged-secret.env")
        secret_path.unlink()
        clean.write_text("clean repository after hook\n", encoding="utf-8")
        _git(root, "add", "README.md")
        _git(root, "commit", "-m", "clean commit through Guard hook")
        _invoke(root, "secrets", "uninstall-hook")

        custom_hooks = root / "custom hooks"
        custom_hooks.mkdir()
        _git(root, "config", "core.hooksPath", str(custom_hooks))
        refused = _invoke(root, "secrets", "install-hook", expected={2})
        if "custom" not in (refused.stdout + refused.stderr).lower():
            raise RuntimeError("custom hooksPath refusal was not actionable")
        if any(custom_hooks.iterdir()):
            raise RuntimeError("custom hooksPath was modified despite refusal")

    print(json.dumps({"schema": "guard-secret-installed-e2e.v1", "status": "pass"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
