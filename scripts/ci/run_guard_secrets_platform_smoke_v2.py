#!/usr/bin/env python3
"""Exercise an exact HOL Guard wheel through real cross-platform Git operations."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import venv
from pathlib import Path


def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    allowed: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, cwd=cwd, env=env, check=False, capture_output=True, text=True)
    if result.returncode not in allowed:
        raise RuntimeError(
            f"command failed with {result.returncode}: {args[0]} {args[1:3]}\n"
            f"stdout={result.stdout[-2000:]}\nstderr={result.stderr[-2000:]}"
        )
    return result


def provider_token() -> str:
    return "".join(("gh", "p_", "Ab3d", "Ef5h", "Ij7l", "Mn9p", "Qr2t", "Uv4x", "Yz6B", "cd8F"))


def environment_python(root: Path) -> Path:
    return root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def environment_bin(root: Path) -> Path:
    return root / ("Scripts" if os.name == "nt" else "bin")


def guard_command(root: Path) -> Path:
    return environment_bin(root) / ("hol-guard.exe" if os.name == "nt" else "hol-guard")


def git(
    root: Path,
    *args: str,
    env: dict[str, str] | None = None,
    allowed: tuple[int, ...] = (0,),
) -> subprocess.CompletedProcess[str]:
    return run(["git", "-C", str(root), *args], env=env, allowed=allowed)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    parsed = parser.parse_args()
    wheel = parsed.wheel.resolve()
    if not wheel.is_file():
        raise SystemExit("wheel does not exist")

    with tempfile.TemporaryDirectory(prefix="guard-secrets-platform-") as temporary:
        base = Path(temporary)
        isolated = base / "isolated environment"
        venv.EnvBuilder(with_pip=True, clear=True).create(isolated)
        python = environment_python(isolated)
        run([str(python), "-m", "pip", "install", "--disable-pip-version-check", str(wheel)])
        guard = guard_command(isolated)
        if not guard.is_file():
            raise RuntimeError("installed wheel did not expose hol-guard")

        root = base / "repository with spaces Ω"
        root.mkdir()
        git(root, "init")
        git(root, "config", "user.email", "guard-smoke@example.invalid")
        git(root, "config", "user.name", "Guard Smoke")

        doctor = run([str(guard), "secrets", "doctor", str(root), "--json"])
        doctor_payload = json.loads(doctor.stdout)
        if doctor_payload.get("schema") != "guard-secrets-setup-doctor.v1" or not doctor_payload.get("ready"):
            raise RuntimeError("setup doctor did not report the initialized repository as ready")
        doctor_text = json.dumps(doctor_payload)
        if str(root) in doctor_text or str(base) in doctor_text:
            raise RuntimeError("setup doctor disclosed an absolute path")

        rules = json.loads(run([str(guard), "secrets", "rules", "--json"]).stdout)
        if not rules.get("rules"):
            raise RuntimeError("installed detector catalog is empty")

        benign = root / "notes Ω.txt"
        benign.write_bytes(b"\xef\xbb\xbfbenign=true\r\n")
        clean = json.loads(run([str(guard), "secrets", "scan", str(root), "--json"]).stdout)
        if clean.get("truncated") or clean.get("finding_count"):
            raise RuntimeError("benign working-tree smoke did not complete cleanly")
        git(root, "add", "notes Ω.txt")
        git(root, "commit", "-m", "benign baseline")
        run([str(guard), "secrets", "install-hook", str(root), "--json"])

        token = provider_token()
        secret_path = root / "config with spaces.env"
        secret_path.write_text(f"GITHUB_TOKEN={token}\n", encoding="utf-8")
        git(root, "add", "config with spaces.env")
        secret_path.write_text("GITHUB_TOKEN=not-a-secret\n", encoding="utf-8")

        invocation_env = dict(os.environ)
        invocation_env["PATH"] = str(environment_bin(isolated)) + os.pathsep + invocation_env.get("PATH", "")
        decoy = base / "decoy"
        decoy.mkdir()
        git(decoy, "init")
        injected_env = dict(invocation_env)
        injected_env.update(
            {
                "GIT_DIR": str(decoy / ".git"),
                "GIT_WORK_TREE": str(decoy),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "credential.helper",
                "GIT_CONFIG_VALUE_0": "!false",
            }
        )

        staged_result = run(
            [str(guard), "secrets", "scan", str(root), "--staged", "--fail-on-findings", "--json"],
            env=injected_env,
            allowed=(3,),
        )
        staged_payload = json.loads(staged_result.stdout)
        if staged_payload.get("finding_count") != 1:
            raise RuntimeError("staged scan did not inspect the requested repository index")
        if token in staged_result.stdout + staged_result.stderr:
            raise RuntimeError("staged scan output disclosed the candidate")

        blocked_commit = git(root, "commit", "-m", "must be blocked", env=invocation_env, allowed=(1, 3))
        if token in blocked_commit.stdout + blocked_commit.stderr:
            raise RuntimeError("pre-commit output disclosed the candidate")

        secret_path.write_text(f"GITHUB_TOKEN={token}\n", encoding="utf-8")
        git(root, "add", "config with spaces.env")
        run([str(guard), "secrets", "uninstall-hook", str(root), "--json"])
        git(root, "commit", "-m", "history fixture")
        secret_path.write_text("GITHUB_TOKEN=rotated\n", encoding="utf-8")
        git(root, "add", "config with spaces.env")
        git(root, "commit", "-m", "remove current value")

        history_result = run(
            [str(guard), "secrets", "scan", str(root), "--history", "--max-commits", "10", "--json"],
            allowed=(0, 2),
        )
        history_payload = json.loads(history_result.stdout)
        if history_payload.get("finding_count", 0) < 1:
            raise RuntimeError("bounded history scan missed the prior committed credential")
        if token in history_result.stdout + history_result.stderr:
            raise RuntimeError("history output disclosed the candidate")

    print("HOL Guard Secrets installed-wheel platform smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
