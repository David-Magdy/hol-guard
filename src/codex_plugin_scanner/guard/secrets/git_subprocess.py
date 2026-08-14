"""Hardened read-only Git subprocess helpers for secret scanning."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

_SAFE_ENV_KEYS = frozenset(
    {
        "APPDATA",
        "COMSPEC",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "PATH",
        "PATHEXT",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "WINDIR",
    }
)
_CONTROLLED_ENV = {
    "GCM_INTERACTIVE": "Never",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_PAGER": "cat",
    "GIT_TERMINAL_PROMPT": "0",
    "PAGER": "cat",
}


def secure_git_environment(source: dict[str, str] | None = None) -> dict[str, str]:
    """Return a minimal environment without ambient Git or credential overrides."""

    current = os.environ if source is None else source
    result = {key: value for key, value in current.items() if key.upper() in _SAFE_ENV_KEYS}
    result.update(_CONTROLLED_ENV)
    return result


def resolve_git_executable() -> str:
    executable = shutil.which("git")
    if not executable:
        raise FileNotFoundError("Git is not installed or is not available on PATH")
    return str(Path(executable).resolve())


def run_git(
    root: Path,
    args: list[str],
    *,
    timeout: int = 20,
) -> subprocess.CompletedProcess[bytes]:
    """Run Git read-only with no shell, prompts, helpers, or ambient Git redirects."""

    executable = resolve_git_executable()
    return subprocess.run(
        [
            executable,
            "-c",
            "credential.helper=",
            "-c",
            "core.askPass=",
            "-c",
            "core.pager=cat",
            "-C",
            str(root),
            *args,
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        env=secure_git_environment(),
        shell=False,
    )


__all__ = ["resolve_git_executable", "run_git", "secure_git_environment"]
