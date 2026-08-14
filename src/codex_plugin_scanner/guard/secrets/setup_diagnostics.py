"""Privacy-safe setup diagnostics for HOL Guard Secrets.

The diagnostic is local and read-only. It intentionally reports stable reason
codes instead of environment values, absolute paths, repository names, or Git
configuration contents.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

DoctorStatus = Literal["pass", "warn", "fail"]

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
_CONTROLLED_GIT_ENV = {
    "GCM_INTERACTIVE": "Never",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_PAGER": "cat",
    "GIT_TERMINAL_PROMPT": "0",
    "PAGER": "cat",
}
_SAFE_TEXT = re.compile(r"[^A-Za-z0-9._+ -]")
_GIT_TIMEOUT_SECONDS = 5


@dataclass(frozen=True, slots=True)
class SetupCheck:
    code: str
    status: DoctorStatus
    summary: str
    action: str | None = None

    def to_public_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "code": self.code,
            "status": self.status,
            "summary": self.summary,
        }
        if self.action:
            payload["action"] = self.action
        return payload


@dataclass(frozen=True, slots=True)
class SecretsSetupReport:
    platform: str
    architecture: str
    python_version: str
    checks: tuple[SetupCheck, ...]

    @property
    def ready(self) -> bool:
        return all(check.status != "fail" for check in self.checks)

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": "guard-secrets-setup-doctor.v1",
            "ready": self.ready,
            "platform": self.platform,
            "architecture": self.architecture,
            "python_version": self.python_version,
            "checks": [check.to_public_dict() for check in self.checks],
            "privacy": {
                "environment_values_included": False,
                "absolute_paths_included": False,
                "repository_identity_included": False,
                "secret_values_included": False,
            },
        }


def _safe_label(value: str, *, fallback: str = "unknown") -> str:
    normalized = " ".join(value.strip().split())[:80]
    if not normalized or _SAFE_TEXT.search(normalized):
        return fallback
    return normalized


def secure_git_environment(source: dict[str, str] | None = None) -> dict[str, str]:
    """Return a narrow environment for read-only Git subprocesses.

    All ambient ``GIT_*`` variables are excluded before controlled values are
    added. This prevents callers from redirecting the repository, index, object
    database, config, SSH command, or credential helper used by a scan.
    """

    current = os.environ if source is None else source
    result = {key: value for key, value in current.items() if key.upper() in _SAFE_ENV_KEYS}
    result.update(_CONTROLLED_GIT_ENV)
    return result


def resolve_git_executable() -> Path | None:
    found = shutil.which("git")
    if found:
        return Path(found).resolve()
    if os.name != "nt":
        return None
    candidates: list[Path] = []
    for variable in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        root = os.environ.get(variable)
        if root:
            candidates.extend(
                (
                    Path(root) / "Git" / "cmd" / "git.exe",
                    Path(root) / "Programs" / "Git" / "cmd" / "git.exe",
                )
            )
    return next((candidate.resolve() for candidate in candidates if candidate.is_file()), None)


def run_secure_git(
    executable: Path,
    target: Path | None,
    args: list[str],
    *,
    timeout: int = _GIT_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[bytes]:
    command = [
        str(executable),
        "-c",
        "credential.helper=",
        "-c",
        "core.askPass=",
        "-c",
        "core.pager=cat",
    ]
    if target is not None:
        command.extend(("-C", str(target)))
    command.extend(args)
    return subprocess.run(
        command,
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        env=secure_git_environment(),
        shell=False,
    )


def _git_shell_available(git: Path) -> bool:
    if os.name != "nt":
        return Path("/bin/sh").is_file() or shutil.which("sh") is not None
    roots = (git.parent.parent / "bin" / "sh.exe", git.parent.parent / "usr" / "bin" / "sh.exe")
    return any(candidate.is_file() for candidate in roots) or shutil.which("sh") is not None


def inspect_secrets_setup(target: Path) -> SecretsSetupReport:
    requested = target.expanduser()
    checks: list[SetupCheck] = []
    python_supported = sys.version_info >= (3, 10)
    checks.append(
        SetupCheck(
            code="python_supported",
            status="pass" if python_supported else "fail",
            summary=f"Python {sys.version_info.major}.{sys.version_info.minor} is detected.",
            action=None if python_supported else "Install Python 3.10 or newer, then reinstall HOL Guard with pipx.",
        )
    )

    if not requested.exists() or not requested.is_dir():
        checks.append(
            SetupCheck(
                code="target_directory_missing",
                status="fail",
                summary="The requested scan directory does not exist or is not a directory.",
                action="Open an existing project directory and run the diagnostic again.",
            )
        )
        return SecretsSetupReport(
            platform=_safe_label(platform.system()),
            architecture=_safe_label(platform.machine()),
            python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            checks=tuple(checks),
        )

    root = requested.resolve()
    git = resolve_git_executable()
    if git is None:
        checks.append(
            SetupCheck(
                code="git_missing",
                status="fail",
                summary="Git is not available to HOL Guard.",
                action="Install Git, reopen the terminal, and run the diagnostic again.",
            )
        )
    else:
        try:
            version = run_secure_git(git, None, ["--version"])
        except (OSError, subprocess.SubprocessError):
            version = None
        if version is None or version.returncode != 0:
            checks.append(
                SetupCheck(
                    code="git_unusable",
                    status="fail",
                    summary="Git was found but could not be executed safely.",
                    action="Repair the Git installation and run the diagnostic again.",
                )
            )
        else:
            version_text = version.stdout.decode("utf-8", errors="replace").strip()
            safe_version = _safe_label(version_text)
            checks.append(
                SetupCheck(
                    code="git_available",
                    status="pass",
                    summary=f"{safe_version} is available.",
                )
            )
            try:
                repository = run_secure_git(git, root, ["rev-parse", "--is-inside-work-tree"])
            except (OSError, subprocess.SubprocessError):
                repository = None
            inside = repository is not None and repository.returncode == 0 and repository.stdout.strip() == b"true"
            checks.append(
                SetupCheck(
                    code="git_repository",
                    status="pass" if inside else "warn",
                    summary=(
                        "The requested directory is a Git worktree."
                        if inside
                        else "The requested directory is not a Git worktree; working-tree scans still work, but staged and history scans do not."
                    ),
                    action=None if inside else "Run inside a Git worktree to use staged, history, and pre-commit protection.",
                )
            )
            if inside:
                try:
                    hook_config = run_secure_git(git, root, ["config", "--get", "core.hooksPath"])
                except (OSError, subprocess.SubprocessError):
                    hook_config = None
                custom_hooks = hook_config is not None and hook_config.returncode == 0 and bool(hook_config.stdout.strip())
                checks.append(
                    SetupCheck(
                        code="standard_hooks_path",
                        status="warn" if custom_hooks else "pass",
                        summary=(
                            "A custom Git hooks path is configured; HOL Guard will not modify it automatically."
                            if custom_hooks
                            else "The repository uses the standard Git hooks directory."
                        ),
                        action=(
                            "Keep the custom hook manager authoritative and invoke `hol-guard secrets scan --staged --fail-on-findings` from it."
                            if custom_hooks
                            else None
                        ),
                    )
                )
                shell_ready = _git_shell_available(git)
                checks.append(
                    SetupCheck(
                        code="hook_shell_available",
                        status="pass" if shell_ready else "warn",
                        summary=(
                            "A POSIX-compatible shell is available for the managed Git hook."
                            if shell_ready
                            else "The Git hook shell could not be verified."
                        ),
                        action=None if shell_ready else "Install Git for Windows with its shell, or invoke the staged scan from your existing hook manager.",
                    )
                )

    writable = os.access(root, os.W_OK)
    checks.append(
        SetupCheck(
            code="target_writable",
            status="pass" if writable else "warn",
            summary=(
                "The project directory is writable."
                if writable
                else "The project directory is read-only; scans work, but hook installation requires a writable Git metadata directory."
            ),
            action=None if writable else "Run scans directly, or install the hook from a writable checkout.",
        )
    )

    return SecretsSetupReport(
        platform=_safe_label(platform.system()),
        architecture=_safe_label(platform.machine()),
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        checks=tuple(checks),
    )


__all__ = [
    "SecretsSetupReport",
    "SetupCheck",
    "inspect_secrets_setup",
    "resolve_git_executable",
    "run_secure_git",
    "secure_git_environment",
]
