"""Shared execution-safety checks for Git inspection commands."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import cast

_GIT_CONFIG_ROUTING_ENV = frozenset(
    {
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
    }
)
_READ_ONLY_GIT_STATUS_FLAGS = frozenset(
    {
        "--ahead-behind",
        "--branch",
        "--ignored",
        "--long",
        "--no-ahead-behind",
        "--no-renames",
        "--porcelain",
        "--renames",
        "--short",
        "--show-stash",
        "--untracked-files",
        "-b",
        "-s",
        "-u",
        "-z",
    }
)
_READ_ONLY_GIT_STATUS_VALUE_FLAGS = frozenset(
    {
        "--column",
        "--find-renames",
        "--ignored",
        "--porcelain",
        "--untracked-files",
    }
)


def git_binary_path_is_trusted(git_path: Path, *, cwd: Path) -> bool:
    """Reject Git executables from user-controlled or broadly writable roots."""

    try:
        untrusted_roots = (
            cwd.resolve(),
            Path.home().resolve(),
            Path("/tmp").resolve(),
            Path("/private/tmp").resolve(),
        )
    except (OSError, RuntimeError):
        return False
    for untrusted_root in untrusted_roots:
        try:
            _ = git_path.relative_to(untrusted_root)
        except ValueError:
            continue
        return False
    getuid = getattr(os, "getuid", None)
    current_uid = cast(Callable[[], int], getuid)() if getuid is not None else -1
    getgroups = getattr(os, "getgroups", None)
    current_groups: set[int] = set(cast(Callable[[], list[int]], getgroups)()) if getgroups is not None else set()
    try:
        for candidate in (git_path, *git_path.parents):
            metadata = candidate.stat()
            if metadata.st_mode & stat.S_IWOTH:
                return False
            if metadata.st_mode & stat.S_IWGRP and metadata.st_gid not in current_groups:
                return False
            if candidate == git_path and current_uid >= 0 and metadata.st_uid not in {0, current_uid}:
                return False
    except OSError:
        return False
    return True


def git_config_routing_environment_is_clean() -> bool:
    """Return whether Git configuration discovery follows its default routes."""

    return not any(os.environ.get(key, "").strip() for key in _GIT_CONFIG_ROUTING_ENV)


def trusted_git_binary_for_cwd(cwd: Path) -> Path | None:
    """Resolve Git using the execution cwd and reject user-controlled binaries."""

    try:
        execution_cwd = cwd.resolve()
        path_entries: list[str] = []
        for entry in os.environ.get("PATH", os.defpath).split(os.pathsep):
            candidate = Path(entry or ".").expanduser()
            if not candidate.is_absolute():
                candidate = execution_cwd / candidate
            path_entries.append(str(candidate))
        git_path = shutil.which("git", path=os.pathsep.join(path_entries))
        if git_path is None:
            return None
        resolved_git = Path(git_path).resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return resolved_git if git_binary_path_is_trusted(resolved_git, cwd=execution_cwd) else None


def git_status_args_are_read_only(args: list[str]) -> bool:
    """Accept only status flags that cannot configure or invoke helpers."""

    if not args or args[0].casefold() != "status":
        return False
    after_option_terminator = False
    for token in args[1:]:
        if after_option_terminator:
            continue
        if token == "--":
            after_option_terminator = True
            continue
        normalized = token.casefold()
        if normalized in _READ_ONLY_GIT_STATUS_FLAGS:
            continue
        if "=" in normalized and normalized.split("=", 1)[0] in _READ_ONLY_GIT_STATUS_VALUE_FLAGS:
            continue
        if (
            normalized.startswith("-")
            and len(normalized) > 2
            and not normalized.startswith("--")
            and all(f"-{flag}" in _READ_ONLY_GIT_STATUS_FLAGS for flag in normalized[1:])
        ):
            continue
        return False
    return True


def git_status_has_execution_free_config(
    cwd: Path,
    *,
    git_binary: Path | None = None,
) -> bool:
    """Reject status when Git configuration could execute an fsmonitor helper."""

    if not git_config_routing_environment_is_clean():
        return False
    resolved_git = git_binary or trusted_git_binary_for_cwd(cwd)
    if resolved_git is None:
        return False
    try:
        result = subprocess.run(
            [str(resolved_git), "config", "--null", "--get-all", "core.fsmonitor"],
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=1,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode == 1 and not result.stdout:
        return True
    if result.returncode != 0:
        return False
    values = [value.strip().casefold() for value in result.stdout.split("\0") if value.strip()]
    return bool(values) and all(value in {"0", "false", "no", "off"} for value in values)


__all__ = (
    "git_binary_path_is_trusted",
    "git_config_routing_environment_is_clean",
    "git_status_args_are_read_only",
    "git_status_has_execution_free_config",
    "trusted_git_binary_for_cwd",
)
