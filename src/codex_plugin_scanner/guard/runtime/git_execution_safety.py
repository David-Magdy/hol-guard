"""Shared execution-safety checks for Git inspection commands."""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import cast


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


__all__ = ("git_binary_path_is_trusted",)
