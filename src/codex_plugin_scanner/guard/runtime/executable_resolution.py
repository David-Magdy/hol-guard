"""Shared executable resolution relative to an execution directory."""

from __future__ import annotations

import os
import shutil
from pathlib import Path


def which_for_execution_cwd(command: str, *, cwd: Path) -> str | None:
    """Resolve a PATH command while interpreting relative PATH entries from ``cwd``."""

    path_entries: list[str] = []
    for entry in os.environ.get("PATH", os.defpath).split(os.pathsep):
        candidate = Path(entry or ".").expanduser()
        if not candidate.is_absolute():
            candidate = cwd / candidate
        path_entries.append(str(candidate))
    return shutil.which(command, path=os.pathsep.join(path_entries))
