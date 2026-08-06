"""Resolve Cline-owned data, hook, and plugin locations without executing Cline."""

from __future__ import annotations

import os
from pathlib import Path

from .base import HarnessContext


def cline_data_dir(context: HarnessContext) -> Path:
    """Resolve Cline's configured data directory across current and legacy hosts."""

    for variable in ("CLINE_DATA_DIR", "CLINE_DIR"):
        configured = os.environ.get(variable, "").strip()
        if configured:
            return Path(configured).expanduser()
    return context.home_dir / ".cline"


def cline_hook_roots(context: HarnessContext) -> tuple[Path, ...]:
    """Return global hook roots used by Cline UI and data-dir based runtimes."""

    data_hooks = cline_data_dir(context) / "hooks"
    candidates = (
        context.home_dir / "Documents" / "Cline" / "Hooks",
        data_hooks,
        context.home_dir / ".cline" / "hooks",
    )
    if os.environ.get("CLINE_DATA_DIR", "").strip() or os.environ.get("CLINE_DIR", "").strip():
        candidates = (data_hooks, *candidates)
    unique: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return tuple(unique)


def cline_plugin_root(context: HarnessContext) -> Path:
    """Return the Guard-owned plugin root under Cline's selected data directory."""

    return cline_data_dir(context) / "plugins" / "hol-guard"


__all__ = ["cline_data_dir", "cline_hook_roots", "cline_plugin_root"]
