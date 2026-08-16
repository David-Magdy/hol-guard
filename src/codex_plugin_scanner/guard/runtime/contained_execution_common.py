"""Low-level, side-effect-free helpers shared by contained execution paths."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

_ALLOWED_ENVIRONMENT_KEYS = ("LANG", "LC_ALL", "LC_CTYPE", "NO_COLOR", "TERM")


def canonical_existing_directory(path: Path) -> Path:
    """Resolve one existing directory while rejecting symlinks and path aliases."""

    if path.is_symlink() or not path.is_dir():
        raise ValueError("workspace must be an existing canonical directory")
    canonical = path.resolve(strict=True)
    if canonical != Path(os.path.normpath(str(path))):
        raise ValueError("workspace cannot contain aliases")
    return canonical


def clean_containment_environment(environment: dict[str, str]) -> tuple[tuple[str, str], ...]:
    """Retain only non-sensitive presentation variables for a contained child."""

    return tuple(
        sorted(
            (key, value)
            for key in _ALLOWED_ENVIRONMENT_KEYS
            if (value := environment.get(key))
        )
    )


def containment_binding_digest(payload: dict[str, object]) -> str:
    """Hash one canonical payload with an explicit length prefix."""

    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(len(encoded).to_bytes(8, "big") + encoded).hexdigest()


__all__ = [
    "canonical_existing_directory",
    "clean_containment_environment",
    "containment_binding_digest",
]
