"""Shared package-evidence parsing and path validation helpers."""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path, PurePosixPath
from typing import cast

_MAX_PACKAGE_JSON_BYTES = 16 * 1024 * 1024


def valid_sha512_integrity(value: object) -> bool:
    """Return true for a syntactically valid 64-byte SRI SHA-512 digest."""

    if not isinstance(value, str) or not value.startswith("sha512-"):
        return False
    try:
        decoded = base64.b64decode(value.removeprefix("sha512-"), validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(decoded) == 64


def resolved_package_bin_target(package_root: Path, target: str | None) -> Path | None:
    """Resolve a relative package bin target without allowing root escape."""

    if target is None:
        return None
    portable = PurePosixPath(target.replace("\\", "/"))
    if portable.is_absolute() or not portable.parts or ".." in portable.parts:
        return None
    candidate = package_root.joinpath(*portable.parts).resolve(strict=False)
    try:
        _ = candidate.relative_to(package_root)
    except ValueError:
        return None
    return candidate


def read_package_json(path: Path) -> dict[str, object] | None:
    """Read a bounded, non-symlink package.json object without raising."""

    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_PACKAGE_JSON_BYTES:
            return None
        payload = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    typed = cast(dict[object, object], payload)
    return {key: value for key, value in typed.items() if isinstance(key, str)}
