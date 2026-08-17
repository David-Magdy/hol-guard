"""Conservative Node semver matching for locally verified package routines."""

from __future__ import annotations

import re

_EXACT_VERSION = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?")
_STABLE_SPECIFIER = re.compile(r"([~^]?)(\d+)\.(\d+)\.(\d+)")
_STABLE_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def node_semver_spec_matches(specifier: str, version: str) -> bool:
    """Match the intentionally small semver subset Guard can prove locally.

    Exact stable and prerelease versions are accepted only on byte-for-byte
    equality. Range matching supports exact, tilde, and caret three-component
    stable versions. Unsupported semver syntax fails closed.
    """

    if specifier == version and _EXACT_VERSION.fullmatch(version) is not None:
        return True

    requested_match = _STABLE_SPECIFIER.fullmatch(specifier)
    installed_match = _STABLE_VERSION.fullmatch(version)
    if requested_match is None or installed_match is None:
        return False

    operator, major, minor, patch = requested_match.groups()
    requested = (int(major), int(minor), int(patch))
    installed = tuple(int(value) for value in installed_match.groups())
    if installed < requested:
        return False
    if operator == "^":
        if requested[0] > 0:
            return installed[0] == requested[0]
        if requested[1] > 0:
            return installed[:2] == requested[:2]
        return installed == requested
    if operator == "~":
        return installed[:2] == requested[:2]
    return installed == requested


__all__ = ["node_semver_spec_matches"]
