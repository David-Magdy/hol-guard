"""Recursive redaction for Managed Controls diagnostics."""

from __future__ import annotations

from collections.abc import Mapping

_SENSITIVE_KEYS = frozenset(
    {"command", "raw_command", "path", "source_path", "secret", "token", "proof", "nonce"}
)


def redact_managed_controls(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): (
                "[REDACTED]"
                if str(key).lower() in _SENSITIVE_KEYS
                else redact_managed_controls(child)
            )
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [redact_managed_controls(child) for child in value]
    return value
