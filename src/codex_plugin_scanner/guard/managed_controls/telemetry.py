"""Allowlisted, privacy-safe Managed Controls telemetry."""

from __future__ import annotations

from collections.abc import Mapping

_ALLOWED_FIELDS = frozenset(
    {
        "event",
        "result",
        "authority_mode",
        "compatibility_state",
        "drift_state",
        "control_count_bucket",
        "latency_bucket",
    }
)
_FORBIDDEN_FRAGMENTS = ("command", "path", "secret", "token", "proof", "nonce")


class TelemetryPrivacyError(ValueError):
    """Raised when telemetry contains sensitive or arbitrary data."""


def managed_controls_telemetry_event(
    values: Mapping[str, object],
) -> dict[str, str]:
    unknown = set(values) - _ALLOWED_FIELDS
    if unknown:
        raise TelemetryPrivacyError("telemetry contains non-allowlisted fields")
    event: dict[str, str] = {}
    for key, value in values.items():
        text = str(value)
        lowered = f"{key}:{text}".lower()
        if any(fragment in lowered for fragment in _FORBIDDEN_FRAGMENTS):
            raise TelemetryPrivacyError("telemetry contains sensitive material")
        event[key] = text
    return event
