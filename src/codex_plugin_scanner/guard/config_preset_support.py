"""Helpers for applying named protection presets to legacy configuration."""

from __future__ import annotations

from collections.abc import Mapping, Set

from .protection_posture import normalize_protection_posture


def apply_named_posture_harness_policy(
    next_payload: dict[str, object],
    incoming: Mapping[str, object],
    *,
    valid_security_levels: Set[str],
) -> dict[str, object]:
    """Clear blanket ask policy for named-profile resets or transitions away from Watch."""

    requested_level = incoming.get("security_level")
    selects_named_level = (
        isinstance(requested_level, str)
        and requested_level in valid_security_levels - {"custom"}
        and incoming.get("risk_actions") == {}
        and incoming.get("harness_risk_actions") == {}
    )
    requested_posture = normalize_protection_posture(incoming.get("protection_posture"))
    current_posture = normalize_protection_posture(next_payload.get("protection_posture"))
    current_is_watch = current_posture == "watch" or (current_posture is None and next_payload.get("mode") == "observe")
    leaves_watch = current_is_watch and requested_posture in {"protected", "extra_careful"}
    if not selects_named_level and not leaves_watch:
        return next_payload
    updated = dict(next_payload)
    updated["harnesses"] = without_blanket_harness_reapproval(updated.get("harnesses"))
    return updated


def without_blanket_harness_reapproval(value: object) -> dict[str, object]:
    """Remove blanket ask fallbacks while preserving other harness policy."""

    if not isinstance(value, Mapping):
        return {}
    preserved: dict[str, object] = {}
    for harness, raw_settings in value.items():
        if not isinstance(harness, str):
            continue
        if isinstance(raw_settings, str) and raw_settings in {"review", "require-reapproval"}:
            continue
        if not isinstance(raw_settings, Mapping):
            preserved[harness] = raw_settings
            continue
        remaining = dict(raw_settings)
        for key in ("action", "default_action"):
            if remaining.get(key) in {"review", "require-reapproval"}:
                remaining.pop(key)
        if remaining:
            preserved[harness] = remaining
    return preserved
