#!/usr/bin/env python3
"""Validate HOL Guard Secrets capability evidence before release claims."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import cast

_ALLOWED_STATES = frozenset(
    {
        "unmapped",
        "designed",
        "implemented",
        "tested",
        "verified_on_release_candidate",
        "generally_available",
    }
)
_RELEASE_STATES = frozenset({"verified_on_release_candidate", "generally_available"})
_SHA = re.compile(r"^[a-f0-9]{40}$")


class ClaimGateError(ValueError):
    """Raised when evidence is invalid or overclaims a capability."""


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ClaimGateError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _string_list(
    value: object,
    *,
    label: str,
    allow_empty: bool = True,
) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ClaimGateError(f"{label} must be an array of strings")
    result = tuple(cast(list[str], value))
    if not allow_empty and not result:
        raise ClaimGateError(f"{label} must not be empty")
    return result


def load_manifest(path: Path) -> Mapping[str, object]:
    payload = _mapping(json.loads(path.read_text(encoding="utf-8")), label="manifest")
    if payload.get("schema") != "guard-secrets-capability-evidence.v2":
        raise ClaimGateError("unsupported capability manifest schema")
    return payload


def validate_manifest(
    payload: Mapping[str, object],
    *,
    exact_release_commit: str | None,
    require_parity: bool,
    required_capabilities: frozenset[str],
) -> tuple[str, ...]:
    if exact_release_commit is not None and not _SHA.fullmatch(exact_release_commit):
        raise ClaimGateError("exact release commit must be a full lowercase SHA")
    raw_capabilities = payload.get("capabilities")
    if not isinstance(raw_capabilities, list):
        raise ClaimGateError("capabilities must be an array")

    errors: list[str] = []
    seen: set[str] = set()
    by_id: dict[str, Mapping[str, object]] = {}
    for index, raw in enumerate(raw_capabilities):
        capability = _mapping(raw, label=f"capabilities[{index}]")
        allowed = {
            "capability_id",
            "product_boundary",
            "surfaces",
            "plans",
            "owner",
            "state",
            "acceptance_tests",
            "evidence_artifacts",
            "release_commit",
            "gap_label",
        }
        unknown = sorted(set(capability) - allowed)
        if unknown:
            errors.append(
                f"capabilities[{index}]: unknown fields: {', '.join(unknown)}"
            )
        capability_id = capability.get("capability_id")
        if not isinstance(capability_id, str) or not capability_id:
            errors.append(f"capabilities[{index}]: invalid capability_id")
            continue
        if capability_id in seen:
            errors.append(f"{capability_id}: duplicate capability")
            continue
        seen.add(capability_id)
        by_id[capability_id] = capability
        state = capability.get("state")
        if state not in _ALLOWED_STATES:
            errors.append(f"{capability_id}: invalid parity state")
            continue
        try:
            tests = _string_list(
                capability.get("acceptance_tests"),
                label=f"{capability_id}.acceptance_tests",
            )
            artifacts = _string_list(
                capability.get("evidence_artifacts"),
                label=f"{capability_id}.evidence_artifacts",
            )
            _string_list(
                capability.get("surfaces"),
                label=f"{capability_id}.surfaces",
                allow_empty=False,
            )
            _string_list(
                capability.get("plans"),
                label=f"{capability_id}.plans",
                allow_empty=False,
            )
        except ClaimGateError as error:
            errors.append(str(error))
            continue
        release_commit = capability.get("release_commit")
        gap_label = capability.get("gap_label")
        if state in {"tested", *_RELEASE_STATES} and not tests:
            errors.append(f"{capability_id}: tested state requires acceptance tests")
        if state in _RELEASE_STATES:
            if not isinstance(release_commit, str) or not _SHA.fullmatch(release_commit):
                errors.append(f"{capability_id}: release state requires exact commit")
            if not artifacts:
                errors.append(
                    f"{capability_id}: release state requires evidence artifacts"
                )
        elif not isinstance(gap_label, str) or not gap_label.strip():
            errors.append(
                f"{capability_id}: non-release state requires an explicit gap label"
            )
        if require_parity and capability_id in required_capabilities:
            if state not in _RELEASE_STATES:
                errors.append(f"{capability_id}: not release-candidate verified")
            elif release_commit != exact_release_commit:
                errors.append(f"{capability_id}: evidence is bound to another commit")

    missing = sorted(required_capabilities - set(by_id))
    errors.extend(
        f"{capability_id}: required capability is unmapped"
        for capability_id in missing
    )
    return tuple(errors)


def main() -> int:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--manifest", type=Path, required=True)
    _ = parser.add_argument("--release-commit")
    _ = parser.add_argument("--require-parity", action="store_true")
    _ = parser.add_argument("--required-capability", action="append", default=[])
    args = parser.parse_args()
    try:
        payload = load_manifest(args.manifest)
        errors = validate_manifest(
            payload,
            exact_release_commit=args.release_commit,
            require_parity=args.require_parity,
            required_capabilities=frozenset(args.required_capability),
        )
    except (ClaimGateError, json.JSONDecodeError, OSError) as error:
        print(f"guard-secrets-claim-gate: {error}")
        return 2
    for error in errors:
        print(f"guard-secrets-claim-gate: {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
