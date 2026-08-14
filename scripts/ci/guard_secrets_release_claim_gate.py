#!/usr/bin/env python3
"""Validate HOL Guard Secrets capability evidence before release claims."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.secrets.contracts_v2 import (
    SecretContractError,
    is_exact_commit_sha,
    parse_capability_evidence_manifest,
    validate_capability_manifest,
)


class ClaimGateError(ValueError):
    """Raised when gate input cannot be interpreted safely."""


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    """Return a string-keyed mapping or raise a stable input error."""

    if not isinstance(value, Mapping):
        raise ClaimGateError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def load_manifest(path: Path) -> Mapping[str, object]:
    """Load a JSON capability manifest without weakening schema validation."""

    return _mapping(
        json.loads(path.read_text(encoding="utf-8")),
        label="manifest",
    )


def validate_manifest(
    payload: Mapping[str, object],
    *,
    exact_release_commit: str | None,
    require_parity: bool,
    required_capabilities: frozenset[str],
) -> tuple[str, ...]:
    """Validate manifest structure and optional exact-release parity claims."""

    if exact_release_commit is not None and not is_exact_commit_sha(exact_release_commit):
        raise ClaimGateError("exact release commit must be a full lowercase SHA")
    if require_parity and exact_release_commit is None:
        raise ClaimGateError("parity enforcement requires an exact release commit")

    try:
        manifest = parse_capability_evidence_manifest(payload)
    except SecretContractError as error:
        raise ClaimGateError(str(error)) from error

    errors = list(manifest.row_errors)
    if require_parity and not errors:
        if exact_release_commit is None:
            raise ClaimGateError("parity enforcement requires an exact release commit")
        try:
            validate_capability_manifest(
                manifest.capabilities,
                required_capability_ids=required_capabilities,
                exact_release_commit=exact_release_commit,
                minimum_state=manifest.public_parity_requires,
            )
        except SecretContractError as error:
            errors.append(str(error))
    return tuple(errors)


def main() -> int:
    """Run the release gate with stable success, validation, and input codes."""

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
        print(f"guard-secrets-claim-gate: {error}", file=sys.stderr)
        return 2
    for error in errors:
        print(f"guard-secrets-claim-gate: {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
