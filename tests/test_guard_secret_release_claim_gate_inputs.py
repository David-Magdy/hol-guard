from __future__ import annotations

import pytest

from scripts.ci.guard_secrets_release_claim_gate import ClaimGateError, validate_manifest


def test_parity_validation_requires_exact_release_commit() -> None:
    payload: dict[str, object] = {
        "schema": "guard-secrets-capability-evidence.v2",
        "capabilities": [],
    }

    with pytest.raises(ClaimGateError, match="requires an exact release commit"):
        validate_manifest(
            payload,
            exact_release_commit=None,
            require_parity=True,
            required_capabilities=frozenset(),
        )
