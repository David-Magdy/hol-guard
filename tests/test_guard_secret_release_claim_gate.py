from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_GATE_PATH = Path("scripts/ci/guard_secrets_release_claim_gate.py")
_SPEC = importlib.util.spec_from_file_location(
    "guard_secrets_release_claim_gate",
    _GATE_PATH,
)
assert _SPEC and _SPEC.loader
_GATE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_GATE)

ClaimGateError = _GATE.ClaimGateError
load_manifest = _GATE.load_manifest
validate_manifest = _GATE.validate_manifest


def _manifest(**overrides: object) -> dict[str, object]:
    capability: dict[str, object] = {
        "capability_id": "cli_precommit",
        "product_boundary": "free-local",
        "surfaces": ["cli", "pre_commit"],
        "plans": ["free", "solo", "pro", "team"],
        "owner": "hol-guard",
        "state": "tested",
        "acceptance_tests": ["tests/test_guard_secrets_native_cli.py"],
        "evidence_artifacts": [],
        "release_commit": None,
        "gap_label": "release-candidate evidence pending",
    }
    capability.update(overrides)
    return {
        "schema": "guard-secrets-capability-evidence.v2",
        "capabilities": [capability],
    }


def test_repository_manifest_is_structurally_valid() -> None:
    manifest = load_manifest(
        Path("docs/guard/contracts/guard-secrets-capability-evidence.v2.json")
    )
    errors = validate_manifest(
        manifest,
        exact_release_commit=None,
        require_parity=False,
        required_capabilities=frozenset(),
    )
    assert errors == ()


def test_unknown_capability_state_is_rejected() -> None:
    errors = validate_manifest(
        _manifest(state="complete"),
        exact_release_commit=None,
        require_parity=False,
        required_capabilities=frozenset(),
    )
    assert errors == ("cli_precommit: invalid parity state",)


def test_non_release_state_requires_gap_label() -> None:
    errors = validate_manifest(
        _manifest(gap_label=None),
        exact_release_commit=None,
        require_parity=False,
        required_capabilities=frozenset(),
    )
    assert errors == (
        "cli_precommit: non-release state requires an explicit gap label",
    )


def test_release_state_requires_exact_evidence() -> None:
    errors = validate_manifest(
        _manifest(
            state="verified_on_release_candidate",
            release_commit=None,
            evidence_artifacts=[],
            gap_label=None,
        ),
        exact_release_commit=None,
        require_parity=False,
        required_capabilities=frozenset(),
    )
    assert errors == (
        "cli_precommit: release state requires exact commit",
        "cli_precommit: release state requires evidence artifacts",
    )


def test_parity_claim_requires_same_release_commit() -> None:
    errors = validate_manifest(
        _manifest(
            state="verified_on_release_candidate",
            release_commit="a" * 40,
            evidence_artifacts=["sha256:evidence"],
            gap_label=None,
        ),
        exact_release_commit="b" * 40,
        require_parity=True,
        required_capabilities=frozenset({"cli_precommit"}),
    )
    assert errors == ("cli_precommit: evidence is bound to another commit",)


def test_required_unmapped_capability_fails() -> None:
    errors = validate_manifest(
        _manifest(),
        exact_release_commit="a" * 40,
        require_parity=True,
        required_capabilities=frozenset({"ide_prevention"}),
    )
    assert errors == ("ide_prevention: required capability is unmapped",)


def test_invalid_release_sha_is_rejected() -> None:
    with pytest.raises(ClaimGateError, match="full lowercase SHA"):
        validate_manifest(
            _manifest(),
            exact_release_commit="short",
            require_parity=False,
            required_capabilities=frozenset(),
        )


def test_future_manifest_schema_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps({"schema": "guard-secrets-capability-evidence.v3"})
    )
    with pytest.raises(ClaimGateError, match="unsupported"):
        load_manifest(path)
