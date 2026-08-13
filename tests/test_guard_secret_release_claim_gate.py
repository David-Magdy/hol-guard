from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_GATE_PATH = _REPOSITORY_ROOT / "scripts/ci/guard_secrets_release_claim_gate.py"
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
        "generated_at": "2026-08-12",
        "parity_states": [
            "unmapped",
            "designed",
            "implemented",
            "tested",
            "verified_on_release_candidate",
            "generally_available",
        ],
        "claim_policy": {
            "public_parity_requires": "verified_on_release_candidate",
            "exact_release_commit_required": True,
            "remaining_gaps_must_be_labeled": True,
        },
        "capabilities": [capability],
    }


def _write_manifest(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_repository_manifest_is_structurally_valid() -> None:
    manifest = load_manifest(_REPOSITORY_ROOT / "docs/guard/contracts/guard-secrets-capability-evidence.v2.json")
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
    assert errors == ("cli_precommit: non-release state requires an explicit gap label",)


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
    assert errors == ("release-candidate capability requires an exact commit SHA",)


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
    assert errors == ("cli_precommit: evidence is bound to a different commit",)


def test_required_unmapped_capability_fails() -> None:
    errors = validate_manifest(
        _manifest(),
        exact_release_commit="a" * 40,
        require_parity=True,
        required_capabilities=frozenset({"ide_prevention"}),
    )
    assert errors == ("required capabilities are unmapped: ide_prevention",)


def test_parity_claim_requires_release_commit() -> None:
    with pytest.raises(ClaimGateError, match="requires an exact release commit"):
        validate_manifest(
            _manifest(),
            exact_release_commit=None,
            require_parity=True,
            required_capabilities=frozenset({"cli_precommit"}),
        )


def test_invalid_release_sha_is_rejected() -> None:
    with pytest.raises(ClaimGateError, match="full lowercase SHA"):
        validate_manifest(
            _manifest(),
            exact_release_commit="short",
            require_parity=False,
            required_capabilities=frozenset(),
        )


def test_future_manifest_schema_is_rejected(tmp_path: Path) -> None:
    path = _write_manifest(
        tmp_path / "manifest.json",
        {"schema": "guard-secrets-capability-evidence.v3"},
    )
    payload = load_manifest(path)

    with pytest.raises(ClaimGateError, match="unsupported"):
        validate_manifest(
            payload,
            exact_release_commit=None,
            require_parity=False,
            required_capabilities=frozenset(),
        )


def test_parity_state_declaration_drift_is_rejected() -> None:
    payload = _manifest()
    payload["parity_states"] = ["unmapped", "tested"]

    with pytest.raises(ClaimGateError, match="do not match"):
        validate_manifest(
            payload,
            exact_release_commit=None,
            require_parity=False,
            required_capabilities=frozenset(),
        )


def test_claim_policy_drift_is_rejected() -> None:
    payload = _manifest()
    payload["claim_policy"] = {
        "public_parity_requires": "tested",
        "exact_release_commit_required": True,
        "remaining_gaps_must_be_labeled": True,
    }

    with pytest.raises(ClaimGateError, match="release-candidate verified or GA"):
        validate_manifest(
            payload,
            exact_release_commit=None,
            require_parity=False,
            required_capabilities=frozenset(),
        )


def test_main_returns_zero_for_valid_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _write_manifest(tmp_path / "valid.json", _manifest())
    monkeypatch.setattr(sys, "argv", ["gate", "--manifest", str(path)])

    assert _GATE.main() == 0
    assert capsys.readouterr().err == ""


def test_main_returns_one_for_validation_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = _write_manifest(tmp_path / "invalid-row.json", _manifest(gap_label=None))
    monkeypatch.setattr(sys, "argv", ["gate", "--manifest", str(path)])

    assert _GATE.main() == 1
    assert "non-release state requires" in capsys.readouterr().err


def test_main_returns_two_for_input_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = tmp_path / "malformed.json"
    path.write_text("{", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["gate", "--manifest", str(path)])

    assert _GATE.main() == 2
    assert "guard-secrets-claim-gate:" in capsys.readouterr().err
