from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.secrets.contracts_v2 import (
    OUTCOME_SURFACE_MAPPING,
    REASON_CODES_V2,
    CapabilityEvidenceV2,
    ParityState,
    PreventionOutcome,
    SecretContractError,
    SecretCustomRuleV2,
    SecretIgnoreDecisionV2,
    SecretIgnoreScope,
    SecretIgnoreState,
    SecretRolloutState,
    SecretRuleCompileState,
    SecretRuleMatcherKind,
    SecretScanCoverageV2,
    parse_capability_evidence_manifest,
    reject_prohibited_fields,
    validate_capability_manifest,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _coverage(**overrides: object) -> SecretScanCoverageV2:
    payload: dict[str, object] = {
        "schema": "guard-secret-coverage.v2",
        "source_set": ["working_tree"],
        "requested_refs": ["refs/heads/main"],
        "completed_refs": ["refs/heads/main"],
        "files_scanned": 4,
        "bytes_scanned": 1024,
        "commits_visited": 0,
        "blobs_scanned": 4,
        "skipped_codes": [],
        "truncation_codes": [],
        "detector_version": "guard-secrets-v2",
        "model_version": None,
        "cache_hits": 0,
        "cache_misses": 4,
        "partial": False,
        "degraded": False,
        "error_code": None,
    }
    payload.update(overrides)
    return SecretScanCoverageV2.from_mapping(payload)


def _direct_coverage(**overrides: object) -> SecretScanCoverageV2:
    values: dict[str, object] = {
        "source_set": ("working_tree",),
        "requested_refs": ("refs/heads/main",),
        "completed_refs": ("refs/heads/main",),
        "files_scanned": 4,
        "bytes_scanned": 1024,
        "commits_visited": 0,
        "blobs_scanned": 4,
        "skipped_codes": (),
        "truncation_codes": (),
        "detector_version": "guard-secrets-v2",
    }
    values.update(overrides)
    return SecretScanCoverageV2(**values)  # type: ignore[arg-type]


def _capability(**overrides: object) -> CapabilityEvidenceV2:
    values: dict[str, object] = {
        "capability_id": "secret:cli",
        "product_boundary": "free-local",
        "surfaces": ("cli",),
        "plans": ("free",),
        "state": ParityState.TESTED,
        "acceptance_tests": ("test_cli",),
        "evidence_artifacts": (),
        "gap_label": "release evidence pending",
    }
    values.update(overrides)
    return CapabilityEvidenceV2(**values)  # type: ignore[arg-type]


def _manifest(**capability_overrides: object) -> dict[str, object]:
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
    capability.update(capability_overrides)
    return {
        "schema": "guard-secrets-capability-evidence.v2",
        "generated_at": "2026-08-12",
        "parity_states": [state.value for state in ParityState],
        "claim_policy": {
            "public_parity_requires": "verified_on_release_candidate",
            "exact_release_commit_required": True,
            "remaining_gaps_must_be_labeled": True,
        },
        "capabilities": [capability],
    }


def test_complete_coverage_is_clean_eligible() -> None:
    coverage = _coverage()

    coverage.assert_outcome(PreventionOutcome.CLEAN)
    assert coverage.clean_eligible is True
    assert coverage.to_public_dict()["clean_eligible"] is True


def test_partial_coverage_cannot_claim_clean() -> None:
    coverage = _coverage(partial=True, truncation_codes=["max_bytes"])

    with pytest.raises(SecretContractError, match="cannot produce a clean"):
        coverage.assert_outcome(PreventionOutcome.CLEAN)


def test_missing_requested_ref_cannot_claim_clean() -> None:
    coverage = _coverage(completed_refs=[])

    assert coverage.clean_eligible is False
    with pytest.raises(SecretContractError):
        coverage.assert_outcome(PreventionOutcome.CLEAN)


def test_direct_coverage_rejects_truncation_without_partial() -> None:
    with pytest.raises(SecretContractError, match="partial=true"):
        _direct_coverage(truncation_codes=("max_bytes",))


def test_direct_coverage_rejects_completed_ref_outside_request() -> None:
    with pytest.raises(SecretContractError, match="subset"):
        _direct_coverage(completed_refs=("refs/heads/other",))


def test_unknown_reason_code_is_rejected() -> None:
    with pytest.raises(SecretContractError, match="unknown reason codes"):
        _direct_coverage(skipped_codes=("future_unknown",))


def test_future_coverage_schema_is_rejected() -> None:
    with pytest.raises(SecretContractError, match="unsupported"):
        _coverage(schema="guard-secret-coverage.v3")


def test_unknown_coverage_field_is_rejected() -> None:
    with pytest.raises(SecretContractError, match="unknown fields"):
        _coverage(unreviewed="value")


def test_nested_raw_value_like_field_is_rejected() -> None:
    with pytest.raises(SecretContractError, match="prohibited"):
        reject_prohibited_fields({"safe": {"candidateValue": "not-serialized"}})


def test_approved_ignore_requires_approver() -> None:
    with pytest.raises(SecretContractError, match="approver"):
        SecretIgnoreDecisionV2(
            decision_id="ignore:1",
            state=SecretIgnoreState.APPROVED,
            requested_scope=SecretIgnoreScope.OCCURRENCE,
            durable_match_key="a" * 64,
            reason="Reviewed fixture",
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            detector_version="guard-secrets-v2",
            model_version=None,
            requester_id="user:1",
            approver_id=None,
            policy_source="personal",
            propagation=("cli", "github"),
        )


@pytest.mark.parametrize(
    "state",
    [SecretIgnoreState.EXPIRED, SecretIgnoreState.REVOKED, SecretIgnoreState.DENIED],
)
def test_terminal_ignore_state_retains_past_expiry(state: SecretIgnoreState) -> None:
    decision = SecretIgnoreDecisionV2(
        decision_id="ignore:terminal",
        state=state,
        requested_scope=SecretIgnoreScope.OCCURRENCE,
        durable_match_key="c" * 64,
        reason="Historical decision",
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        detector_version="guard-secrets-v2",
        model_version=None,
        requester_id="user:1",
        approver_id=None,
        policy_source="personal",
        propagation=("cli",),
    )

    assert decision.expires_at is not None


def test_active_ignore_rejects_past_expiry() -> None:
    with pytest.raises(SecretContractError, match="must be in the future"):
        SecretIgnoreDecisionV2(
            decision_id="ignore:active",
            state=SecretIgnoreState.REQUESTED,
            requested_scope=SecretIgnoreScope.OCCURRENCE,
            durable_match_key="d" * 64,
            reason="Pending review",
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
            detector_version="guard-secrets-v2",
            model_version=None,
            requester_id="user:1",
            approver_id=None,
            policy_source="personal",
            propagation=("cli",),
        )


def test_non_expiring_ignore_requires_fixture_justification() -> None:
    with pytest.raises(SecretContractError, match="justification"):
        SecretIgnoreDecisionV2(
            decision_id="ignore:2",
            state=SecretIgnoreState.REQUESTED,
            requested_scope=SecretIgnoreScope.FIXTURE,
            durable_match_key="b" * 64,
            reason="Reviewed fixture",
            expires_at=None,
            detector_version="guard-secrets-v2",
            model_version=None,
            requester_id="user:1",
            approver_id=None,
            policy_source="personal",
            propagation=("cli",),
        )


def test_active_custom_rule_must_compile_validly() -> None:
    with pytest.raises(SecretContractError, match="valid compiled"):
        SecretCustomRuleV2(
            rule_id="rule:custom:1",
            version="1.0.0",
            matcher_kind=SecretRuleMatcherKind.REGEX,
            matcher_digest="a" * 64,
            safe_fixture_digest="b" * 64,
            provenance_digest="c" * 64,
            compile_state=SecretRuleCompileState.TOO_COMPLEX,
            complexity_budget=100,
            rollout_state=SecretRolloutState.ACTIVE,
            surfaces=("cli",),
        )


def test_custom_rule_complexity_is_bounded() -> None:
    with pytest.raises(SecretContractError, match="complexity_budget"):
        SecretCustomRuleV2(
            rule_id="rule:custom:2",
            version="1.0.0",
            matcher_kind=SecretRuleMatcherKind.PREFIX,
            matcher_digest="a" * 64,
            safe_fixture_digest="b" * 64,
            provenance_digest="c" * 64,
            compile_state=SecretRuleCompileState.VALID,
            complexity_budget=100_001,
            rollout_state=SecretRolloutState.DRAFT,
            surfaces=("cli",),
        )


def test_release_claim_rejects_unverified_capability() -> None:
    capability = _capability()

    with pytest.raises(SecretContractError, match="not verified"):
        validate_capability_manifest(
            [capability],
            required_capability_ids=frozenset({"secret:cli"}),
            exact_release_commit="d" * 40,
        )


def test_release_claim_accepts_exact_commit_evidence() -> None:
    commit = "d" * 40
    capability = _capability(
        state=ParityState.VERIFIED_ON_RELEASE_CANDIDATE,
        evidence_artifacts=("sha256:benchmark",),
        release_commit=commit,
        gap_label=None,
    )

    validate_capability_manifest(
        [capability],
        required_capability_ids=frozenset({"secret:cli"}),
        exact_release_commit=commit,
    )


def test_malformed_release_commit_is_rejected() -> None:
    with pytest.raises(SecretContractError, match="full commit SHA"):
        validate_capability_manifest(
            [],
            required_capability_ids=frozenset(),
            exact_release_commit="D" * 40,
        )


def test_duplicate_capability_ids_are_rejected() -> None:
    capability = _capability()

    with pytest.raises(SecretContractError, match="must be unique"):
        validate_capability_manifest(
            [capability, capability],
            required_capability_ids=frozenset({"secret:cli"}),
            exact_release_commit="d" * 40,
        )


def test_missing_required_capability_is_rejected() -> None:
    with pytest.raises(SecretContractError, match="required capabilities are unmapped"):
        validate_capability_manifest(
            [],
            required_capability_ids=frozenset({"secret:ide"}),
            exact_release_commit="d" * 40,
        )


def test_every_outcome_has_a_surface_mapping() -> None:
    assert set(OUTCOME_SURFACE_MAPPING) == set(PreventionOutcome)


def test_repository_reason_code_registry_matches_runtime() -> None:
    payload = json.loads(
        (_REPOSITORY_ROOT / "docs/guard/contracts/guard-secrets-reason-codes.v2.json").read_text(encoding="utf-8")
    )
    categories = payload["categories"]
    declared = {code for codes in categories.values() for code in codes}

    assert declared == REASON_CODES_V2


def test_manifest_parser_consumes_declared_policy() -> None:
    manifest = parse_capability_evidence_manifest(_manifest())

    assert manifest.row_errors == ()
    assert manifest.public_parity_requires is ParityState.VERIFIED_ON_RELEASE_CANDIDATE
    assert manifest.exact_release_commit_required is True
    assert manifest.remaining_gaps_must_be_labeled is True


def test_manifest_parser_rejects_parity_state_drift() -> None:
    payload = _manifest()
    payload["parity_states"] = ["unmapped", "tested"]

    with pytest.raises(SecretContractError, match="do not match"):
        parse_capability_evidence_manifest(payload)


def test_manifest_parser_rejects_claim_policy_weakening() -> None:
    payload = _manifest()
    payload["claim_policy"] = {
        "public_parity_requires": "verified_on_release_candidate",
        "exact_release_commit_required": False,
        "remaining_gaps_must_be_labeled": True,
    }

    with pytest.raises(SecretContractError, match="must require"):
        parse_capability_evidence_manifest(payload)
