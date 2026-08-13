from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from codex_plugin_scanner.guard.secrets.contracts_v2 import (
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
    reject_prohibited_fields,
    validate_capability_manifest,
)


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
    capability = CapabilityEvidenceV2(
        capability_id="secret:ide",
        product_boundary="free-local",
        surfaces=("ide",),
        plans=("free", "solo", "pro", "team"),
        state=ParityState.TESTED,
        acceptance_tests=("test_ide",),
        evidence_artifacts=(),
    )

    with pytest.raises(SecretContractError, match="not verified"):
        validate_capability_manifest(
            [capability],
            required_capability_ids=frozenset({"secret:ide"}),
            exact_release_commit="d" * 40,
        )


def test_release_claim_accepts_exact_commit_evidence() -> None:
    commit = "d" * 40
    capability = CapabilityEvidenceV2(
        capability_id="secret:cli",
        product_boundary="free-local",
        surfaces=("cli", "pre_commit"),
        plans=("free", "solo", "pro", "team"),
        state=ParityState.VERIFIED_ON_RELEASE_CANDIDATE,
        acceptance_tests=("test_cli",),
        evidence_artifacts=("sha256:benchmark",),
        release_commit=commit,
    )

    validate_capability_manifest(
        [capability],
        required_capability_ids=frozenset({"secret:cli"}),
        exact_release_commit=commit,
    )
