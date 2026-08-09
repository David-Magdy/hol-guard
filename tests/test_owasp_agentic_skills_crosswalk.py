from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.standards.owasp_agentic_skills import (
    EvidenceState,
    OWASP_AST10_RISKS,
    OWASP_AST10_SOURCE_REVISION,
    evidence_record,
    map_rule_id,
)


def test_risk_catalog_is_exactly_ast01_through_ast10() -> None:
    assert tuple(OWASP_AST10_RISKS) == tuple(f"AST{index:02d}" for index in range(1, 11))
    assert len({risk.name for risk in OWASP_AST10_RISKS.values()}) == 10


@pytest.mark.parametrize(
    ("rule_id", "expected"),
    [
        ("SECURITY_MD_MISSING", ("AST09",)),
        ("RISKY_APPROVAL_DEFAULT", ("AST03", "AST06")),
    ],
)
def test_conservative_rule_mappings(rule_id: str, expected: tuple[str, ...]) -> None:
    mapping = map_rule_id(rule_id)

    assert mapping.mapped is True
    assert tuple(risk.risk_id for risk in mapping.risks) == expected
    assert "compliance" in mapping.note


@pytest.mark.parametrize(
    "rule_id",
    [
        "HARDCODED_SECRET",
        "DANGEROUS_MCP_COMMAND",
        "MCP_REMOTE_URL_INSECURE",
        "UNKNOWN_FUTURE_RULE",
    ],
)
def test_unreviewed_or_out_of_scope_rules_are_explicitly_unmapped(rule_id: str) -> None:
    mapping = map_rule_id(rule_id)

    assert mapping.mapped is False
    assert mapping.risks == ()
    assert "does not mean the finding is unimportant" in mapping.note


@pytest.mark.parametrize("state", list(EvidenceState))
def test_evidence_keeps_scanner_state_separate_from_mapping(state: EvidenceState) -> None:
    payload = evidence_record("SECURITY_MD_MISSING", state)

    assert payload["finding"] == {
        "rule_id": "SECURITY_MD_MISSING",
        "state": state.value,
    }
    assert payload["mapping"]["status"] == "mapped"
    assert payload["mapping"]["risks"] == [{"id": "AST09", "name": "No Governance"}]
    assert payload["source"]["revision"] == OWASP_AST10_SOURCE_REVISION

    json.dumps(payload)


def test_rule_ids_are_normalized_without_guessing() -> None:
    assert map_rule_id(" security_md_missing ").rule_id == "SECURITY_MD_MISSING"
    assert map_rule_id(" never-seen-before ").mapped is False
