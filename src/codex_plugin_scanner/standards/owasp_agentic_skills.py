"""OWASP Agentic Skills Top 10 reference mappings for HOL Guard findings.

This module is descriptive metadata only. It does not alter scanner verdicts and
must not be used to claim OWASP compliance or certification.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


OWASP_AST10_VERSION = "1.0 (2026 Edition)"
OWASP_AST10_SOURCE_REVISION = "9faab9ae8d1f0dd132603264a50a679f94b6e955"
OWASP_AST10_SOURCE_PATH = "top10.md"


@dataclass(frozen=True, slots=True)
class AstRisk:
    risk_id: str
    name: str


class EvidenceState(str, Enum):
    """Scanner evidence state, independent from standards mapping."""

    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    NOT_TESTED = "not_tested"


OWASP_AST10_RISKS: dict[str, AstRisk] = {
    "AST01": AstRisk("AST01", "Malicious Skills"),
    "AST02": AstRisk("AST02", "Supply Chain Compromise"),
    "AST03": AstRisk("AST03", "Over-Privileged Skills"),
    "AST04": AstRisk("AST04", "Insecure Metadata"),
    "AST05": AstRisk("AST05", "Unsafe Deserialization"),
    "AST06": AstRisk("AST06", "Weak Isolation"),
    "AST07": AstRisk("AST07", "Update Drift"),
    "AST08": AstRisk("AST08", "Poor Scanning"),
    "AST09": AstRisk("AST09", "No Governance"),
    "AST10": AstRisk("AST10", "Cross-Platform Reuse"),
}

# Only map rules when the association is narrow enough to be useful. Everything
# else is deliberately UNMAPPED rather than inferred from a broad category name.
_RULE_RISK_IDS: dict[str, tuple[str, ...]] = {
    "SECURITY_MD_MISSING": ("AST09",),
    "RISKY_APPROVAL_DEFAULT": ("AST03", "AST06"),
}

_UNMAPPED_REASON = (
    "No conservative OWASP Agentic Skills Top 10 association is encoded for this "
    "HOL Guard rule. This does not mean the finding is unimportant."
)


@dataclass(frozen=True, slots=True)
class AstMapping:
    rule_id: str
    risks: tuple[AstRisk, ...]
    mapped: bool
    note: str


def map_rule_id(rule_id: str) -> AstMapping:
    """Return a conservative AST10 association for a HOL Guard rule ID."""

    normalized = rule_id.strip().upper()
    risk_ids = _RULE_RISK_IDS.get(normalized, ())
    if not risk_ids:
        return AstMapping(
            rule_id=normalized,
            risks=(),
            mapped=False,
            note=_UNMAPPED_REASON,
        )
    return AstMapping(
        rule_id=normalized,
        risks=tuple(OWASP_AST10_RISKS[risk_id] for risk_id in risk_ids),
        mapped=True,
        note=(
            "Reference mapping only. A mapped finding is not evidence of full "
            "coverage, conformance, compliance, or certification."
        ),
    )


def evidence_record(rule_id: str, state: EvidenceState) -> dict[str, object]:
    """Build machine-readable evidence without conflating scan state and risk mapping."""

    mapping = map_rule_id(rule_id)
    return {
        "schema": "hol.guard.owasp-agentic-skills.v1",
        "source": {
            "version": OWASP_AST10_VERSION,
            "revision": OWASP_AST10_SOURCE_REVISION,
            "path": OWASP_AST10_SOURCE_PATH,
        },
        "finding": {
            "rule_id": mapping.rule_id,
            "state": state.value,
        },
        "mapping": {
            "status": "mapped" if mapping.mapped else "unmapped",
            "risks": [
                {"id": risk.risk_id, "name": risk.name}
                for risk in mapping.risks
            ],
            "note": mapping.note,
        },
    }
