# pyright: basic
"""Stable evidence contracts for layered extension assurance."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field, replace
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class CoverageState(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    INCOMPLETE = "incomplete"
    ERROR = "error"


class Disposition(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    REVIEW = "review"
    BLOCK = "block"
    ERROR = "error"


class AssuranceLevel(str, Enum):
    STATIC = "static"
    PROVENANCE_VERIFIED = "provenance-verified"
    SANDBOX_PLANNED = "sandbox-planned"
    SANDBOX_OBSERVED = "sandbox-observed"


@dataclass(frozen=True, slots=True)
class EvidenceLocation:
    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    excerpt_sha256: str | None = None
    note: str | None = None

    def to_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SecurityFinding:
    rule_id: str
    severity: Severity
    confidence: Confidence
    category: str
    title: str
    description: str
    remediation: str
    locations: tuple[EvidenceLocation, ...] = ()
    source: str = "native-assurance"
    fingerprint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    def with_fingerprint(self) -> SecurityFinding:
        normalized = {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "title": self.title,
            "source": self.source,
            "locations": [location.to_payload() for location in self.locations],
            "metadata": self.metadata,
        }
        fingerprint = hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()
        return replace(self, fingerprint=fingerprint)

    def to_payload(self) -> dict[str, Any]:
        fingerprint = self.fingerprint or self.with_fingerprint().fingerprint
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "locations": [location.to_payload() for location in self.locations],
            "source": self.source,
            "fingerprint": fingerprint,
            "metadata": self.metadata,
        }


@dataclass(frozen=True, slots=True)
class CoverageGap:
    code: str
    severity: Severity
    description: str
    path: str | None = None
    count: int = 1

    def to_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["severity"] = self.severity.value
        return payload


@dataclass(frozen=True, slots=True)
class CoverageSummary:
    state: CoverageState
    inventory_files: int
    analyzed_files: int
    analyzed_bytes: int
    opaque_files: int
    unreadable_files: int
    oversized_files: int
    archive_members: int
    native_artifacts: int
    rust_accelerated_files: int
    gaps: tuple[CoverageGap, ...] = ()
    limitations: tuple[str, ...] = ()

    def to_payload(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "inventory_files": self.inventory_files,
            "analyzed_files": self.analyzed_files,
            "analyzed_bytes": self.analyzed_bytes,
            "opaque_files": self.opaque_files,
            "unreadable_files": self.unreadable_files,
            "oversized_files": self.oversized_files,
            "archive_members": self.archive_members,
            "native_artifacts": self.native_artifacts,
            "rust_accelerated_files": self.rust_accelerated_files,
            "gaps": [gap.to_payload() for gap in self.gaps],
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class ScanDecision:
    disposition: Disposition
    reason: str
    blocking_fingerprints: tuple[str, ...] = ()
    review_fingerprints: tuple[str, ...] = ()
    required_actions: tuple[str, ...] = ()

    def to_payload(self) -> dict[str, Any]:
        return {
            "disposition": self.disposition.value,
            "reason": self.reason,
            "blocking_fingerprints": list(self.blocking_fingerprints),
            "review_fingerprints": list(self.review_fingerprints),
            "required_actions": list(self.required_actions),
        }


@dataclass(frozen=True, slots=True)
class EvidenceLayer:
    name: str
    status: str
    summary: str
    digest: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AssuranceReport:
    schema_version: str
    scanner_version: str
    artifact_root: str
    artifact_digest: str
    generated_at: str
    assurance_level: AssuranceLevel
    coverage: CoverageSummary
    findings: tuple[SecurityFinding, ...]
    decision: ScanDecision
    layers: tuple[EvidenceLayer, ...]
    capabilities: tuple[str, ...]
    dependencies: tuple[dict[str, Any], ...]
    native_artifacts: tuple[dict[str, Any], ...]
    archive_artifacts: tuple[dict[str, Any], ...]
    policy: dict[str, Any]
    drift: dict[str, Any] | None = None
    provenance: dict[str, Any] | None = None
    detonation: dict[str, Any] | None = None

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "scanner_version": self.scanner_version,
            "artifact_root": self.artifact_root,
            "artifact_digest": self.artifact_digest,
            "generated_at": self.generated_at,
            "assurance_level": self.assurance_level.value,
            "coverage": self.coverage.to_payload(),
            "findings": [finding.to_payload() for finding in self.findings],
            "decision": self.decision.to_payload(),
            "layers": [layer.to_payload() for layer in self.layers],
            "capabilities": list(self.capabilities),
            "dependencies": list(self.dependencies),
            "native_artifacts": list(self.native_artifacts),
            "archive_artifacts": list(self.archive_artifacts),
            "policy": self.policy,
            "drift": self.drift,
            "provenance": self.provenance,
            "detonation": self.detonation,
        }
        payload["evidence_digest"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        return payload


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
