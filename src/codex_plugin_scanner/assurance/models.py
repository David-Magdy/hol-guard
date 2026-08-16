"""Typed contracts for extension assurance evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class Disposition(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    REVIEW = "review"
    BLOCK = "block"
    ERROR = "error"


DISPOSITION_ORDER: dict[Disposition, int] = {
    Disposition.ALLOW: 1,
    Disposition.WARN: 2,
    Disposition.REVIEW: 3,
    Disposition.BLOCK: 4,
    Disposition.ERROR: 5,
}


class CoverageState(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    INCOMPLETE = "incomplete"
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
    symbol: str | None = None
    excerpt_sha256: str | None = None


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
    source: str = "assurance-native"
    fingerprint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def with_fingerprint(self) -> SecurityFinding:
        if self.fingerprint:
            return self
        material = {
            "rule_id": self.rule_id,
            "category": self.category,
            "title": self.title,
            "locations": [asdict(location) for location in self.locations],
            "metadata": self.metadata,
        }
        digest = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
        return SecurityFinding(
            rule_id=self.rule_id,
            severity=self.severity,
            confidence=self.confidence,
            category=self.category,
            title=self.title,
            description=self.description,
            remediation=self.remediation,
            locations=self.locations,
            source=self.source,
            fingerprint=digest,
            metadata=self.metadata,
        )


@dataclass(frozen=True, slots=True)
class CoverageGap:
    code: str
    severity: Severity
    description: str
    path: str | None = None
    count: int = 1


@dataclass(frozen=True, slots=True)
class CoverageSummary:
    state: CoverageState
    inventory_files: int
    analyzed_files: int
    analyzed_bytes: int
    opaque_files: int = 0
    unreadable_files: int = 0
    oversized_files: int = 0
    archive_members: int = 0
    native_artifacts: int = 0
    rust_accelerated_files: int = 0
    gaps: tuple[CoverageGap, ...] = ()
    limitations: tuple[str, ...] = ()

    @property
    def percent(self) -> float:
        if self.inventory_files <= 0:
            return 0.0
        return round(min(1.0, self.analyzed_files / self.inventory_files) * 100.0, 2)


@dataclass(frozen=True, slots=True)
class EvidenceLayer:
    name: str
    status: str
    summary: str
    digest: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AssuranceDecision:
    disposition: Disposition
    reason: str
    blocking_fingerprints: tuple[str, ...] = ()
    review_fingerprints: tuple[str, ...] = ()
    required_actions: tuple[str, ...] = ()


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
    decision: AssuranceDecision
    layers: tuple[EvidenceLayer, ...]
    capabilities: tuple[str, ...] = ()
    dependencies: tuple[dict[str, Any], ...] = ()
    native_artifacts: tuple[dict[str, Any], ...] = ()
    archive_artifacts: tuple[dict[str, Any], ...] = ()
    policy: dict[str, Any] = field(default_factory=dict)
    drift: dict[str, Any] | None = None
    provenance: dict[str, Any] | None = None
    detonation: dict[str, Any] | None = None

    def to_payload(self) -> dict[str, Any]:
        payload = _jsonable(asdict(self))
        payload["evidence_digest"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        return payload


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        _jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def max_severity(findings: tuple[SecurityFinding, ...]) -> Severity | None:
    if not findings:
        return None
    return max(findings, key=lambda finding: SEVERITY_ORDER[finding.severity]).severity
