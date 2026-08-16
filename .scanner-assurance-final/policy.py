# pyright: basic
"""Managed assurance policy composition and consumer-facing decisions."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

from .models import (
    AssuranceLevel,
    Confidence,
    CoverageState,
    Disposition,
    ScanDecision,
    SecurityFinding,
    Severity,
)


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}
CONFIDENCE_ORDER: dict[Confidence, int] = {
    Confidence.UNKNOWN: 1,
    Confidence.LOW: 2,
    Confidence.MEDIUM: 3,
    Confidence.HIGH: 4,
}
DISPOSITION_ORDER: dict[Disposition, int] = {
    Disposition.ALLOW: 0,
    Disposition.WARN: 1,
    Disposition.REVIEW: 2,
    Disposition.BLOCK: 3,
    Disposition.ERROR: 4,
}
ASSURANCE_ORDER: dict[AssuranceLevel, int] = {
    AssuranceLevel.STATIC: 0,
    AssuranceLevel.PROVENANCE_VERIFIED: 1,
    AssuranceLevel.SANDBOX_PLANNED: 2,
    AssuranceLevel.SANDBOX_OBSERVED: 3,
}


@dataclass(frozen=True, slots=True)
class AssurancePolicy:
    name: str = "balanced"
    block_at: Severity = Severity.HIGH
    review_at: Severity = Severity.MEDIUM
    warn_at: Severity = Severity.LOW
    minimum_confidence: Confidence = Confidence.LOW
    incomplete_coverage: Disposition = Disposition.REVIEW
    error_coverage: Disposition = Disposition.ERROR
    minimum_assurance: AssuranceLevel = AssuranceLevel.STATIC
    require_provenance: bool = False
    require_detonation: bool = False
    require_rust_for_native: bool = False
    deny_capabilities: tuple[str, ...] = ()
    allowed_upload_hosts: tuple[str, ...] = ()
    trusted_signers: tuple[str, ...] = ()
    maximum_evidence_age_seconds: int = 7 * 24 * 60 * 60
    maximum_clock_skew_seconds: int = 300
    maximum_findings: int = 100_000
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.name or len(self.name) > 128:
            raise ValueError("policy name is invalid")
        if SEVERITY_ORDER[self.block_at] < SEVERITY_ORDER[self.review_at]:
            raise ValueError("block_at cannot be less severe than review_at")
        if SEVERITY_ORDER[self.review_at] < SEVERITY_ORDER[self.warn_at]:
            raise ValueError("review_at cannot be less severe than warn_at")
        if self.maximum_evidence_age_seconds <= 0:
            raise ValueError("maximum_evidence_age_seconds must be positive")
        if self.maximum_clock_skew_seconds < 0:
            raise ValueError("maximum_clock_skew_seconds cannot be negative")
        if self.maximum_findings <= 0 or self.maximum_findings > 1_000_000:
            raise ValueError("maximum_findings is outside the allowed range")
        if any(not value or len(value) > 256 for value in self.deny_capabilities):
            raise ValueError("deny_capabilities contains an invalid value")
        if any(len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value) for value in self.trusted_signers):
            raise ValueError("trusted_signers must contain lowercase SHA-256 key identifiers")

    def to_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        for field_name in (
            "block_at",
            "review_at",
            "warn_at",
            "minimum_confidence",
            "incomplete_coverage",
            "error_coverage",
            "minimum_assurance",
        ):
            payload[field_name] = getattr(self, field_name).value
        payload["deny_capabilities"] = list(self.deny_capabilities)
        payload["allowed_upload_hosts"] = list(self.allowed_upload_hosts)
        payload["trusted_signers"] = list(self.trusted_signers)
        payload["schema_version"] = "hol-guard.assurance-policy.v1"
        return payload


BUILTIN_POLICIES: dict[str, AssurancePolicy] = {
    "audit": AssurancePolicy(
        name="audit",
        block_at=Severity.CRITICAL,
        review_at=Severity.HIGH,
        warn_at=Severity.MEDIUM,
        minimum_confidence=Confidence.MEDIUM,
        incomplete_coverage=Disposition.WARN,
        error_coverage=Disposition.ERROR,
    ),
    "balanced": AssurancePolicy(
        name="balanced",
        block_at=Severity.HIGH,
        review_at=Severity.MEDIUM,
        warn_at=Severity.LOW,
        minimum_confidence=Confidence.LOW,
        incomplete_coverage=Disposition.REVIEW,
        error_coverage=Disposition.ERROR,
        deny_capabilities=("privilege-escalation", "process-injection"),
    ),
    "consumer-install": AssurancePolicy(
        name="consumer-install",
        block_at=Severity.HIGH,
        review_at=Severity.MEDIUM,
        warn_at=Severity.LOW,
        minimum_confidence=Confidence.LOW,
        incomplete_coverage=Disposition.BLOCK,
        error_coverage=Disposition.ERROR,
        minimum_assurance=AssuranceLevel.PROVENANCE_VERIFIED,
        require_provenance=True,
        require_rust_for_native=True,
        deny_capabilities=(
            "credential-store",
            "input-capture",
            "privilege-escalation",
            "process-injection",
            "container-control",
        ),
        maximum_evidence_age_seconds=24 * 60 * 60,
    ),
    "enterprise-strict": AssurancePolicy(
        name="enterprise-strict",
        block_at=Severity.MEDIUM,
        review_at=Severity.LOW,
        warn_at=Severity.INFO,
        minimum_confidence=Confidence.UNKNOWN,
        incomplete_coverage=Disposition.BLOCK,
        error_coverage=Disposition.ERROR,
        minimum_assurance=AssuranceLevel.SANDBOX_OBSERVED,
        require_provenance=True,
        require_detonation=True,
        require_rust_for_native=True,
        deny_capabilities=(
            "credential-store",
            "input-capture",
            "privilege-escalation",
            "process-injection",
            "container-control",
            "tls-bypass",
        ),
        maximum_evidence_age_seconds=12 * 60 * 60,
        maximum_clock_skew_seconds=120,
    ),
}


def load_policy(path: Path | None, *, profile: str = "balanced") -> AssurancePolicy:
    try:
        builtin = BUILTIN_POLICIES[profile]
    except KeyError as exc:
        raise ValueError(f"unknown assurance profile: {profile}") from exc
    if path is None:
        builtin.validate()
        return builtin
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"failed to read assurance policy: {exc}") from exc
    if len(raw) > 1024 * 1024:
        raise ValueError("assurance policy exceeds size limit")
    try:
        if path.suffix.lower() == ".toml":
            payload = tomllib.loads(raw.decode("utf-8"))
        else:
            payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("assurance policy is not valid JSON or TOML") from exc
    custom = policy_from_payload(payload)
    composed = compose_managed_policy(builtin, custom, None)
    composed.validate()
    return composed


def policy_from_payload(payload: object) -> AssurancePolicy:
    if not isinstance(payload, dict):
        raise ValueError("assurance policy must be an object")
    allowed = {
        "schema_version",
        "name",
        "block_at",
        "review_at",
        "warn_at",
        "minimum_confidence",
        "incomplete_coverage",
        "error_coverage",
        "minimum_assurance",
        "require_provenance",
        "require_detonation",
        "require_rust_for_native",
        "deny_capabilities",
        "allowed_upload_hosts",
        "trusted_signers",
        "maximum_evidence_age_seconds",
        "maximum_clock_skew_seconds",
        "maximum_findings",
        "metadata",
    }
    unknown = set(payload) - allowed
    if unknown:
        raise ValueError(f"unknown assurance policy fields: {', '.join(sorted(unknown))}")
    if payload.get("schema_version", "hol-guard.assurance-policy.v1") != "hol-guard.assurance-policy.v1":
        raise ValueError("unsupported assurance policy schema")
    kwargs: dict[str, Any] = {}
    converters = {
        "block_at": Severity,
        "review_at": Severity,
        "warn_at": Severity,
        "minimum_confidence": Confidence,
        "incomplete_coverage": Disposition,
        "error_coverage": Disposition,
        "minimum_assurance": AssuranceLevel,
    }
    for key, converter in converters.items():
        if key in payload:
            try:
                kwargs[key] = converter(str(payload[key]))
            except ValueError as exc:
                raise ValueError(f"invalid assurance policy {key}") from exc
    for key in (
        "name",
        "require_provenance",
        "require_detonation",
        "require_rust_for_native",
        "maximum_evidence_age_seconds",
        "maximum_clock_skew_seconds",
        "maximum_findings",
        "metadata",
    ):
        if key in payload:
            kwargs[key] = payload[key]
    for key in ("deny_capabilities", "allowed_upload_hosts", "trusted_signers"):
        if key in payload:
            values = payload[key]
            if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
                raise ValueError(f"assurance policy {key} must be a string array")
            kwargs[key] = tuple(values)
    policy = AssurancePolicy(**kwargs)
    policy.validate()
    return policy


def compose_managed_policy(
    managed: AssurancePolicy,
    repository: AssurancePolicy | None,
    user: AssurancePolicy | None,
) -> AssurancePolicy:
    """Compose policy layers without allowing lower-precedence weakening."""

    result = managed
    for lower in (repository, user):
        if lower is None:
            continue
        result = AssurancePolicy(
            name=result.name,
            block_at=_stricter_severity(result.block_at, lower.block_at),
            review_at=_stricter_severity(result.review_at, lower.review_at),
            warn_at=_stricter_severity(result.warn_at, lower.warn_at),
            minimum_confidence=_broader_confidence(result.minimum_confidence, lower.minimum_confidence),
            incomplete_coverage=_more_restrictive(result.incomplete_coverage, lower.incomplete_coverage),
            error_coverage=_more_restrictive(result.error_coverage, lower.error_coverage),
            minimum_assurance=_higher_assurance(result.minimum_assurance, lower.minimum_assurance),
            require_provenance=result.require_provenance or lower.require_provenance,
            require_detonation=result.require_detonation or lower.require_detonation,
            require_rust_for_native=result.require_rust_for_native or lower.require_rust_for_native,
            deny_capabilities=tuple(sorted(set(result.deny_capabilities) | set(lower.deny_capabilities))),
            allowed_upload_hosts=_constrained_set(result.allowed_upload_hosts, lower.allowed_upload_hosts),
            trusted_signers=_constrained_set(result.trusted_signers, lower.trusted_signers),
            maximum_evidence_age_seconds=min(
                result.maximum_evidence_age_seconds,
                lower.maximum_evidence_age_seconds,
            ),
            maximum_clock_skew_seconds=min(
                result.maximum_clock_skew_seconds,
                lower.maximum_clock_skew_seconds,
            ),
            maximum_findings=min(result.maximum_findings, lower.maximum_findings),
            metadata={**lower.metadata, **result.metadata},
        )
    result.validate()
    return result


def evaluate_decision(
    findings: tuple[SecurityFinding, ...],
    *,
    coverage: CoverageState,
    assurance_level: AssuranceLevel,
    capabilities: tuple[str, ...],
    policy: AssurancePolicy,
    provenance_verified: bool,
    detonation_observed: bool,
    native_count: int,
    rust_accelerated_files: int,
) -> ScanDecision:
    policy.validate()
    disposition = Disposition.ALLOW
    blocking: list[str] = []
    review: list[str] = []
    actions: list[str] = []
    for finding in findings:
        if CONFIDENCE_ORDER[finding.confidence] < CONFIDENCE_ORDER[policy.minimum_confidence]:
            continue
        severity = SEVERITY_ORDER[finding.severity]
        if severity >= SEVERITY_ORDER[policy.block_at]:
            disposition = _more_restrictive(disposition, Disposition.BLOCK)
            blocking.append(finding.fingerprint)
        elif severity >= SEVERITY_ORDER[policy.review_at]:
            disposition = _more_restrictive(disposition, Disposition.REVIEW)
            review.append(finding.fingerprint)
        elif severity >= SEVERITY_ORDER[policy.warn_at]:
            disposition = _more_restrictive(disposition, Disposition.WARN)
    if coverage in {CoverageState.PARTIAL, CoverageState.INCOMPLETE}:
        disposition = _more_restrictive(disposition, policy.incomplete_coverage)
        actions.append(f"resolve {coverage.value} scan coverage before installation")
    elif coverage == CoverageState.ERROR:
        disposition = _more_restrictive(disposition, policy.error_coverage)
        actions.append("resolve the assurance scanner error")
    denied = sorted(set(capabilities) & set(policy.deny_capabilities))
    if denied:
        disposition = _more_restrictive(disposition, Disposition.BLOCK)
        actions.append(f"remove or explicitly isolate denied capabilities: {', '.join(denied)}")
    if ASSURANCE_ORDER[assurance_level] < ASSURANCE_ORDER[policy.minimum_assurance]:
        disposition = _more_restrictive(disposition, Disposition.BLOCK)
        actions.append(f"raise assurance to at least {policy.minimum_assurance.value}")
    if policy.require_provenance and not provenance_verified:
        disposition = _more_restrictive(disposition, Disposition.BLOCK)
        actions.append("verify trusted exact-artifact provenance")
    if policy.require_detonation and not detonation_observed:
        disposition = _more_restrictive(disposition, Disposition.BLOCK)
        actions.append("produce a bound sandbox observation")
    if policy.require_rust_for_native and native_count > rust_accelerated_files:
        disposition = _more_restrictive(disposition, Disposition.BLOCK)
        actions.append("structurally parse every native artifact with the reviewed Rust engine")
    if len(findings) > policy.maximum_findings:
        disposition = Disposition.ERROR
        actions.append("reduce or partition the finding set before policy evaluation")
    reason = _decision_reason(disposition, len(blocking), len(review), coverage, assurance_level)
    return ScanDecision(
        disposition=disposition,
        reason=reason,
        blocking_fingerprints=tuple(sorted(set(blocking))),
        review_fingerprints=tuple(sorted(set(review))),
        required_actions=tuple(dict.fromkeys(actions)),
    )


def _decision_reason(
    disposition: Disposition,
    blocking_count: int,
    review_count: int,
    coverage: CoverageState,
    assurance_level: AssuranceLevel,
) -> str:
    return (
        f"Managed policy produced {disposition.value}: {blocking_count} blocking and "
        f"{review_count} review findings, coverage={coverage.value}, "
        f"assurance={assurance_level.value}."
    )


def _stricter_severity(left: Severity, right: Severity) -> Severity:
    return left if SEVERITY_ORDER[left] <= SEVERITY_ORDER[right] else right


def _broader_confidence(left: Confidence, right: Confidence) -> Confidence:
    return left if CONFIDENCE_ORDER[left] <= CONFIDENCE_ORDER[right] else right


def _more_restrictive(left: Disposition, right: Disposition) -> Disposition:
    return left if DISPOSITION_ORDER[left] >= DISPOSITION_ORDER[right] else right


def _higher_assurance(left: AssuranceLevel, right: AssuranceLevel) -> AssuranceLevel:
    return left if ASSURANCE_ORDER[left] >= ASSURANCE_ORDER[right] else right


def _constrained_set(left: tuple[str, ...], right: tuple[str, ...]) -> tuple[str, ...]:
    if left and right:
        return tuple(sorted(set(left) & set(right)))
    return tuple(sorted(set(left or right)))


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate policy key: {key}")
        result[key] = value
    return result
