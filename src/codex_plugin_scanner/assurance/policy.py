"""Managed policy composition and assurance decision evaluation."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .models import (
    AssuranceDecision,
    AssuranceLevel,
    Confidence,
    CoverageState,
    DISPOSITION_ORDER,
    Disposition,
    SEVERITY_ORDER,
    SecurityFinding,
    Severity,
)


ASSURANCE_ORDER: dict[AssuranceLevel, int] = {
    AssuranceLevel.STATIC: 1,
    AssuranceLevel.PROVENANCE_VERIFIED: 2,
    AssuranceLevel.SANDBOX_PLANNED: 3,
    AssuranceLevel.SANDBOX_OBSERVED: 4,
}


@dataclass(frozen=True, slots=True)
class AssurancePolicy:
    schema_version: str = "hol-guard.assurance-policy.v1"
    name: str = "balanced"
    block_at: Severity = Severity.CRITICAL
    review_at: Severity = Severity.HIGH
    warn_at: Severity = Severity.MEDIUM
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
    maximum_evidence_age_seconds: int = 86_400
    maximum_clock_skew_seconds: int = 300
    maximum_findings: int = 10_000
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        for key in (
            "block_at",
            "review_at",
            "warn_at",
            "minimum_confidence",
            "incomplete_coverage",
            "error_coverage",
            "minimum_assurance",
        ):
            payload[key] = getattr(self, key).value
        payload["deny_capabilities"] = list(self.deny_capabilities)
        payload["allowed_upload_hosts"] = list(self.allowed_upload_hosts)
        payload["trusted_signers"] = list(self.trusted_signers)
        return payload


BUILTIN_POLICIES: dict[str, AssurancePolicy] = {
    "audit": AssurancePolicy(
        name="audit",
        block_at=Severity.CRITICAL,
        review_at=Severity.CRITICAL,
        warn_at=Severity.HIGH,
        incomplete_coverage=Disposition.WARN,
    ),
    "balanced": AssurancePolicy(name="balanced"),
    "consumer-install": AssurancePolicy(
        name="consumer-install",
        block_at=Severity.HIGH,
        review_at=Severity.MEDIUM,
        warn_at=Severity.LOW,
        incomplete_coverage=Disposition.BLOCK,
        require_rust_for_native=False,
        deny_capabilities=(
            "credential-store",
            "input-capture",
            "kernel-interface",
            "container-control",
            "cloud-metadata",
        ),
    ),
    "enterprise-strict": AssurancePolicy(
        name="enterprise-strict",
        block_at=Severity.MEDIUM,
        review_at=Severity.LOW,
        warn_at=Severity.INFO,
        incomplete_coverage=Disposition.BLOCK,
        minimum_assurance=AssuranceLevel.PROVENANCE_VERIFIED,
        require_provenance=True,
        require_detonation=True,
        require_rust_for_native=True,
        deny_capabilities=(
            "credential-store",
            "input-capture",
            "kernel-interface",
            "container-control",
            "cloud-metadata",
            "privilege-escalation",
            "persistence",
        ),
        maximum_evidence_age_seconds=3_600,
    ),
}


class PolicyError(ValueError):
    pass


def load_policy(path: Path | None = None, *, profile: str = "balanced") -> AssurancePolicy:
    base = BUILTIN_POLICIES.get(profile)
    if base is None:
        raise PolicyError(f"unknown assurance policy profile: {profile}")
    if path is None:
        return base
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"failed to load assurance policy {path}: {exc}") from exc
    return policy_from_payload(payload, base=base)


def policy_from_payload(payload: object, *, base: AssurancePolicy | None = None) -> AssurancePolicy:
    if not isinstance(payload, dict):
        raise PolicyError("assurance policy must be a JSON object")
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
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise PolicyError(f"unknown assurance policy fields: {', '.join(unknown)}")
    seed = base or BUILTIN_POLICIES["balanced"]
    values = seed.to_payload()
    values.update(payload)
    if values.get("schema_version") != "hol-guard.assurance-policy.v1":
        raise PolicyError("unsupported assurance policy schema_version")
    try:
        policy = AssurancePolicy(
            schema_version=str(values["schema_version"]),
            name=str(values["name"]),
            block_at=Severity(str(values["block_at"])),
            review_at=Severity(str(values["review_at"])),
            warn_at=Severity(str(values["warn_at"])),
            minimum_confidence=Confidence(str(values["minimum_confidence"])),
            incomplete_coverage=Disposition(str(values["incomplete_coverage"])),
            error_coverage=Disposition(str(values["error_coverage"])),
            minimum_assurance=AssuranceLevel(str(values["minimum_assurance"])),
            require_provenance=_strict_bool(values["require_provenance"], "require_provenance"),
            require_detonation=_strict_bool(values["require_detonation"], "require_detonation"),
            require_rust_for_native=_strict_bool(values["require_rust_for_native"], "require_rust_for_native"),
            deny_capabilities=_string_tuple(values["deny_capabilities"], "deny_capabilities"),
            allowed_upload_hosts=_string_tuple(values["allowed_upload_hosts"], "allowed_upload_hosts"),
            trusted_signers=_string_tuple(values["trusted_signers"], "trusted_signers"),
            maximum_evidence_age_seconds=_positive_int(
                values["maximum_evidence_age_seconds"], "maximum_evidence_age_seconds"
            ),
            maximum_clock_skew_seconds=_positive_int(
                values["maximum_clock_skew_seconds"], "maximum_clock_skew_seconds", allow_zero=True
            ),
            maximum_findings=_positive_int(values["maximum_findings"], "maximum_findings"),
            metadata=_object(values["metadata"], "metadata"),
        )
    except (KeyError, ValueError) as exc:
        raise PolicyError(f"invalid assurance policy: {exc}") from exc
    if SEVERITY_ORDER[policy.block_at] < SEVERITY_ORDER[policy.review_at]:
        raise PolicyError("block_at must be at least as severe as review_at")
    if SEVERITY_ORDER[policy.review_at] < SEVERITY_ORDER[policy.warn_at]:
        raise PolicyError("review_at must be at least as severe as warn_at")
    return policy


def compose_managed_policy(
    managed: AssurancePolicy | None,
    repository: AssurancePolicy | None,
    user: AssurancePolicy | None,
) -> AssurancePolicy:
    """Compose policies without allowing a lower-precedence layer to weaken a floor."""

    layers = [policy for policy in (managed, repository, user) if policy is not None]
    if not layers:
        return BUILTIN_POLICIES["balanced"]
    result = layers[0]
    for candidate in layers[1:]:
        result = AssurancePolicy(
            name=f"{result.name}+{candidate.name}",
            block_at=_less_severe(result.block_at, candidate.block_at),
            review_at=_less_severe(result.review_at, candidate.review_at),
            warn_at=_less_severe(result.warn_at, candidate.warn_at),
            minimum_confidence=_stricter_confidence(result.minimum_confidence, candidate.minimum_confidence),
            incomplete_coverage=_more_restrictive(result.incomplete_coverage, candidate.incomplete_coverage),
            error_coverage=_more_restrictive(result.error_coverage, candidate.error_coverage),
            minimum_assurance=_higher_assurance(result.minimum_assurance, candidate.minimum_assurance),
            require_provenance=result.require_provenance or candidate.require_provenance,
            require_detonation=result.require_detonation or candidate.require_detonation,
            require_rust_for_native=result.require_rust_for_native or candidate.require_rust_for_native,
            deny_capabilities=tuple(sorted(set(result.deny_capabilities) | set(candidate.deny_capabilities))),
            allowed_upload_hosts=_intersect_allowlists(
                result.allowed_upload_hosts, candidate.allowed_upload_hosts
            ),
            trusted_signers=_intersect_allowlists(result.trusted_signers, candidate.trusted_signers),
            maximum_evidence_age_seconds=min(
                result.maximum_evidence_age_seconds, candidate.maximum_evidence_age_seconds
            ),
            maximum_clock_skew_seconds=min(
                result.maximum_clock_skew_seconds, candidate.maximum_clock_skew_seconds
            ),
            maximum_findings=min(result.maximum_findings, candidate.maximum_findings),
            metadata={**candidate.metadata, **result.metadata},
        )
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
) -> AssuranceDecision:
    blocking: list[str] = []
    review: list[str] = []
    reasons: list[str] = []
    disposition = Disposition.ALLOW

    if len(findings) > policy.maximum_findings:
        return AssuranceDecision(
            disposition=Disposition.ERROR,
            reason="finding limit exceeded; report is not safe to treat as complete",
            required_actions=("raise the managed limit only after reviewing scanner resource use",),
        )

    for finding in findings:
        severity = SEVERITY_ORDER[finding.severity]
        if severity >= SEVERITY_ORDER[policy.block_at]:
            blocking.append(finding.fingerprint)
            disposition = _more_restrictive(disposition, Disposition.BLOCK)
        elif severity >= SEVERITY_ORDER[policy.review_at]:
            review.append(finding.fingerprint)
            disposition = _more_restrictive(disposition, Disposition.REVIEW)
        elif severity >= SEVERITY_ORDER[policy.warn_at]:
            disposition = _more_restrictive(disposition, Disposition.WARN)

    denied = sorted(set(capabilities) & set(policy.deny_capabilities))
    if denied:
        disposition = _more_restrictive(disposition, Disposition.BLOCK)
        reasons.append(f"managed policy denies capabilities: {', '.join(denied)}")

    if coverage in {CoverageState.INCOMPLETE, CoverageState.PARTIAL}:
        disposition = _more_restrictive(disposition, policy.incomplete_coverage)
        reasons.append(f"scan coverage is {coverage.value}")
    elif coverage is CoverageState.ERROR:
        disposition = _more_restrictive(disposition, policy.error_coverage)
        reasons.append("scan coverage failed")

    required_actions: list[str] = []
    if ASSURANCE_ORDER[assurance_level] < ASSURANCE_ORDER[policy.minimum_assurance]:
        disposition = _more_restrictive(disposition, Disposition.BLOCK)
        reasons.append(
            f"assurance level {assurance_level.value} is below managed minimum "
            f"{policy.minimum_assurance.value}"
        )
        required_actions.append("produce the missing evidence layer and rescan")
    if policy.require_provenance and not provenance_verified:
        disposition = _more_restrictive(disposition, Disposition.BLOCK)
        reasons.append("verified provenance is required")
        required_actions.append("attach a trusted Ed25519 DSSE attestation")
    if policy.require_detonation and not detonation_observed:
        disposition = _more_restrictive(disposition, Disposition.BLOCK)
        reasons.append("sandbox observation is required")
        required_actions.append("run the immutable, no-network detonation plan")
    if policy.require_rust_for_native and native_count > rust_accelerated_files:
        disposition = _more_restrictive(disposition, Disposition.BLOCK)
        reasons.append("native artifacts were not all parsed by the Rust engine")
        required_actions.append("build and configure hol-guard-scanner-engine")

    if blocking:
        reasons.insert(0, f"{len(blocking)} finding(s) meet the blocking threshold")
    elif review:
        reasons.insert(0, f"{len(review)} finding(s) require review")
    elif disposition is Disposition.WARN:
        reasons.insert(0, "non-blocking risks or limitations were detected")
    elif not reasons:
        reasons.append(
            "no policy-blocking evidence was detected; this is not a proof that the extension is safe"
        )

    return AssuranceDecision(
        disposition=disposition,
        reason="; ".join(reasons),
        blocking_fingerprints=tuple(blocking),
        review_fingerprints=tuple(review),
        required_actions=tuple(dict.fromkeys(required_actions)),
    )


def _less_severe(left: Severity, right: Severity) -> Severity:
    return left if SEVERITY_ORDER[left] <= SEVERITY_ORDER[right] else right


def _more_restrictive(left: Disposition, right: Disposition) -> Disposition:
    return left if DISPOSITION_ORDER[left] >= DISPOSITION_ORDER[right] else right


def _higher_assurance(left: AssuranceLevel, right: AssuranceLevel) -> AssuranceLevel:
    return left if ASSURANCE_ORDER[left] >= ASSURANCE_ORDER[right] else right


def _stricter_confidence(left: Confidence, right: Confidence) -> Confidence:
    order = {Confidence.UNKNOWN: 0, Confidence.LOW: 1, Confidence.MEDIUM: 2, Confidence.HIGH: 3}
    return left if order[left] >= order[right] else right


def _intersect_allowlists(left: tuple[str, ...], right: tuple[str, ...]) -> tuple[str, ...]:
    if not left:
        return right
    if not right:
        return left
    return tuple(sorted(set(left) & set(right)))


def _strict_bool(value: object, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise PolicyError(f"{field_name} must be a boolean")
    return value


def _string_tuple(value: object, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise PolicyError(f"{field_name} must be an array of non-empty strings")
    return tuple(dict.fromkeys(value))


def _positive_int(value: object, field_name: str, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyError(f"{field_name} must be an integer")
    minimum = 0 if allow_zero else 1
    if value < minimum:
        raise PolicyError(f"{field_name} must be at least {minimum}")
    return value


def _object(value: object, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{field_name} must be an object")
    return dict(value)
