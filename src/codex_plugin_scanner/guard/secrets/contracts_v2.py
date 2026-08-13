"""Versioned cross-surface contracts for HOL Guard Secrets.

The contracts in this module are intentionally dependency-free so the same
semantics can be used by the local CLI, hooks, IDE bridge, isolated workers,
and release evidence tooling. Serializable forms are strict and explicitly
exclude raw credential material and arbitrary source context.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Final, cast


class SecretContractError(ValueError):
    """Raised when an external Secrets contract is invalid or unsafe."""


class ParityState(str, Enum):
    UNMAPPED = "unmapped"
    DESIGNED = "designed"
    IMPLEMENTED = "implemented"
    TESTED = "tested"
    VERIFIED_ON_RELEASE_CANDIDATE = "verified_on_release_candidate"
    GENERALLY_AVAILABLE = "generally_available"


class PreventionOutcome(str, Enum):
    CLEAN = "clean"
    WARN = "warn"
    SOFT_BLOCK = "soft_block"
    POLICY_BLOCK = "policy_block"
    PARTIAL = "partial"
    DEGRADED = "degraded"
    ERROR = "error"


class SecretClass(str, Enum):
    REAL = "real"
    PLACEHOLDER_OR_EXAMPLE = "placeholder_or_example"
    WEAK_OR_AMBIGUOUS = "weak_or_ambiguous"
    UNKNOWN = "unknown"


class SecretValidity(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


class SecretExposure(str, Enum):
    LOCAL_ONLY = "local_only"
    PRIVATE_REPOSITORY = "private_repository"
    PUBLIC_REPOSITORY = "public_repository"
    PUBLIC_EXTERNAL_SURFACE = "public_external_surface"
    UNKNOWN = "unknown"


class SecretLifecycle(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    REMEDIATING = "remediating"
    AWAITING_REVERIFICATION = "awaiting_reverification"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    REOPENED = "reopened"


class SecretIgnoreScope(str, Enum):
    OCCURRENCE = "occurrence"
    SECRET_IDENTITY = "secret_identity"
    PATH_HASH = "path_hash"
    DETECTOR = "detector"
    FIXTURE = "fixture"
    REPOSITORY = "repository"
    LOCAL_WORKSPACE = "local_workspace"


class SecretIgnoreState(str, Enum):
    REQUESTED = "requested"
    APPROVED = "approved"
    DENIED = "denied"
    CHANGES_REQUESTED = "changes_requested"
    REVOKED = "revoked"
    EXPIRED = "expired"


_ACTIVE_IGNORE_STATES: Final = frozenset(
    {
        SecretIgnoreState.REQUESTED,
        SecretIgnoreState.APPROVED,
        SecretIgnoreState.CHANGES_REQUESTED,
    }
)


class SecretRuleMatcherKind(str, Enum):
    PREFIX = "prefix"
    REGEX = "regex"
    ASSIGNMENT = "assignment"
    STRUCTURED = "structured"


class SecretRuleCompileState(str, Enum):
    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    TOO_COMPLEX = "too_complex"


class SecretRolloutState(str, Enum):
    DRAFT = "draft"
    SHADOW = "shadow"
    CANARY = "canary"
    ACTIVE = "active"
    REVOKED = "revoked"


_PROHIBITED_KEY = re.compile(
    r"(?:^|_)(?:raw_?secret|candidate(?:_value)?|credential(?:_value)?|"
    r"secret_?value|token_?value|source_(?:line|content|excerpt)|prompt|"
    r"tool_(?:output|result)|environment_?value|auth(?:orization)?_?header|"
    r"provider_?response(?:_body)?|absolute_?path)(?:$|_)",
    re.IGNORECASE,
)
_DIGEST = re.compile(r"^[a-f0-9]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:@/-]{1,160}$")
_SCHEMA_COVERAGE: Final = "guard-secret-coverage.v2"
_SCHEMA_IGNORE: Final = "guard-secret-ignore-decision.v2"
_SCHEMA_RULE: Final = "guard-secret-custom-rule.v2"


def _normalized_key(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^A-Za-z0-9]+", "_", value).lower().strip("_")


def reject_prohibited_fields(value: object, *, path: str = "$") -> None:
    """Reject raw-value-shaped fields recursively before serialization."""

    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise SecretContractError(f"{path}: mapping keys must be strings")
            if _PROHIBITED_KEY.search(_normalized_key(key)):
                raise SecretContractError(f"{path}.{key}: prohibited Secrets field")
            reject_prohibited_fields(nested, path=f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, nested in enumerate(value):
            reject_prohibited_fields(nested, path=f"{path}[{index}]")


def _strict_keys(payload: Mapping[str, object], allowed: set[str], *, schema: str) -> None:
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise SecretContractError(f"{schema}: unknown fields: {', '.join(unknown)}")
    reject_prohibited_fields(payload)


def _str_tuple(value: object, *, field_name: str, allow_empty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise SecretContractError(f"{field_name}: expected an array of strings")
    result = tuple(cast(list[str], value))
    if not allow_empty and not result:
        raise SecretContractError(f"{field_name}: must not be empty")
    return result


def _non_negative_int(value: object, *, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SecretContractError(f"{field_name}: expected a non-negative integer")
    return value


def _required_text(value: object, *, field_name: str, limit: int = 200) -> str:
    if not isinstance(value, str):
        raise SecretContractError(f"{field_name}: expected text")
    normalized = value.strip()
    if not normalized or len(normalized) > limit:
        raise SecretContractError(f"{field_name}: invalid length")
    return normalized


def _optional_text(value: object, *, field_name: str, limit: int = 200) -> str | None:
    if value is None:
        return None
    return _required_text(value, field_name=field_name, limit=limit)


@dataclass(frozen=True, slots=True)
class SecretScanCoverageV2:
    source_set: tuple[str, ...]
    requested_refs: tuple[str, ...]
    completed_refs: tuple[str, ...]
    files_scanned: int
    bytes_scanned: int
    commits_visited: int
    blobs_scanned: int
    skipped_codes: tuple[str, ...]
    truncation_codes: tuple[str, ...]
    detector_version: str
    model_version: str | None = None
    cache_hits: int = 0
    cache_misses: int = 0
    partial: bool = False
    degraded: bool = False
    error_code: str | None = None

    @property
    def clean_eligible(self) -> bool:
        return (
            not self.partial
            and not self.degraded
            and self.error_code is None
            and not self.truncation_codes
            and set(self.requested_refs).issubset(self.completed_refs)
        )

    def assert_outcome(self, outcome: PreventionOutcome) -> None:
        if outcome is PreventionOutcome.CLEAN and not self.clean_eligible:
            raise SecretContractError("incomplete coverage cannot produce a clean outcome")
        if self.error_code is not None and outcome not in {
            PreventionOutcome.ERROR,
            PreventionOutcome.PARTIAL,
        }:
            raise SecretContractError("coverage with an error must be error or partial")
        if self.degraded and outcome is PreventionOutcome.CLEAN:
            raise SecretContractError("degraded coverage cannot produce a clean outcome")

    def to_public_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema": _SCHEMA_COVERAGE,
            "source_set": list(self.source_set),
            "requested_refs": list(self.requested_refs),
            "completed_refs": list(self.completed_refs),
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "commits_visited": self.commits_visited,
            "blobs_scanned": self.blobs_scanned,
            "skipped_codes": list(self.skipped_codes),
            "truncation_codes": list(self.truncation_codes),
            "detector_version": self.detector_version,
            "model_version": self.model_version,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "partial": self.partial,
            "degraded": self.degraded,
            "error_code": self.error_code,
            "clean_eligible": self.clean_eligible,
        }
        reject_prohibited_fields(payload)
        return payload

    @classmethod
    def from_mapping(cls, payload: Mapping[str, object]) -> SecretScanCoverageV2:
        allowed = {
            "schema",
            "source_set",
            "requested_refs",
            "completed_refs",
            "files_scanned",
            "bytes_scanned",
            "commits_visited",
            "blobs_scanned",
            "skipped_codes",
            "truncation_codes",
            "detector_version",
            "model_version",
            "cache_hits",
            "cache_misses",
            "partial",
            "degraded",
            "error_code",
        }
        _strict_keys(payload, allowed, schema=_SCHEMA_COVERAGE)
        if payload.get("schema") != _SCHEMA_COVERAGE:
            raise SecretContractError("unsupported SecretScanCoverage schema")
        partial = payload.get("partial", False)
        degraded = payload.get("degraded", False)
        if not isinstance(partial, bool) or not isinstance(degraded, bool):
            raise SecretContractError("coverage partial/degraded flags must be boolean")
        instance = cls(
            source_set=_str_tuple(
                payload.get("source_set"),
                field_name="source_set",
                allow_empty=False,
            ),
            requested_refs=_str_tuple(
                payload.get("requested_refs"),
                field_name="requested_refs",
            ),
            completed_refs=_str_tuple(
                payload.get("completed_refs"),
                field_name="completed_refs",
            ),
            files_scanned=_non_negative_int(
                payload.get("files_scanned"),
                field_name="files_scanned",
            ),
            bytes_scanned=_non_negative_int(
                payload.get("bytes_scanned"),
                field_name="bytes_scanned",
            ),
            commits_visited=_non_negative_int(
                payload.get("commits_visited"),
                field_name="commits_visited",
            ),
            blobs_scanned=_non_negative_int(
                payload.get("blobs_scanned"),
                field_name="blobs_scanned",
            ),
            skipped_codes=_str_tuple(
                payload.get("skipped_codes"),
                field_name="skipped_codes",
            ),
            truncation_codes=_str_tuple(
                payload.get("truncation_codes"),
                field_name="truncation_codes",
            ),
            detector_version=_required_text(
                payload.get("detector_version"),
                field_name="detector_version",
            ),
            model_version=_optional_text(
                payload.get("model_version"),
                field_name="model_version",
            ),
            cache_hits=_non_negative_int(
                payload.get("cache_hits", 0),
                field_name="cache_hits",
            ),
            cache_misses=_non_negative_int(
                payload.get("cache_misses", 0),
                field_name="cache_misses",
            ),
            partial=partial,
            degraded=degraded,
            error_code=_optional_text(
                payload.get("error_code"),
                field_name="error_code",
            ),
        )
        if instance.truncation_codes and not instance.partial:
            raise SecretContractError("truncation requires partial=true")
        if set(instance.completed_refs) - set(instance.requested_refs):
            raise SecretContractError("completed_refs must be a subset of requested_refs")
        return instance


@dataclass(frozen=True, slots=True)
class SecretIgnoreDecisionV2:
    decision_id: str
    state: SecretIgnoreState
    requested_scope: SecretIgnoreScope
    durable_match_key: str
    reason: str
    expires_at: datetime | None
    detector_version: str
    model_version: str | None
    requester_id: str
    approver_id: str | None
    policy_source: str
    propagation: tuple[str, ...]
    permanent_fixture_justification: str | None = None

    def __post_init__(self) -> None:
        for field_name, value in {
            "decision_id": self.decision_id,
            "requester_id": self.requester_id,
            "policy_source": self.policy_source,
        }.items():
            if not _IDENTIFIER.fullmatch(value):
                raise SecretContractError(f"{field_name}: invalid identifier")
        if not _DIGEST.fullmatch(self.durable_match_key):
            raise SecretContractError("durable_match_key must be an opaque SHA-256 digest")
        if len(self.reason.strip()) < 3 or len(self.reason) > 500:
            raise SecretContractError("ignore reason must be between 3 and 500 characters")
        if self.expires_at is None and not self.permanent_fixture_justification:
            raise SecretContractError("non-expiring decisions require permanent fixture justification")
        if self.expires_at is not None:
            if self.expires_at.tzinfo is None:
                raise SecretContractError("expires_at must be timezone-aware")
            if (
                self.state in _ACTIVE_IGNORE_STATES
                and self.expires_at.astimezone(timezone.utc)
                <= datetime.now(timezone.utc)
            ):
                raise SecretContractError("expires_at must be in the future")
        if self.state is SecretIgnoreState.APPROVED and not self.approver_id:
            raise SecretContractError("approved ignore decisions require an approver")
        if len(set(self.propagation)) != len(self.propagation):
            raise SecretContractError("propagation surfaces must be unique")

    def to_public_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema": _SCHEMA_IGNORE,
            "decision_id": self.decision_id,
            "state": self.state.value,
            "requested_scope": self.requested_scope.value,
            "durable_match_key": self.durable_match_key,
            "reason": self.reason,
            "expires_at": (
                self.expires_at.astimezone(timezone.utc).isoformat()
                if self.expires_at
                else None
            ),
            "detector_version": self.detector_version,
            "model_version": self.model_version,
            "requester_id": self.requester_id,
            "approver_id": self.approver_id,
            "policy_source": self.policy_source,
            "propagation": list(self.propagation),
            "permanent_fixture_justification": self.permanent_fixture_justification,
        }
        reject_prohibited_fields(payload)
        return payload


@dataclass(frozen=True, slots=True)
class SecretCustomRuleV2:
    rule_id: str
    version: str
    matcher_kind: SecretRuleMatcherKind
    matcher_digest: str
    safe_fixture_digest: str
    provenance_digest: str
    compile_state: SecretRuleCompileState
    complexity_budget: int
    rollout_state: SecretRolloutState
    surfaces: tuple[str, ...]

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.rule_id):
            raise SecretContractError("rule_id is invalid")
        if not _IDENTIFIER.fullmatch(self.version):
            raise SecretContractError("version is invalid")
        for field_name, digest in {
            "matcher_digest": self.matcher_digest,
            "safe_fixture_digest": self.safe_fixture_digest,
            "provenance_digest": self.provenance_digest,
        }.items():
            if not _DIGEST.fullmatch(digest):
                raise SecretContractError(f"{field_name} must be SHA-256")
        if not 1 <= self.complexity_budget <= 100_000:
            raise SecretContractError("complexity_budget is outside the supported bound")
        if not self.surfaces or len(set(self.surfaces)) != len(self.surfaces):
            raise SecretContractError("rule surfaces must be non-empty and unique")
        if (
            self.rollout_state
            in {
                SecretRolloutState.CANARY,
                SecretRolloutState.ACTIVE,
            }
            and self.compile_state is not SecretRuleCompileState.VALID
        ):
            raise SecretContractError("only valid compiled rules may be canary or active")

    def to_public_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema": _SCHEMA_RULE,
            "rule_id": self.rule_id,
            "version": self.version,
            "matcher_kind": self.matcher_kind.value,
            "matcher_digest": self.matcher_digest,
            "safe_fixture_digest": self.safe_fixture_digest,
            "provenance_digest": self.provenance_digest,
            "compile_state": self.compile_state.value,
            "complexity_budget": self.complexity_budget,
            "rollout_state": self.rollout_state.value,
            "surfaces": list(self.surfaces),
        }
        reject_prohibited_fields(payload)
        return payload


@dataclass(frozen=True, slots=True)
class CapabilityEvidenceV2:
    capability_id: str
    product_boundary: str
    surfaces: tuple[str, ...]
    plans: tuple[str, ...]
    state: ParityState
    acceptance_tests: tuple[str, ...]
    evidence_artifacts: tuple[str, ...]
    release_commit: str | None = None

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.capability_id):
            raise SecretContractError("capability_id is invalid")
        if not self.surfaces or not self.plans:
            raise SecretContractError("capability surfaces and plans must be non-empty")
        if (
            self.state
            in {
                ParityState.TESTED,
                ParityState.VERIFIED_ON_RELEASE_CANDIDATE,
                ParityState.GENERALLY_AVAILABLE,
            }
            and not self.acceptance_tests
        ):
            raise SecretContractError("tested capability requires acceptance tests")
        if self.state in {
            ParityState.VERIFIED_ON_RELEASE_CANDIDATE,
            ParityState.GENERALLY_AVAILABLE,
        }:
            if not self.release_commit or not re.fullmatch(r"[a-f0-9]{40}", self.release_commit):
                raise SecretContractError("release-candidate capability requires an exact commit SHA")
            if not self.evidence_artifacts:
                raise SecretContractError("release-candidate capability requires evidence artifacts")


@dataclass(frozen=True, slots=True)
class OrganizationMetricDefinitionV2:
    metric_id: str
    numerator: str
    denominator: str
    censored_open_handling: str
    recurrence_handling: str
    incomplete_scan_handling: str

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.metric_id):
            raise SecretContractError("metric_id is invalid")
        for value in (
            self.numerator,
            self.denominator,
            self.censored_open_handling,
            self.recurrence_handling,
            self.incomplete_scan_handling,
        ):
            if not value.strip():
                raise SecretContractError("metric definition fields must not be empty")


OUTCOME_SURFACE_MAPPING: Final[dict[PreventionOutcome, dict[str, str]]] = {
    PreventionOutcome.CLEAN: {
        "cli": "0",
        "check": "success",
        "ide": "none",
        "agent": "allow",
    },
    PreventionOutcome.WARN: {
        "cli": "0",
        "check": "neutral",
        "ide": "warning",
        "agent": "notice",
    },
    PreventionOutcome.SOFT_BLOCK: {
        "cli": "3",
        "check": "failure",
        "ide": "error",
        "agent": "pause",
    },
    PreventionOutcome.POLICY_BLOCK: {
        "cli": "4",
        "check": "failure",
        "ide": "error",
        "agent": "deny",
    },
    PreventionOutcome.PARTIAL: {
        "cli": "2",
        "check": "neutral",
        "ide": "degraded",
        "agent": "pause",
    },
    PreventionOutcome.DEGRADED: {
        "cli": "2",
        "check": "neutral",
        "ide": "degraded",
        "agent": "pause",
    },
    PreventionOutcome.ERROR: {
        "cli": "2",
        "check": "failure",
        "ide": "error",
        "agent": "pause",
    },
}


REASON_CODES_V2: Final[frozenset[str]] = frozenset(
    {
        "archive_budget_exceeded",
        "binary_skipped",
        "cache_stale",
        "cleanup_failed",
        "detector_bundle_invalid",
        "detector_unavailable",
        "encoding_unsupported",
        "file_changed_during_scan",
        "git_object_missing",
        "history_shallow",
        "lfs_object_missing",
        "max_bytes",
        "max_commits",
        "max_files",
        "max_findings",
        "model_bundle_invalid",
        "model_degraded",
        "policy_block",
        "policy_refresh_required",
        "source_unreadable",
        "validation_error",
        "validation_rate_limited",
        "validation_unknown",
        "validation_unsupported",
        "worker_cancelled",
        "worker_timeout",
    }
)


def validate_capability_manifest(
    capabilities: Sequence[CapabilityEvidenceV2],
    *,
    required_capability_ids: frozenset[str],
    exact_release_commit: str,
) -> None:
    """Fail unless every claimed parity row is release-candidate verified."""

    if not re.fullmatch(r"[a-f0-9]{40}", exact_release_commit):
        raise SecretContractError("exact_release_commit must be a full commit SHA")
    by_id = {capability.capability_id: capability for capability in capabilities}
    if len(by_id) != len(capabilities):
        raise SecretContractError("capability IDs must be unique")
    missing = sorted(required_capability_ids - set(by_id))
    if missing:
        raise SecretContractError(f"required capabilities are unmapped: {', '.join(missing)}")
    for capability_id in sorted(required_capability_ids):
        capability = by_id[capability_id]
        if capability.state not in {
            ParityState.VERIFIED_ON_RELEASE_CANDIDATE,
            ParityState.GENERALLY_AVAILABLE,
        }:
            raise SecretContractError(f"{capability_id}: not verified on a release candidate")
        if capability.release_commit != exact_release_commit:
            raise SecretContractError(f"{capability_id}: evidence is bound to a different commit")
