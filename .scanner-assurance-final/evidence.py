# pyright: basic
"""Strict evidence envelope construction and verification."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from .models import canonical_json_bytes


EVIDENCE_SCHEMA = "hol-guard.extension-security-evidence.v1"
ASSURANCE_SCHEMA = "hol-guard.assurance-report.v1"
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class EvidenceError(ValueError):
    pass


def build_evidence_envelope(
    assurance_payload: dict[str, Any],
    *,
    tenant_id: str,
    subject_id: str,
    sequence: int = 1,
    evidence_id: str | None = None,
    provenance_envelope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _validate_identifier(tenant_id, "tenant_id")
    _validate_identifier(subject_id, "subject_id")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
        raise EvidenceError("sequence must be a positive integer")
    validate_assurance_payload(assurance_payload)
    identifier = evidence_id or str(uuid.uuid4())
    try:
        uuid.UUID(identifier)
    except ValueError as exc:
        raise EvidenceError("evidence_id must be a UUID") from exc
    if provenance_envelope is not None and not isinstance(provenance_envelope, dict):
        raise EvidenceError("provenance must be a DSSE envelope object or null")
    payload: dict[str, Any] = {
        "schema_version": EVIDENCE_SCHEMA,
        "evidence_id": identifier,
        "tenant_id": tenant_id,
        "subject_id": subject_id,
        "sequence": sequence,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "artifact_digest": assurance_payload["artifact_digest"],
        "assurance_evidence_digest": assurance_payload["evidence_digest"],
        "assurance": assurance_payload,
        "provenance": provenance_envelope,
    }
    payload["evidence_digest"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return payload


def validate_evidence_envelope(
    envelope: object,
    *,
    maximum_bytes: int = 32 * 1024 * 1024,
) -> dict[str, Any]:
    if not isinstance(envelope, dict):
        raise EvidenceError("evidence envelope must be an object")
    serialized = canonical_json_bytes(envelope)
    if len(serialized) > maximum_bytes:
        raise EvidenceError("evidence envelope exceeds size limit")
    allowed = {
        "schema_version",
        "evidence_id",
        "tenant_id",
        "subject_id",
        "sequence",
        "created_at",
        "artifact_digest",
        "assurance_evidence_digest",
        "assurance",
        "provenance",
        "evidence_digest",
    }
    unknown = set(envelope) - allowed
    if unknown:
        raise EvidenceError(f"unknown evidence fields: {', '.join(sorted(unknown))}")
    if envelope.get("schema_version") != EVIDENCE_SCHEMA:
        raise EvidenceError("unsupported evidence schema_version")
    evidence_id = envelope.get("evidence_id")
    if not isinstance(evidence_id, str):
        raise EvidenceError("evidence_id must be a string")
    try:
        uuid.UUID(evidence_id)
    except ValueError as exc:
        raise EvidenceError("evidence_id must be a UUID") from exc
    tenant_id = envelope.get("tenant_id")
    subject_id = envelope.get("subject_id")
    if not isinstance(tenant_id, str) or not isinstance(subject_id, str):
        raise EvidenceError("tenant_id and subject_id must be strings")
    _validate_identifier(tenant_id, "tenant_id")
    _validate_identifier(subject_id, "subject_id")
    sequence = envelope.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
        raise EvidenceError("sequence must be a positive integer")
    created_at = envelope.get("created_at")
    if not isinstance(created_at, str):
        raise EvidenceError("created_at must be an RFC3339 string")
    _parse_timestamp(created_at)
    artifact_digest = envelope.get("artifact_digest")
    assurance_evidence_digest = envelope.get("assurance_evidence_digest")
    if not isinstance(artifact_digest, str) or not HEX64_RE.fullmatch(artifact_digest):
        raise EvidenceError("artifact_digest must be a lowercase SHA-256 digest")
    if not isinstance(assurance_evidence_digest, str) or not HEX64_RE.fullmatch(
        assurance_evidence_digest
    ):
        raise EvidenceError("assurance_evidence_digest must be a lowercase SHA-256 digest")
    assurance = envelope.get("assurance")
    validated_assurance = validate_assurance_payload(assurance)
    if validated_assurance["artifact_digest"] != artifact_digest:
        raise EvidenceError("outer artifact_digest does not match assurance evidence")
    if validated_assurance["evidence_digest"] != assurance_evidence_digest:
        raise EvidenceError("outer assurance_evidence_digest does not match assurance evidence")
    expected = envelope.get("evidence_digest")
    if not isinstance(expected, str) or not HEX64_RE.fullmatch(expected):
        raise EvidenceError("evidence_digest must be a lowercase SHA-256 digest")
    unsigned = dict(envelope)
    unsigned.pop("evidence_digest", None)
    actual = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    if actual != expected:
        raise EvidenceError("evidence digest mismatch")
    provenance = envelope.get("provenance")
    if provenance is not None and not isinstance(provenance, dict):
        raise EvidenceError("provenance must be a DSSE envelope object or null")
    _validate_json_depth(envelope, depth=0)
    return dict(envelope)


def validate_assurance_payload(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise EvidenceError("assurance evidence must be an object")
    allowed = {
        "schema_version",
        "scanner_version",
        "artifact_root",
        "artifact_digest",
        "generated_at",
        "assurance_level",
        "coverage",
        "findings",
        "decision",
        "layers",
        "capabilities",
        "dependencies",
        "native_artifacts",
        "archive_artifacts",
        "policy",
        "drift",
        "provenance",
        "detonation",
        "evidence_digest",
    }
    unknown = set(payload) - allowed
    if unknown:
        raise EvidenceError(f"unknown assurance fields: {', '.join(sorted(unknown))}")
    required = set(allowed)
    missing = required - set(payload)
    if missing:
        raise EvidenceError(f"assurance evidence lacks fields: {', '.join(sorted(missing))}")
    if payload.get("schema_version") != ASSURANCE_SCHEMA:
        raise EvidenceError("unsupported assurance report schema")
    artifact_digest = payload.get("artifact_digest")
    evidence_digest = payload.get("evidence_digest")
    if not isinstance(artifact_digest, str) or not HEX64_RE.fullmatch(artifact_digest):
        raise EvidenceError("assurance artifact_digest is invalid")
    if not isinstance(evidence_digest, str) or not HEX64_RE.fullmatch(evidence_digest):
        raise EvidenceError("assurance evidence_digest is invalid")
    unsigned = dict(payload)
    unsigned.pop("evidence_digest", None)
    actual = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    if actual != evidence_digest:
        raise EvidenceError("assurance evidence digest mismatch")
    generated_at = payload.get("generated_at")
    if not isinstance(generated_at, str):
        raise EvidenceError("assurance generated_at is invalid")
    _parse_timestamp(generated_at)
    if not isinstance(payload.get("scanner_version"), str) or not payload["scanner_version"]:
        raise EvidenceError("assurance scanner_version is invalid")
    if not isinstance(payload.get("artifact_root"), str) or not payload["artifact_root"]:
        raise EvidenceError("assurance artifact_root is invalid")
    if payload.get("assurance_level") not in {
        "static",
        "provenance-verified",
        "sandbox-planned",
        "sandbox-observed",
    }:
        raise EvidenceError("assurance level is invalid")

    coverage = payload.get("coverage")
    decision = payload.get("decision")
    findings = payload.get("findings")
    if not isinstance(coverage, dict):
        raise EvidenceError("assurance coverage must be an object")
    _validate_coverage(coverage)
    if not isinstance(decision, dict):
        raise EvidenceError("assurance decision must be an object")
    _validate_decision(decision)
    if not isinstance(findings, list) or len(findings) > 100_000:
        raise EvidenceError("assurance findings must be a bounded array")
    seen_fingerprints: set[str] = set()
    for item in findings:
        _validate_finding(item)
        fingerprint = item["fingerprint"]
        if fingerprint in seen_fingerprints:
            raise EvidenceError("assurance finding fingerprints must be unique")
        seen_fingerprints.add(fingerprint)
    for field_name in (
        "layers",
        "capabilities",
        "dependencies",
        "native_artifacts",
        "archive_artifacts",
    ):
        if not isinstance(payload.get(field_name), list):
            raise EvidenceError(f"assurance {field_name} must be an array")
    capabilities = payload["capabilities"]
    if any(not isinstance(item, str) or not item for item in capabilities):
        raise EvidenceError("assurance capabilities must be non-empty strings")
    if len(set(capabilities)) != len(capabilities):
        raise EvidenceError("assurance capabilities must be unique")
    if not isinstance(payload.get("policy"), dict):
        raise EvidenceError("assurance policy must be an object")
    for optional in ("drift", "provenance", "detonation"):
        if payload[optional] is not None and not isinstance(payload[optional], dict):
            raise EvidenceError(f"assurance {optional} must be an object or null")
    _validate_json_depth(payload, depth=0)
    return dict(payload)


def parse_json_document(raw: bytes, *, maximum_bytes: int = 32 * 1024 * 1024) -> object:
    if len(raw) > maximum_bytes:
        raise EvidenceError("JSON document exceeds size limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("document is not valid UTF-8 JSON") from exc
    _validate_json_depth(value, depth=0)
    return value


def _validate_coverage(coverage: dict[str, Any]) -> None:
    allowed = {
        "state",
        "inventory_files",
        "analyzed_files",
        "analyzed_bytes",
        "opaque_files",
        "unreadable_files",
        "oversized_files",
        "archive_members",
        "native_artifacts",
        "rust_accelerated_files",
        "gaps",
        "limitations",
    }
    if set(coverage) - allowed or allowed - set(coverage):
        raise EvidenceError("assurance coverage fields are incomplete or unknown")
    if coverage.get("state") not in {"complete", "partial", "incomplete", "error"}:
        raise EvidenceError("assurance coverage state is invalid")
    for field_name in (
        "inventory_files",
        "analyzed_files",
        "analyzed_bytes",
        "opaque_files",
        "unreadable_files",
        "oversized_files",
        "archive_members",
        "native_artifacts",
        "rust_accelerated_files",
    ):
        value = coverage.get(field_name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise EvidenceError(f"assurance coverage {field_name} is invalid")
    if not isinstance(coverage.get("gaps"), list) or not isinstance(
        coverage.get("limitations"), list
    ):
        raise EvidenceError("assurance coverage gaps and limitations must be arrays")


def _validate_decision(decision: dict[str, Any]) -> None:
    allowed = {
        "disposition",
        "reason",
        "blocking_fingerprints",
        "review_fingerprints",
        "required_actions",
    }
    if set(decision) - allowed or allowed - set(decision):
        raise EvidenceError("assurance decision fields are incomplete or unknown")
    if decision.get("disposition") not in {"allow", "warn", "review", "block", "error"}:
        raise EvidenceError("assurance decision disposition is invalid")
    if not isinstance(decision.get("reason"), str) or not decision["reason"]:
        raise EvidenceError("assurance decision reason is invalid")
    for field_name in ("blocking_fingerprints", "review_fingerprints"):
        values = decision.get(field_name)
        if not isinstance(values, list) or any(
            not isinstance(item, str) or not HEX64_RE.fullmatch(item) for item in values
        ):
            raise EvidenceError(f"assurance decision {field_name} is invalid")
    required_actions = decision.get("required_actions")
    if not isinstance(required_actions, list) or any(
        not isinstance(item, str) for item in required_actions
    ):
        raise EvidenceError("assurance decision required_actions is invalid")


def _validate_finding(item: object) -> None:
    if not isinstance(item, dict):
        raise EvidenceError("every assurance finding must be an object")
    allowed = {
        "rule_id",
        "severity",
        "confidence",
        "category",
        "title",
        "description",
        "remediation",
        "locations",
        "source",
        "fingerprint",
        "metadata",
    }
    if set(item) - allowed or allowed - set(item):
        raise EvidenceError("assurance finding fields are incomplete or unknown")
    fingerprint = item.get("fingerprint")
    if not isinstance(fingerprint, str) or not HEX64_RE.fullmatch(fingerprint):
        raise EvidenceError("every assurance finding requires a SHA-256 fingerprint")
    if item.get("severity") not in {"critical", "high", "medium", "low", "info"}:
        raise EvidenceError("assurance finding severity is invalid")
    if item.get("confidence") not in {"high", "medium", "low", "unknown"}:
        raise EvidenceError("assurance finding confidence is invalid")
    for field_name in ("rule_id", "category", "title", "description", "remediation", "source"):
        if not isinstance(item.get(field_name), str) or not item[field_name]:
            raise EvidenceError(f"assurance finding {field_name} is invalid")
    if not isinstance(item.get("locations"), list) or not isinstance(item.get("metadata"), dict):
        raise EvidenceError("assurance finding locations or metadata is invalid")


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise EvidenceError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _validate_json_depth(value: object, *, depth: int) -> None:
    if depth > 64:
        raise EvidenceError("JSON document exceeds nesting limit")
    if isinstance(value, dict):
        for item in value.values():
            _validate_json_depth(item, depth=depth + 1)
    elif isinstance(value, list):
        for item in value:
            _validate_json_depth(item, depth=depth + 1)


def _validate_identifier(value: str, field_name: str) -> None:
    if not IDENTIFIER_RE.fullmatch(value):
        raise EvidenceError(f"{field_name} contains unsupported characters or length")


def _parse_timestamp(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise EvidenceError("timestamp is not valid RFC3339") from exc
    if parsed.tzinfo is None:
        raise EvidenceError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)
