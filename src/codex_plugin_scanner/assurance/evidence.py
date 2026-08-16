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


def validate_evidence_envelope(envelope: object, *, maximum_bytes: int = 32 * 1024 * 1024) -> dict[str, Any]:
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
    if not isinstance(assurance_evidence_digest, str) or not HEX64_RE.fullmatch(assurance_evidence_digest):
        raise EvidenceError("assurance_evidence_digest must be a lowercase SHA-256 digest")
    assurance = envelope.get("assurance")
    validate_assurance_payload(assurance)
    if assurance["artifact_digest"] != artifact_digest:
        raise EvidenceError("outer artifact_digest does not match assurance evidence")
    if assurance["evidence_digest"] != assurance_evidence_digest:
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
    return dict(envelope)


def validate_assurance_payload(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise EvidenceError("assurance evidence must be an object")
    required = {
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
        "evidence_digest",
    }
    missing = required - set(payload)
    if missing:
        raise EvidenceError(f"assurance evidence lacks fields: {', '.join(sorted(missing))}")
    if payload.get("schema_version") != "hol-guard.assurance-report.v1":
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
    coverage = payload.get("coverage")
    decision = payload.get("decision")
    findings = payload.get("findings")
    if not isinstance(coverage, dict) or coverage.get("state") not in {
        "complete",
        "partial",
        "incomplete",
        "error",
    }:
        raise EvidenceError("assurance coverage state is invalid")
    if not isinstance(decision, dict) or decision.get("disposition") not in {
        "allow",
        "warn",
        "review",
        "block",
        "error",
    }:
        raise EvidenceError("assurance decision disposition is invalid")
    if not isinstance(findings, list) or len(findings) > 100_000:
        raise EvidenceError("assurance findings must be a bounded array")
    for item in findings:
        if not isinstance(item, dict):
            raise EvidenceError("every assurance finding must be an object")
        fingerprint = item.get("fingerprint")
        if not isinstance(fingerprint, str) or not HEX64_RE.fullmatch(fingerprint):
            raise EvidenceError("every assurance finding requires a SHA-256 fingerprint")
    for field_name in ("layers", "capabilities", "dependencies", "native_artifacts", "archive_artifacts"):
        if not isinstance(payload.get(field_name), list):
            raise EvidenceError(f"assurance {field_name} must be an array")
    return dict(payload)


def parse_json_document(raw: bytes, *, maximum_bytes: int = 32 * 1024 * 1024) -> object:
    if len(raw) > maximum_bytes:
        raise EvidenceError("JSON document exceeds size limit")
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("document is not valid UTF-8 JSON") from exc


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
