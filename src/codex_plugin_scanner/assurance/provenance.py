"""Ed25519 DSSE provenance bound to exact extension and evidence digests."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import canonical_json_bytes

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
except ImportError:  # pragma: no cover - exercised in dependency-missing environments
    InvalidSignature = Exception  # type: ignore[assignment,misc]
    Ed25519PrivateKey = None  # type: ignore[assignment,misc]
    Ed25519PublicKey = None  # type: ignore[assignment,misc]
    serialization = None  # type: ignore[assignment]


PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://hol.org/guard/extension-assurance/v1"


class ProvenanceError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class VerificationResult:
    verified: bool
    key_id: str | None
    reason: str
    statement: dict[str, Any] | None = None


def generate_keypair(private_path: Path, public_path: Path) -> str:
    _require_crypto()
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)
    try:
        private_path.chmod(0o600)
        public_path.chmod(0o644)
    except OSError:
        pass
    return key_id_for_public_key(public_key)


def build_statement(
    *,
    artifact_digest: str,
    evidence_digest: str,
    scanner_version: str,
    decision: str,
    coverage_state: str,
    assurance_level: str,
) -> dict[str, Any]:
    _validate_sha256(artifact_digest, "artifact_digest")
    _validate_sha256(evidence_digest, "evidence_digest")
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": "extension", "digest": {"sha256": artifact_digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "evidenceDigest": {"sha256": evidence_digest},
            "scannerVersion": scanner_version,
            "decision": decision,
            "coverageState": coverage_state,
            "assuranceLevel": assurance_level,
            "issuedAt": datetime.now(timezone.utc).isoformat(),
        },
    }


def sign_statement(statement: dict[str, Any], private_key_path: Path) -> dict[str, Any]:
    _require_crypto()
    private_key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ProvenanceError("private key must be Ed25519")
    public_key = private_key.public_key()
    key_id = key_id_for_public_key(public_key)
    payload = canonical_json_bytes(statement)
    signature = private_key.sign(dsse_pae(PAYLOAD_TYPE, payload))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": key_id, "sig": base64.b64encode(signature).decode("ascii")}],
    }


def verify_envelope(
    envelope: object,
    public_key_paths: tuple[Path, ...],
    *,
    expected_artifact_digest: str | None = None,
    expected_evidence_digest: str | None = None,
) -> VerificationResult:
    _require_crypto()
    try:
        payload_type, payload, signatures = _parse_envelope(envelope)
    except ProvenanceError as exc:
        return VerificationResult(False, None, str(exc))
    if payload_type != PAYLOAD_TYPE:
        return VerificationResult(False, None, "unexpected DSSE payload type")
    try:
        statement = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return VerificationResult(False, None, "DSSE payload is not valid JSON")
    try:
        _validate_statement(
            statement,
            expected_artifact_digest=expected_artifact_digest,
            expected_evidence_digest=expected_evidence_digest,
        )
    except ProvenanceError as exc:
        return VerificationResult(False, None, str(exc))

    keys: dict[str, Any] = {}
    for path in public_key_paths:
        try:
            key = serialization.load_pem_public_key(path.read_bytes())
        except (OSError, ValueError):
            continue
        if isinstance(key, Ed25519PublicKey):
            keys[key_id_for_public_key(key)] = key
    if not keys:
        return VerificationResult(False, None, "no valid trusted Ed25519 public keys were loaded")

    pae = dsse_pae(payload_type, payload)
    for signature_record in signatures:
        key_id = signature_record.get("keyid")
        encoded_signature = signature_record.get("sig")
        if not isinstance(key_id, str) or not isinstance(encoded_signature, str):
            continue
        key = keys.get(key_id)
        if key is None:
            continue
        try:
            signature = base64.b64decode(encoded_signature, validate=True)
            key.verify(signature, pae)
        except (ValueError, InvalidSignature):
            continue
        return VerificationResult(True, key_id, "signature and digest bindings verified", statement)
    return VerificationResult(False, None, "no trusted signature verified")


def key_id_for_public_key(public_key: Any) -> str:
    _require_crypto()
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 %d %b %d %b" % (len(type_bytes), type_bytes, len(payload), payload)


def _parse_envelope(envelope: object) -> tuple[str, bytes, list[dict[str, Any]]]:
    if not isinstance(envelope, dict):
        raise ProvenanceError("DSSE envelope must be an object")
    allowed = {"payloadType", "payload", "signatures"}
    unknown = set(envelope) - allowed
    if unknown:
        raise ProvenanceError(f"unknown DSSE envelope fields: {', '.join(sorted(unknown))}")
    payload_type = envelope.get("payloadType")
    encoded_payload = envelope.get("payload")
    signatures = envelope.get("signatures")
    if not isinstance(payload_type, str) or not isinstance(encoded_payload, str):
        raise ProvenanceError("DSSE payloadType and payload must be strings")
    if not isinstance(signatures, list) or not signatures or len(signatures) > 32:
        raise ProvenanceError("DSSE signatures must be a non-empty bounded array")
    if any(not isinstance(item, dict) for item in signatures):
        raise ProvenanceError("each DSSE signature must be an object")
    try:
        payload = base64.b64decode(encoded_payload, validate=True)
    except ValueError as exc:
        raise ProvenanceError("DSSE payload is not valid base64") from exc
    if len(payload) > 16 * 1024 * 1024:
        raise ProvenanceError("DSSE payload exceeds size limit")
    return payload_type, payload, signatures


def _validate_statement(
    statement: object,
    *,
    expected_artifact_digest: str | None,
    expected_evidence_digest: str | None,
) -> None:
    if not isinstance(statement, dict):
        raise ProvenanceError("in-toto statement must be an object")
    if statement.get("_type") != STATEMENT_TYPE or statement.get("predicateType") != PREDICATE_TYPE:
        raise ProvenanceError("unexpected in-toto statement type")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1 or not isinstance(subjects[0], dict):
        raise ProvenanceError("statement must contain exactly one subject")
    digest = subjects[0].get("digest")
    artifact_digest = digest.get("sha256") if isinstance(digest, dict) else None
    if not isinstance(artifact_digest, str):
        raise ProvenanceError("statement subject lacks a sha256 digest")
    _validate_sha256(artifact_digest, "statement artifact digest")
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        raise ProvenanceError("statement predicate must be an object")
    evidence_digest_record = predicate.get("evidenceDigest")
    evidence_digest = (
        evidence_digest_record.get("sha256") if isinstance(evidence_digest_record, dict) else None
    )
    if not isinstance(evidence_digest, str):
        raise ProvenanceError("statement predicate lacks an evidence digest")
    _validate_sha256(evidence_digest, "statement evidence digest")
    if expected_artifact_digest is not None and artifact_digest != expected_artifact_digest:
        raise ProvenanceError("statement artifact digest does not match the scanned artifact")
    if expected_evidence_digest is not None and evidence_digest != expected_evidence_digest:
        raise ProvenanceError("statement evidence digest does not match the evidence envelope")


def _validate_sha256(value: str, field_name: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value.lower()):
        raise ProvenanceError(f"{field_name} must be a complete SHA-256 digest")


def _require_crypto() -> None:
    if Ed25519PrivateKey is None or serialization is None:
        raise ProvenanceError("the cryptography package with Ed25519 support is required")
