"""Layered extension-security evidence, attestation, and secure upload helpers."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EVIDENCE_SCHEMA = "extension-security-evidence.v2"
ATTESTATION_SCHEMA = "extension-security-attestation.v1"
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
MAX_RESPONSE_BYTES = 256 * 1024
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SECRET_KEY_RE = re.compile(r"(?:secret|token|password|credential|authorization|api[_-]?key)", re.I)
_SECRET_VALUE_RE = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)


class EvidenceError(ValueError):
    """Raised when evidence is malformed or violates a security invariant."""


@dataclass(frozen=True, slots=True)
class AttestationVerification:
    status: str
    key_id: str | None
    reason: str


@dataclass(frozen=True, slots=True)
class UploadReceipt:
    status_code: int
    evidence_digest: str
    response: dict[str, Any]


def canonical_json_bytes(payload: object) -> bytes:
    """Return deterministic UTF-8 JSON bytes for hashing and signing."""

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def evidence_digest(payload: object) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _redact(value: object, *, key: str | None = None, depth: int = 0) -> object:
    if depth > 20:
        return "[truncated]"
    if key and _SECRET_KEY_RE.search(key):
        return "[redacted]"
    if isinstance(value, str):
        if _SECRET_VALUE_RE.search(value):
            return "[redacted]"
        return value[:4096]
    if isinstance(value, dict):
        return {str(item_key)[:128]: _redact(item_value, key=str(item_key), depth=depth + 1) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_redact(item, depth=depth + 1) for item in value[:10_000]]
    if isinstance(value, tuple):
        return [_redact(item, depth=depth + 1) for item in value[:10_000]]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:4096]


def build_evidence_envelope(
    *,
    target_digest: str,
    scanner_version: str,
    layers: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    policy: dict[str, Any] | None = None,
    subject: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a privacy-safe, deterministic layered evidence envelope."""

    normalized_digest = target_digest.lower()
    if not _SHA256_RE.fullmatch(normalized_digest):
        raise EvidenceError("target_digest must be a lowercase SHA-256 value")
    if not scanner_version or len(scanner_version) > 128:
        raise EvidenceError("scanner_version is required and bounded")
    normalized_layers: list[dict[str, Any]] = []
    seen_layers: set[str] = set()
    for layer in layers:
        if not isinstance(layer, dict):
            raise EvidenceError("each evidence layer must be an object")
        layer_id = str(layer.get("id", "")).strip()
        status = str(layer.get("status", "")).strip()
        if not layer_id or len(layer_id) > 80 or layer_id in seen_layers:
            raise EvidenceError("layer identifiers must be unique and bounded")
        if status not in {"verified", "complete", "partial", "not-run", "unavailable", "failed", "unknown"}:
            raise EvidenceError(f"unsupported layer status: {status}")
        seen_layers.add(layer_id)
        normalized_layers.append(
            {
                "id": layer_id,
                "status": status,
                "analyzer": str(layer.get("analyzer", "unknown"))[:128],
                "coverage": max(0.0, min(100.0, float(layer.get("coverage", 0.0)))),
                "claims": _redact(layer.get("claims", {})),
                "limitations": [str(item)[:500] for item in list(layer.get("limitations", []))[:100]],
                "evidenceDigest": str(layer.get("evidenceDigest", ""))[:64] or None,
            }
        )
    normalized_layers.sort(key=lambda item: item["id"])

    normalized_findings: list[dict[str, Any]] = []
    for finding in findings[:10_000]:
        if not isinstance(finding, dict):
            continue
        normalized_findings.append(
            {
                "ruleId": str(finding.get("ruleId", "UNKNOWN"))[:160],
                "severity": str(finding.get("severity", "info"))[:16],
                "category": str(finding.get("category", "assurance"))[:80],
                "filePath": str(finding.get("filePath", ""))[:2048] or None,
                "lineNumber": int(finding["lineNumber"]) if finding.get("lineNumber") else None,
                "fingerprint": str(finding.get("fingerprint", ""))[:128] or None,
                "source": str(finding.get("source", "native"))[:80],
            }
        )
    normalized_findings.sort(
        key=lambda item: (
            item["severity"],
            item["ruleId"],
            item["filePath"] or "",
            item["lineNumber"] or 0,
        )
    )

    envelope: dict[str, Any] = {
        "schemaVersion": EVIDENCE_SCHEMA,
        "generatedAt": generated_at or datetime.now(timezone.utc).isoformat(),
        "scanner": {"name": "HOL Guard AI Plugin Scanner", "version": scanner_version},
        "target": {"digest": {"algorithm": "sha256", "value": normalized_digest}},
        "layers": normalized_layers,
        "findings": normalized_findings,
        "policy": _redact(policy or {}),
    }
    if subject:
        envelope["subject"] = _redact(subject)
    digest = evidence_digest(envelope)
    envelope["evidenceDigest"] = {"algorithm": "sha256", "value": digest}
    encoded = canonical_json_bytes(envelope)
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise EvidenceError("evidence envelope exceeds the maximum encoded size")
    return envelope


def validate_evidence_envelope(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise EvidenceError("evidence must be a JSON object")
    if payload.get("schemaVersion") != EVIDENCE_SCHEMA:
        raise EvidenceError("evidence schema version mismatch")
    target = payload.get("target")
    digest = target.get("digest") if isinstance(target, dict) else None
    digest_value = digest.get("value") if isinstance(digest, dict) else None
    if not isinstance(digest_value, str) or not _SHA256_RE.fullmatch(digest_value):
        raise EvidenceError("evidence target digest is invalid")
    layers = payload.get("layers")
    if not isinstance(layers, list) or not layers:
        raise EvidenceError("evidence must contain at least one layer")
    expected = payload.get("evidenceDigest")
    expected_value = expected.get("value") if isinstance(expected, dict) else None
    unsigned = dict(payload)
    unsigned.pop("evidenceDigest", None)
    actual = evidence_digest(unsigned)
    if expected_value != actual:
        raise EvidenceError("evidence digest does not match the canonical payload")
    if len(canonical_json_bytes(payload)) > MAX_EVIDENCE_BYTES:
        raise EvidenceError("evidence envelope exceeds the maximum encoded size")
    return payload


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """Build DSSE pre-authentication encoding."""

    type_bytes = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(type_bytes)).encode() + b" " + type_bytes + b" " + str(len(payload)).encode() + b" " + payload


def _load_trusted_keys(path: Path | None) -> dict[str, bytes]:
    if path is None:
        configured = os.environ.get("HOL_GUARD_SCANNER_TRUSTED_KEYS")
        path = Path(configured).expanduser() if configured else None
    if path is None:
        return {}
    resolved = path.resolve()
    if not resolved.is_file() or resolved.stat().st_size > 256 * 1024:
        raise EvidenceError("trusted keyring is missing or exceeds the supported size")
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    keys = payload.get("keys") if isinstance(payload, dict) else None
    if not isinstance(keys, list):
        raise EvidenceError("trusted keyring must contain a keys array")
    result: dict[str, bytes] = {}
    for item in keys:
        if not isinstance(item, dict):
            continue
        key_id = str(item.get("keyId", ""))
        value = str(item.get("publicKey", ""))
        if not key_id or len(key_id) > 160:
            raise EvidenceError("trusted key ID is invalid")
        try:
            decoded = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise EvidenceError("trusted public key is not valid base64") from exc
        if len(decoded) != 32:
            raise EvidenceError("Ed25519 public keys must be exactly 32 bytes")
        result[key_id] = decoded
    return result


def verify_attestation(
    path: Path,
    *,
    target_digest: str,
    trusted_keyring: Path | None = None,
) -> AttestationVerification:
    """Verify a DSSE Ed25519 attestation bound to the exact target digest.

    Embedded keys can establish integrity but not trusted publisher identity.
    Such valid envelopes return ``self-attested``. ``verified`` requires that
    the signature key ID is present in the caller-controlled trusted keyring.
    """

    if not path.is_file():
        return AttestationVerification("absent", None, "No attestation was supplied.")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return AttestationVerification("failed", None, "Attestation is unreadable or malformed.")
    if not isinstance(payload, dict) or payload.get("schemaVersion") != ATTESTATION_SCHEMA:
        return AttestationVerification("failed", None, "Attestation schema is unsupported.")
    envelope = payload.get("envelope")
    if not isinstance(envelope, dict):
        return AttestationVerification("failed", None, "DSSE envelope is missing.")
    payload_type = str(envelope.get("payloadType", ""))
    encoded_statement = str(envelope.get("payload", ""))
    signatures = envelope.get("signatures")
    if not payload_type or not isinstance(signatures, list) or not signatures:
        return AttestationVerification("failed", None, "DSSE envelope fields are incomplete.")
    try:
        statement_bytes = base64.b64decode(encoded_statement, validate=True)
        statement = json.loads(statement_bytes)
    except (ValueError, json.JSONDecodeError):
        return AttestationVerification("failed", None, "Attestation statement is invalid.")
    subjects = statement.get("subject") if isinstance(statement, dict) else None
    if not isinstance(subjects, list) or not any(
        isinstance(subject, dict)
        and isinstance(subject.get("digest"), dict)
        and subject["digest"].get("sha256") == target_digest
        for subject in subjects
    ):
        return AttestationVerification("failed", None, "Attestation is not bound to the scanned target digest.")
    try:
        trusted = _load_trusted_keys(trusted_keyring)
    except (EvidenceError, OSError, json.JSONDecodeError) as exc:
        return AttestationVerification("failed", None, str(exc))
    embedded = payload.get("publicKeys")
    embedded_keys: dict[str, bytes] = {}
    if isinstance(embedded, list):
        for item in embedded:
            if not isinstance(item, dict):
                continue
            try:
                key_bytes = base64.b64decode(str(item.get("publicKey", "")), validate=True)
            except ValueError:
                continue
            if len(key_bytes) == 32:
                embedded_keys[str(item.get("keyId", ""))] = key_bytes
    message = dsse_pae(payload_type, statement_bytes)
    for signature in signatures:
        if not isinstance(signature, dict):
            continue
        key_id = str(signature.get("keyid", ""))
        key = trusted.get(key_id) or embedded_keys.get(key_id)
        if key is None:
            continue
        try:
            signature_bytes = base64.b64decode(str(signature.get("sig", "")), validate=True)
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

            Ed25519PublicKey.from_public_bytes(key).verify(signature_bytes, message)
        except (ValueError, ImportError, Exception):
            continue
        if key_id in trusted:
            return AttestationVerification("verified", key_id, "Signature matches a caller-trusted Ed25519 key.")
        return AttestationVerification(
            "self-attested",
            key_id,
            "Signature is valid, but publisher identity is not in the caller-controlled trust root.",
        )
    return AttestationVerification("failed", None, "No valid signature matched an available key.")


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        raise urllib.error.HTTPError(req.full_url, code, "Redirects are not allowed for evidence uploads", headers, fp)


def upload_evidence(
    endpoint: str,
    envelope: dict[str, Any],
    *,
    token: str,
    timeout: float = 10.0,
    ssl_context: ssl.SSLContext | None = None,
) -> UploadReceipt:
    """Upload evidence over HTTPS without redirects or credential forwarding."""

    validated = validate_evidence_envelope(envelope)
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise EvidenceError("evidence endpoint must be a credential-free HTTPS URL")
    if parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
        raise EvidenceError("loopback evidence endpoints are not allowed")
    if not token or len(token) > 8192 or "\r" in token or "\n" in token:
        raise EvidenceError("upload token is missing or malformed")
    body = canonical_json_bytes(validated)
    digest = validated["evidenceDigest"]["value"]
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Idempotency-Key": digest,
            "X-HOL-Evidence-Digest": digest,
            "User-Agent": "hol-guard-extension-evidence/2",
        },
    )
    opener = urllib.request.build_opener(_NoRedirectHandler(), urllib.request.HTTPSHandler(context=ssl_context or ssl.create_default_context()))
    try:
        with opener.open(request, timeout=max(1.0, min(timeout, 30.0))) as response:
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(response_body) > MAX_RESPONSE_BYTES:
                raise EvidenceError("evidence upload response exceeded the maximum size")
            status = int(response.status)
    except urllib.error.HTTPError as exc:
        raise EvidenceError(f"evidence upload rejected with HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise EvidenceError("evidence upload transport failed") from exc
    if not 200 <= status < 300:
        raise EvidenceError(f"evidence upload failed with HTTP {status}")
    if not response_body:
        response_payload: dict[str, Any] = {}
    else:
        try:
            decoded = json.loads(response_body)
        except json.JSONDecodeError as exc:
            raise EvidenceError("evidence upload response was not valid JSON") from exc
        if not isinstance(decoded, dict):
            raise EvidenceError("evidence upload response must be a JSON object")
        response_payload = decoded
    return UploadReceipt(status_code=status, evidence_digest=digest, response=response_payload)
