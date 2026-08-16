"""Evidence envelope, signature, and upload security tests."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.evidence_envelope import (
    ATTESTATION_SCHEMA,
    EvidenceError,
    build_evidence_envelope,
    canonical_json_bytes,
    dsse_pae,
    upload_evidence,
    validate_evidence_envelope,
    verify_attestation,
)


def _envelope() -> dict[str, object]:
    return build_evidence_envelope(
        target_digest="a" * 64,
        scanner_version="3.0.0",
        layers=[
            {
                "id": "static",
                "status": "complete",
                "analyzer": "python",
                "coverage": 100,
                "claims": {"findings": 0},
                "limitations": [],
            },
            {
                "id": "runtime",
                "status": "not-run",
                "analyzer": "oci",
                "coverage": 0,
                "claims": {},
                "limitations": ["No runtime evidence was supplied."],
            },
        ],
        findings=[],
        policy={"profile": "consumer-install"},
        generated_at="2026-08-16T00:00:00+00:00",
    )


def test_evidence_digest_is_deterministic_and_tamper_evident() -> None:
    first = _envelope()
    second = _envelope()

    assert first == second
    assert validate_evidence_envelope(first) is first
    tampered = json.loads(json.dumps(first))
    tampered["layers"][0]["coverage"] = 99
    with pytest.raises(EvidenceError, match="digest"):
        validate_evidence_envelope(tampered)


def test_evidence_redacts_secret_bearing_claims() -> None:
    envelope = build_evidence_envelope(
        target_digest="b" * 64,
        scanner_version="3.0.0",
        layers=[
            {
                "id": "static",
                "status": "complete",
                "analyzer": "python",
                "coverage": 100,
                "claims": {
                    "authorization": "Bearer sensitive-value",
                    "sample": "github_pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                },
                "limitations": [],
            }
        ],
        findings=[],
    )

    rendered = json.dumps(envelope)
    assert "sensitive-value" not in rendered
    assert "github_pat_" not in rendered
    assert "[redacted]" in rendered


def _write_attestation(tmp_path: Path, target_digest: str):
    cryptography = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    private_key = cryptography.Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "extension", "digest": {"sha256": target_digest}}],
        "predicateType": "https://hol.org/guard/extension-security/v1",
        "predicate": {"builder": "test"},
    }
    statement_bytes = canonical_json_bytes(statement)
    payload_type = "application/vnd.in-toto+json"
    signature = private_key.sign(dsse_pae(payload_type, statement_bytes))
    key_id = "publisher:test"
    attestation = {
        "schemaVersion": ATTESTATION_SCHEMA,
        "envelope": {
            "payloadType": payload_type,
            "payload": base64.b64encode(statement_bytes).decode("ascii"),
            "signatures": [{"keyid": key_id, "sig": base64.b64encode(signature).decode("ascii")}],
        },
        "publicKeys": [{"keyId": key_id, "publicKey": base64.b64encode(public_key).decode("ascii")}],
    }
    path = tmp_path / "attestation.json"
    path.write_text(json.dumps(attestation), encoding="utf-8")
    return path, key_id, public_key


def test_attestation_distinguishes_self_attested_from_trusted(tmp_path: Path) -> None:
    digest = "c" * 64
    path, key_id, public_key = _write_attestation(tmp_path, digest)

    self_attested = verify_attestation(path, target_digest=digest)
    keyring = tmp_path / "trusted-keys.json"
    keyring.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "keyId": key_id,
                        "publicKey": base64.b64encode(public_key).decode("ascii"),
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    trusted = verify_attestation(path, target_digest=digest, trusted_keyring=keyring)
    wrong_digest = verify_attestation(path, target_digest="d" * 64, trusted_keyring=keyring)

    assert self_attested.status == "self-attested"
    assert trusted.status == "verified"
    assert wrong_digest.status == "failed"


def test_upload_requires_safe_https_endpoint() -> None:
    envelope = _envelope()

    with pytest.raises(EvidenceError, match="HTTPS"):
        upload_evidence("http://registry.example.com/evidence", envelope, token="token")
    with pytest.raises(EvidenceError, match="loopback"):
        upload_evidence("https://127.0.0.1/evidence", envelope, token="token")
    with pytest.raises(EvidenceError, match="credential-free"):
        upload_evidence("https://user:pass@registry.example.com/evidence", envelope, token="token")


def test_upload_uses_digest_as_idempotency_key(monkeypatch: pytest.MonkeyPatch) -> None:
    envelope = _envelope()
    captured: dict[str, object] = {}

    class Response:
        status = 201

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _limit: int) -> bytes:
            return b'{"accepted":true}'

    class Opener:
        def open(self, request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return Response()

    monkeypatch.setattr("urllib.request.build_opener", lambda *_handlers: Opener())

    receipt = upload_evidence(
        "https://registry.example.com/v1/evidence",
        envelope,
        token="upload-token",
    )

    request = captured["request"]
    assert request.get_header("Idempotency-key") == envelope["evidenceDigest"]["value"]
    assert request.get_header("Authorization") == "Bearer upload-token"
    assert receipt.status_code == 201
