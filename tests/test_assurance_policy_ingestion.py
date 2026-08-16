"""Managed policy, signed provenance, and consuming-side ingestion tests."""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.assurance.evidence import (
    EvidenceError,
    build_evidence_envelope,
    validate_evidence_envelope,
)
from codex_plugin_scanner.assurance.ingestion import EvidenceStore, IngestionError
from codex_plugin_scanner.assurance.models import canonical_json_bytes
from codex_plugin_scanner.assurance.orchestrator import scan_extension_assurance
from codex_plugin_scanner.assurance.policy import (
    BUILTIN_POLICIES,
    AssurancePolicy,
    Disposition,
    Severity,
    compose_managed_policy,
)
from codex_plugin_scanner.assurance.provenance import (
    build_statement,
    generate_keypair,
    sign_statement,
    verify_envelope,
)
from codex_plugin_scanner.assurance.upload import SecureEvidenceUploader, UploadError


def _benign_report(tmp_path: Path) -> dict[str, object]:
    (tmp_path / "README.md").write_text("# reviewed extension\n", encoding="utf-8")
    return scan_extension_assurance(tmp_path).to_payload()


def test_evidence_digest_tampering_is_rejected(tmp_path: Path) -> None:
    report = _benign_report(tmp_path)
    envelope = build_evidence_envelope(report, tenant_id="tenant-a", subject_id="plugin-a")
    envelope["artifact_digest"] = "0" * 64
    with pytest.raises(EvidenceError):
        validate_evidence_envelope(envelope)


def test_ingestion_is_idempotent_and_rejects_conflicting_replay(tmp_path: Path) -> None:
    report = _benign_report(tmp_path / "plugin")
    envelope = build_evidence_envelope(report, tenant_id="tenant-a", subject_id="plugin-a")
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    first = store.ingest(envelope, policy=BUILTIN_POLICIES["balanced"])
    second = store.ingest(envelope, policy=BUILTIN_POLICIES["balanced"])
    assert first.idempotent is False
    assert second.idempotent is True

    conflicting = copy.deepcopy(envelope)
    conflicting["sequence"] = 2
    unsigned = dict(conflicting)
    unsigned.pop("evidence_digest")
    conflicting["evidence_digest"] = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    with pytest.raises(IngestionError, match="evidence_id replayed"):
        store.ingest(conflicting, policy=BUILTIN_POLICIES["balanced"])


def test_ingestion_requires_strictly_increasing_sequence(tmp_path: Path) -> None:
    report = _benign_report(tmp_path / "plugin")
    store = EvidenceStore(tmp_path / "evidence.sqlite3")
    first = build_evidence_envelope(
        report,
        tenant_id="tenant-a",
        subject_id="plugin-a",
        sequence=2,
    )
    store.ingest(first, policy=BUILTIN_POLICIES["balanced"])
    older = build_evidence_envelope(
        report,
        tenant_id="tenant-a",
        subject_id="plugin-a",
        sequence=1,
    )
    with pytest.raises(IngestionError, match="strictly increasing"):
        store.ingest(older, policy=BUILTIN_POLICIES["balanced"])


def test_managed_policy_cannot_be_weakened() -> None:
    managed = BUILTIN_POLICIES["enterprise-strict"]
    user = AssurancePolicy(
        name="permissive-user",
        block_at=Severity.CRITICAL,
        review_at=Severity.CRITICAL,
        warn_at=Severity.CRITICAL,
        incomplete_coverage=Disposition.ALLOW,
        require_provenance=False,
        require_detonation=False,
    )
    composed = compose_managed_policy(managed, None, user)
    assert composed.block_at == managed.block_at
    assert composed.incomplete_coverage == managed.incomplete_coverage
    assert composed.require_provenance is True
    assert composed.require_detonation is True
    assert composed.minimum_assurance == managed.minimum_assurance


def test_signed_provenance_binds_artifact_and_evidence_digest(tmp_path: Path) -> None:
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    key_id = generate_keypair(private_key, public_key)
    statement = build_statement(
        artifact_digest="1" * 64,
        evidence_digest="2" * 64,
        scanner_version="3.0.0",
        decision="allow",
        coverage_state="complete",
        assurance_level="static",
    )
    envelope = sign_statement(statement, private_key)
    verified = verify_envelope(
        envelope,
        (public_key,),
        expected_artifact_digest="1" * 64,
        expected_evidence_digest="2" * 64,
    )
    assert verified.verified is True
    assert verified.key_id == key_id
    tampered = verify_envelope(
        envelope,
        (public_key,),
        expected_artifact_digest="3" * 64,
    )
    assert tampered.verified is False


def test_strict_ingestion_requires_trusted_provenance(tmp_path: Path) -> None:
    report = _benign_report(tmp_path / "plugin")
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    key_id = generate_keypair(private_key, public_key)
    statement = build_statement(
        artifact_digest=str(report["artifact_digest"]),
        evidence_digest=str(report["evidence_digest"]),
        scanner_version=str(report["scanner_version"]),
        decision=str(report["decision"]["disposition"]),
        coverage_state=str(report["coverage"]["state"]),
        assurance_level=str(report["assurance_level"]),
    )
    provenance = sign_statement(statement, private_key)
    envelope = build_evidence_envelope(
        report,
        tenant_id="tenant-a",
        subject_id="plugin-a",
        provenance_envelope=provenance,
    )
    policy = AssurancePolicy(
        name="signed",
        require_provenance=True,
        trusted_signers=(key_id,),
    )
    result = EvidenceStore(tmp_path / "evidence.sqlite3").ingest(
        envelope,
        policy=policy,
        trusted_public_keys=(public_key,),
    )
    assert result.provenance_verified is True
    assert result.signer_key_id == key_id


def test_uploader_rejects_private_dns_and_non_https() -> None:
    def private_resolver(host: str, port: int, **kwargs):
        return [(2, 1, 6, "", ("127.0.0.1", port))]

    uploader = SecureEvidenceUploader(
        allowed_hosts=("registry.example",),
        resolver=private_resolver,
    )
    with pytest.raises(UploadError, match="HTTPS"):
        uploader._validate_endpoint("http://registry.example/evidence")
    with pytest.raises(UploadError, match="non-public"):
        uploader._validate_endpoint("https://registry.example/evidence")


def test_evidence_age_is_enforced(tmp_path: Path) -> None:
    report = _benign_report(tmp_path / "plugin")
    envelope = build_evidence_envelope(report, tenant_id="tenant-a", subject_id="plugin-a")
    now = datetime(2030, 1, 1, tzinfo=timezone.utc)
    with pytest.raises(IngestionError, match="older"):
        EvidenceStore(tmp_path / "evidence.sqlite3").ingest(
            envelope,
            policy=BUILTIN_POLICIES["balanced"],
            now=now,
        )
