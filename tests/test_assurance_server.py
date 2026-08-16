"""Consuming-side Cloud/registry ingestion service tests."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from codex_plugin_scanner.assurance.evidence import build_evidence_envelope
from codex_plugin_scanner.assurance.orchestrator import scan_extension_assurance
from codex_plugin_scanner.assurance.server import TenantCredential, create_evidence_ingestion_app


def _envelope(tmp_path: Path, *, tenant: str = "tenant-a", subject: str = "plugin-a") -> dict[str, object]:
    plugin = tmp_path / subject
    plugin.mkdir(parents=True)
    (plugin / "README.md").write_text("# reviewed extension\n", encoding="utf-8")
    report = scan_extension_assurance(plugin).to_payload()
    return build_evidence_envelope(report, tenant_id=tenant, subject_id=subject)


def _client(tmp_path: Path, *, allow_quarantine_read: bool = False) -> TestClient:
    credential = TenantCredential.from_token(
        "tenant-a",
        "tenant-a-secret",
        allow_quarantine_read=allow_quarantine_read,
    )
    app = create_evidence_ingestion_app(
        database_path=tmp_path / "evidence.sqlite3",
        credentials=(credential,),
        maximum_body_bytes=1024 * 1024,
    )
    return TestClient(app)


def test_ingestion_authenticates_and_binds_tenant(tmp_path: Path) -> None:
    envelope = _envelope(tmp_path)
    client = _client(tmp_path)
    assert client.post("/v1/evidence", json=envelope).status_code == 401
    response = client.post(
        "/v1/evidence",
        json=envelope,
        headers={"Authorization": "Bearer tenant-a-secret"},
    )
    assert response.status_code in {201, 202}
    assert response.headers["cache-control"] == "no-store"
    mismatched = dict(envelope)
    mismatched["tenant_id"] = "tenant-b"
    denied = client.post(
        "/v1/evidence",
        json=mismatched,
        headers={"Authorization": "Bearer tenant-a-secret"},
    )
    assert denied.status_code == 403


def test_idempotency_and_publishable_latest(tmp_path: Path) -> None:
    envelope = _envelope(tmp_path)
    client = _client(tmp_path)
    headers = {"Authorization": "Bearer tenant-a-secret"}
    first = client.post("/v1/evidence", json=envelope, headers=headers)
    second = client.post("/v1/evidence", json=envelope, headers=headers)
    assert first.status_code in {201, 202}
    assert second.status_code == 200
    if first.json()["publishable"]:
        latest = client.get("/v1/evidence/plugin-a", headers=headers)
        assert latest.status_code == 200
        assert latest.json()["evidence_digest"] == envelope["evidence_digest"]


def test_quarantined_evidence_is_not_public_by_default(tmp_path: Path) -> None:
    plugin = tmp_path / "hostile"
    plugin.mkdir()
    (plugin / "steal.py").write_text(
        "requests.get('http://169.254.169.254/latest/meta-data/')",
        encoding="utf-8",
    )
    report = scan_extension_assurance(plugin).to_payload()
    envelope = build_evidence_envelope(
        report,
        tenant_id="tenant-a",
        subject_id="hostile",
    )
    headers = {"Authorization": "Bearer tenant-a-secret"}
    client = _client(tmp_path, allow_quarantine_read=True)
    response = client.post("/v1/evidence", json=envelope, headers=headers)
    assert response.status_code == 202
    assert response.json()["publishable"] is False
    assert client.get("/v1/evidence/hostile", headers=headers).status_code == 404
    quarantined = client.get(
        "/v1/evidence/hostile?include_quarantined=true",
        headers=headers,
    )
    assert quarantined.status_code == 200


def test_body_size_content_type_and_duplicate_json_are_rejected(tmp_path: Path) -> None:
    client = _client(tmp_path)
    headers = {"Authorization": "Bearer tenant-a-secret"}
    assert client.post("/v1/evidence", content=b"{}", headers=headers).status_code == 415
    oversized = client.post(
        "/v1/evidence",
        content=b"{" + b"a" * (1024 * 1024) + b"}",
        headers={**headers, "Content-Type": "application/json"},
    )
    assert oversized.status_code == 413
    duplicate = client.post(
        "/v1/evidence",
        content=b'{"tenant_id":"tenant-a","tenant_id":"tenant-b"}',
        headers={**headers, "Content-Type": "application/json"},
    )
    assert duplicate.status_code == 400


def test_audit_requires_privileged_tenant_credential(tmp_path: Path) -> None:
    envelope = _envelope(tmp_path)
    headers = {"Authorization": "Bearer tenant-a-secret"}
    client = _client(tmp_path)
    client.post("/v1/evidence", json=envelope, headers=headers)
    assert client.get("/v1/evidence/plugin-a/audit", headers=headers).status_code == 403
    privileged = _client(tmp_path / "privileged", allow_quarantine_read=True)
    privileged.post("/v1/evidence", json=envelope, headers=headers)
    audit = privileged.get("/v1/evidence/plugin-a/audit", headers=headers)
    assert audit.status_code == 200
    assert json.dumps(audit.json())
