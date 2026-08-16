"""Regression tests for exact binding, strict parsing, and privacy boundaries."""

from __future__ import annotations

import json
import stat
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.assurance.archive_scan import scan_archive_file
from codex_plugin_scanner.assurance.detonation import (
    DetonationError,
    build_plan,
    execute_plan,
    load_plan,
    write_plan,
)
from codex_plugin_scanner.assurance.evidence import EvidenceError, parse_json_document
from codex_plugin_scanner.assurance.inventory import build_inventory
from codex_plugin_scanner.assurance.limits import ScanLimits
from codex_plugin_scanner.assurance.native_scan import scan_native_bytes
from codex_plugin_scanner.assurance.orchestrator import scan_extension_assurance
from codex_plugin_scanner.assurance.provenance import (
    build_artifact_statement,
    generate_keypair,
    sign_statement,
    verify_envelope,
)
from codex_plugin_scanner.assurance.surface_scan import scan_surfaces


DIGESTED_IMAGE = "example.invalid/hol-guard/detonation@sha256:" + "a" * 64


def test_artifact_provenance_verifies_without_circular_evidence_digest(tmp_path: Path) -> None:
    extension = tmp_path / "extension"
    extension.mkdir()
    (extension / "README.md").write_text("reviewed", encoding="utf-8")
    report = scan_extension_assurance(extension)
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    generate_keypair(private_key, public_key)
    statement = build_artifact_statement(
        artifact_digest=report.artifact_digest,
        scanner_version=report.scanner_version,
    )
    envelope = sign_statement(statement, private_key)
    result = verify_envelope(
        envelope,
        (public_key,),
        expected_artifact_digest=report.artifact_digest,
    )
    assert result.verified is True
    assert result.statement is not None
    assert "evidenceDigest" not in result.statement["predicate"]


def test_detonation_plan_is_bound_to_artifact_and_rejects_post_review_mutation(tmp_path: Path) -> None:
    extension = tmp_path / "extension"
    extension.mkdir()
    target = extension / "run.sh"
    target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    plan = build_plan(
        extension,
        image=DIGESTED_IMAGE,
        command=("/bin/sh", "/extension/run.sh"),
    )
    assert len(plan.artifact_digest) == 64
    target.write_text("#!/bin/sh\necho changed\n", encoding="utf-8")
    with pytest.raises(DetonationError, match="artifact changed"):
        execute_plan(plan)


def test_detonation_plan_loader_rejects_unknown_fields_and_digest_tampering(tmp_path: Path) -> None:
    extension = tmp_path / "extension"
    extension.mkdir()
    (extension / "run.sh").write_text("exit 0", encoding="utf-8")
    plan = build_plan(extension, image=DIGESTED_IMAGE, command=("/bin/true",))
    path = tmp_path / "plan.json"
    write_plan(path, plan)
    assert load_plan(path).plan_digest == plan.plan_digest
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["network"] = "host"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(DetonationError):
        load_plan(path)
    payload = plan.to_payload()
    payload["unknown"] = True
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(DetonationError, match="unknown"):
        load_plan(path)


def test_duplicate_json_keys_and_deep_json_are_rejected() -> None:
    with pytest.raises(EvidenceError, match="duplicate"):
        parse_json_document(b'{"a":1,"a":2}')
    nested = "0"
    for _ in range(70):
        nested = f"[{nested}]"
    with pytest.raises(EvidenceError, match="nesting"):
        parse_json_document(nested.encode())


def test_surface_endpoint_is_sanitized_and_nested_shell_runner_is_detected(tmp_path: Path) -> None:
    payload = {
        "mcpServers": {
            "hostile": {
                "command": "sh",
                "args": ["-c", "npx mutable-package && echo done"],
                "url": "https://user:secret@example.com/path?token=secret#fragment",
            }
        }
    }
    (tmp_path / ".mcp.json").write_text(json.dumps(payload), encoding="utf-8")
    result = scan_surfaces(tmp_path)
    assert result.endpoints == ("https://example.com/path",)
    assert all("secret" not in endpoint for endpoint in result.endpoints)
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "ASSURANCE_MCP_SHELL_LAUNCHER" in rule_ids
    assert "ASSURANCE_MCP_MUTABLE_PACKAGE_RUNNER" in rule_ids


def test_zip_symlink_is_never_read_as_regular_payload(tmp_path: Path) -> None:
    archive = tmp_path / "extension.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        handle.writestr(info, "../../outside")
    result = scan_archive_file(archive, archive.name, ScanLimits())
    assert any(finding.rule_id == "ASSURANCE_ARCHIVE_SYMLINK" for finding in result.findings)
    assert all(path != "extension.zip!/link" for path, _payload in result.text_payloads)


def test_inventory_includes_packaged_dependency_and_build_directories(tmp_path: Path) -> None:
    for relative in (
        "node_modules/pkg/index.js",
        "dist/bundle.js",
        "build/generated.py",
        "target/release/tool",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("content", encoding="utf-8")
    inventory = build_inventory(tmp_path, ScanLimits())
    paths = {entry.relative_path for entry in inventory.entries}
    assert {
        "node_modules/pkg/index.js",
        "dist/bundle.js",
        "build/generated.py",
        "target/release/tool",
    } <= paths


def test_native_signature_presence_never_claims_verification() -> None:
    payload = b"MZ" + b"\0" * 1024 + b"WIN_CERTIFICATE"
    result = scan_native_bytes(payload, "fixture.exe", ScanLimits())
    assert result.summary["signature"]["verified"] is False
    assert result.summary["signature"]["verification"] == "not-performed"


def test_tampered_plan_object_cannot_be_repaired_by_replacing_digest_only(tmp_path: Path) -> None:
    extension = tmp_path / "extension"
    extension.mkdir()
    (extension / "run.sh").write_text("exit 0", encoding="utf-8")
    plan = build_plan(extension, image=DIGESTED_IMAGE, command=("/bin/true",))
    weakened = replace(plan, network="host")
    with pytest.raises(DetonationError):
        execute_plan(weakened)
