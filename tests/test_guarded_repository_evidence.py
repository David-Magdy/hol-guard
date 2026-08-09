from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from codex_plugin_scanner.guarded_repository_evidence import (
    CLAIM,
    build_guarded_repository_evidence,
    file_sha256,
    guarded_repository_evidence_json,
    guarded_repository_evidence_sha256,
)


def _evidence():
    return build_guarded_repository_evidence(
        repository="hashgraph-online/example",
        commit_sha="a" * 40,
        workflow_run_id="123456",
        scanner_version="3.0.0a1",
        scanner_profile="strict-security",
        score=93,
        grade="A",
        max_severity="medium",
        findings_total=2,
        sarif_sha256="b" * 64,
        visibility="public",
        generated_at=datetime(2026, 8, 9, 20, 0, tzinfo=UTC),
    )


def test_guarded_repository_evidence_is_sanitized_and_bounded() -> None:
    evidence = _evidence()
    serialized = guarded_repository_evidence_json(evidence)

    assert evidence.claim == CLAIM
    assert evidence.runtime_coverage_claimed is False
    assert evidence.sensitive_content_included is False
    assert "vulnerability-free" in evidence.claim
    assert "does not prove runtime protection" in evidence.claim
    for forbidden in ("path", "source_code", "prompt", "command", "secret", "token", "actor"):
        assert f'"{forbidden}"' not in serialized
    assert len(guarded_repository_evidence_sha256(evidence)) == 64


def test_guarded_repository_evidence_rejects_invalid_identity_and_digest() -> None:
    kwargs = dict(
        repository="hashgraph-online/example",
        commit_sha="a" * 40,
        workflow_run_id="123456",
        scanner_version="3.0.0a1",
        scanner_profile="strict-security",
        score=93,
        grade="A",
        max_severity="medium",
        findings_total=2,
        sarif_sha256="b" * 64,
        visibility="private",
        generated_at=datetime(2026, 8, 9, 20, 0, tzinfo=UTC),
    )
    with pytest.raises(ValueError, match="repository"):
        build_guarded_repository_evidence(**{**kwargs, "repository": "invalid"})
    with pytest.raises(ValueError, match="commit_sha"):
        build_guarded_repository_evidence(**{**kwargs, "commit_sha": "main"})
    with pytest.raises(ValueError, match="sarif_sha256"):
        build_guarded_repository_evidence(**{**kwargs, "sarif_sha256": "bad"})


def test_file_sha256_hashes_only_subject_bytes(tmp_path: Path) -> None:
    path = tmp_path / "scan.sarif"
    path.write_bytes(b"synthetic sarif")

    first = file_sha256(path)
    path.write_bytes(b"synthetic sarif changed")
    second = file_sha256(path)

    assert first != second
    assert len(first) == 64
    assert len(second) == 64
