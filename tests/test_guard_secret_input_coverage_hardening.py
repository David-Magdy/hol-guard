from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.secrets.secret_repository_scanner import scan_repository_secrets
from codex_plugin_scanner.guard.secrets.secret_staged_scanner import scan_staged_secrets


def _token() -> str:
    return "".join(("gh", "p_", "Ab3d", "Ef5h", "Ij7l", "Mn9p", "Qr2t", "Uv4x", "Yz6B", "cd8F"))


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    assert _git(root, "init").returncode == 0
    return root


@pytest.mark.parametrize("encoding", ["utf-16", "utf-32"])
def test_unicode_bom_text_is_scanned_without_raw_value_disclosure(tmp_path: Path, encoding: str) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    token = _token()
    (root / "credentials.env").write_bytes(f"GITHUB_TOKEN={token}\n".encode(encoding))

    result = scan_repository_secrets(root)

    assert result.truncated is False
    assert [finding.rule_id for finding in result.findings] == ["github-token"]
    assert token not in json.dumps(result.to_public_dict())


def test_unsupported_working_tree_encoding_is_partial_not_clean(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "credentials.env").write_bytes(b"GITHUB_TOKEN=\x80\x81\x82\n")

    result = scan_repository_secrets(root)

    assert result.truncated is True
    assert "unsupported_text_encoding" in result.errors
    assert result.findings == ()


def test_unsupported_staged_encoding_is_partial_not_clean(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "credentials.env").write_bytes(b"GITHUB_TOKEN=\x80\x81\x82\n")
    assert _git(root, "add", "credentials.env").returncode == 0

    result = scan_staged_secrets(root)

    assert result.truncated is True
    assert "unsupported_text_encoding" in result.errors
    assert result.findings == ()


@pytest.mark.skipif(os.name == "nt", reason="creating symlinks requires additional Windows runner privileges")
def test_working_tree_symlink_outside_repository_is_not_followed(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    outside = tmp_path / "outside.env"
    token = _token()
    outside.write_text(f"GITHUB_TOKEN={token}\n", encoding="utf-8")
    (root / "linked.env").symlink_to(outside)

    result = scan_repository_secrets(root)

    assert result.findings == ()
    assert token not in json.dumps(result.to_public_dict())


def test_known_binary_suffix_is_an_explicitly_excluded_surface_not_partial(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"A" * 4096)

    result = scan_repository_secrets(root, max_file_bytes=64)

    assert result.truncated is False
    assert result.errors == ()
    assert result.findings == ()


def test_known_binary_staged_blob_does_not_create_false_partial_coverage(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"A" * 4096)
    assert _git(root, "add", "image.png").returncode == 0

    result = scan_staged_secrets(root, max_file_bytes=64)

    assert result.truncated is False
    assert result.errors == ()
    assert result.findings == ()
