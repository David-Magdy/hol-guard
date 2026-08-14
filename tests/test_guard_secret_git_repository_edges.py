from __future__ import annotations

import json
import subprocess
from pathlib import Path

from codex_plugin_scanner.guard.secrets.secret_repository_scanner import scan_repository_secrets
from codex_plugin_scanner.guard.secrets.secret_staged_scanner import scan_staged_secrets


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def _repository(root: Path) -> Path:
    root.mkdir()
    assert _git(root, "init").returncode == 0
    assert _git(root, "config", "user.email", "guard-test@example.invalid").returncode == 0
    assert _git(root, "config", "user.name", "Guard Test").returncode == 0
    return root


def _commit(root: Path, name: str, content: str, message: str) -> None:
    (root / name).write_text(content, encoding="utf-8")
    assert _git(root, "add", name).returncode == 0
    assert _git(root, "commit", "-m", message).returncode == 0


def _lfs_pointer() -> str:
    digest = "".join(("0123456789abcdef",) * 4)
    return (
        "version https://git-lfs.github.com/spec/v1\n"
        f"oid sha256:{digest}\n"
        "size 128\n"
    )


def test_working_tree_lfs_pointer_is_partial_not_clean(tmp_path: Path) -> None:
    root = _repository(tmp_path / "repository")
    (root / "asset.dat").write_text(_lfs_pointer(), encoding="utf-8")

    result = scan_repository_secrets(root)

    assert result.truncated is True
    assert "git_lfs_pointer_content_unavailable" in result.errors
    assert "sha256:" not in json.dumps(result.to_public_dict())


def test_staged_lfs_pointer_is_partial_not_clean(tmp_path: Path) -> None:
    root = _repository(tmp_path / "repository")
    (root / "asset.dat").write_text(_lfs_pointer(), encoding="utf-8")
    assert _git(root, "add", "asset.dat").returncode == 0

    result = scan_staged_secrets(root)

    assert result.truncated is True
    assert "git_lfs_pointer_content_unavailable" in result.errors


def test_history_lfs_pointer_is_partial_not_clean(tmp_path: Path) -> None:
    root = _repository(tmp_path / "repository")
    _commit(root, "asset.dat", _lfs_pointer(), "add pointer")
    (root / "asset.dat").write_text("materialized=false\n", encoding="utf-8")

    result = scan_repository_secrets(root, include_history=True, max_commits=10)

    assert result.truncated is True
    assert "git_lfs_pointer_content_unavailable" in result.errors


def test_shallow_history_is_reported_as_partial(tmp_path: Path) -> None:
    source = _repository(tmp_path / "source")
    _commit(source, "one.txt", "one\n", "one")
    _commit(source, "two.txt", "two\n", "two")
    shallow = tmp_path / "shallow"
    result = subprocess.run(
        ["git", "clone", "--depth", "1", source.as_uri(), str(shallow)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    scan = scan_repository_secrets(shallow, include_history=True, max_commits=10)

    assert scan.truncated is True
    assert "git_history_shallow_repository" in scan.errors


def test_promisor_partial_clone_config_is_reported_as_partial(tmp_path: Path) -> None:
    root = _repository(tmp_path / "repository")
    _commit(root, "one.txt", "one\n", "one")
    assert _git(root, "config", "remote.origin.promisor", "true").returncode == 0
    assert _git(root, "config", "extensions.partialClone", "origin").returncode == 0

    scan = scan_repository_secrets(root, include_history=True, max_commits=10)

    assert scan.truncated is True
    assert "git_history_partial_clone" in scan.errors


def test_repository_submodule_is_reported_as_unscanned(tmp_path: Path) -> None:
    child = _repository(tmp_path / "child")
    _commit(child, "child.txt", "safe\n", "child")
    parent = _repository(tmp_path / "parent")
    _commit(parent, "parent.txt", "safe\n", "parent")
    added = _git(
        parent,
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        child.as_uri(),
        "vendor/child",
    )
    assert added.returncode == 0, added.stderr

    scan = scan_repository_secrets(parent)

    assert scan.truncated is True
    assert "git_submodule_content_unavailable" in scan.errors


def test_replace_refs_are_ignored_and_reported_as_partial(tmp_path: Path) -> None:
    root = _repository(tmp_path / "repository")
    _commit(root, "one.txt", "one\n", "one")
    first = _git(root, "rev-parse", "HEAD").stdout.strip()
    _commit(root, "two.txt", "two\n", "two")
    second = _git(root, "rev-parse", "HEAD").stdout.strip()
    replaced = _git(root, "replace", second, first)
    assert replaced.returncode == 0, replaced.stderr

    scan = scan_repository_secrets(root, include_history=True, max_commits=10)

    assert scan.truncated is True
    assert "git_replace_refs_ignored" in scan.errors
    assert scan.commits_scanned >= 2


def test_grafts_and_alternate_objects_are_reported_as_partial(tmp_path: Path) -> None:
    root = _repository(tmp_path / "repository")
    _commit(root, "one.txt", "one\n", "one")
    common = Path(_git(root, "rev-parse", "--git-common-dir").stdout.strip())
    if not common.is_absolute():
        common = root / common
    info = common / "info"
    info.mkdir(parents=True, exist_ok=True)
    (info / "grafts").write_text(_git(root, "rev-parse", "HEAD").stdout.strip() + "\n", encoding="utf-8")
    alternate = common / "objects" / "info" / "alternates"
    alternate.parent.mkdir(parents=True, exist_ok=True)
    alternate.write_text(str((tmp_path / "external-objects").resolve()) + "\n", encoding="utf-8")

    scan = scan_repository_secrets(root, include_history=True, max_commits=10)

    assert scan.truncated is True
    assert "git_history_grafts_present" in scan.errors
    assert "git_alternate_objects_present" in scan.errors


def test_unknown_nul_bearing_extension_is_partial_not_silently_binary(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "unknown.payload").write_bytes(b"KEY=value\x00more")

    scan = scan_repository_secrets(root)

    assert scan.truncated is True
    assert "unsupported_text_encoding" in scan.errors
