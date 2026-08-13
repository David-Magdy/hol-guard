from __future__ import annotations

import dataclasses
import inspect
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Callable

import pytest

from codex_plugin_scanner.guard.secrets import secret_repository_scanner, secret_staged_scanner
from codex_plugin_scanner.guard.secrets.coverage import (
    audit_staged_index,
    audit_working_tree,
)


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "coverage repository"
    root.mkdir()
    assert _git(root, "init").returncode == 0
    assert _git(root, "config", "user.email", "coverage@example.test").returncode == 0
    assert _git(root, "config", "user.name", "Coverage Test").returncode == 0
    return root


def _scanner(module: Any, *names: str) -> Callable[..., Any]:
    for name in names:
        candidate = getattr(module, name, None)
        if callable(candidate):
            return candidate
    raise AssertionError(f"scanner entry point not found: {names}")


def _call_scan(scanner: Callable[..., Any], root: Path, **overrides: Any) -> Any:
    parameters = inspect.signature(scanner).parameters
    kwargs = {key: value for key, value in overrides.items() if key in parameters}
    return scanner(root, **kwargs)


def _payload(result: Any) -> dict[str, Any]:
    method = getattr(result, "to_public_dict", None)
    if callable(method):
        value = method()
        assert isinstance(value, dict)
        return value
    if dataclasses.is_dataclass(result):
        return dataclasses.asdict(result)
    raise AssertionError(f"unsupported scan result: {type(result)!r}")


def _reason_payload(result: Any) -> str:
    return json.dumps(_payload(result), sort_keys=True)


def _synthetic_token() -> str:
    return "".join(
        (
            "gh",
            "p_",
            "Ab3d",
            "Ef5h",
            "Ij7l",
            "Mn9p",
            "Qr2t",
            "Uv4x",
            "Yz6B",
            "cd8F",
            "gh1J",
            "kl3N",
        )
    )


def test_working_tree_audit_marks_oversized_text_incomplete(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "large.env").write_text("SECRET_KEY=" + "A" * 512, encoding="utf-8")

    audit = audit_working_tree(root, max_files=100, max_file_bytes=64)

    assert audit.complete is False
    assert "max_file_bytes" in audit.incomplete_reasons


def test_working_tree_audit_marks_malformed_text_incomplete(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "malformed.env").write_bytes(b"SECRET_KEY=\xff\xfe\x00broken")

    audit = audit_working_tree(root, max_files=100, max_file_bytes=1024)

    assert "unsupported_text_encoding" in audit.incomplete_reasons


def test_working_tree_audit_marks_lfs_pointer_incomplete(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "secret.env").write_text(
        "version https://git-lfs.github.com/spec/v1\n"
        "oid sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
        "size 123\n",
        encoding="utf-8",
    )

    audit = audit_working_tree(root, max_files=100, max_file_bytes=1024)

    assert "git_lfs_pointer" in audit.incomplete_reasons


def test_working_tree_audit_marks_symlink_incomplete(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    target = root / "target.env"
    target.write_text("clean\n", encoding="utf-8")
    link = root / "linked.env"
    try:
        link.symlink_to(target.name)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable")

    audit = audit_working_tree(root, max_files=100, max_file_bytes=1024)

    assert "symlink_skipped" in audit.incomplete_reasons


def test_working_tree_audit_bounds_path_enumeration(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    for index in range(4):
        (root / f"file-{index}.txt").write_text("clean\n", encoding="utf-8")

    audit = audit_working_tree(root, max_files=2, max_file_bytes=1024)

    assert "max_files" in audit.incomplete_reasons


def test_repository_scan_cannot_claim_clean_when_large_file_is_skipped(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    path = root / "large-secret.env"
    path.write_text(f"TOKEN={_synthetic_token()}\n" + "X" * 512, encoding="utf-8")
    scanner = _scanner(
        secret_repository_scanner,
        "scan_secret_repository",
        "scan_repository_secrets",
        "scan_repository",
    )

    result = _call_scan(scanner, root, max_files=100, max_file_bytes=64)
    payload = _reason_payload(result)

    assert "max_file_bytes" in payload
    assert str(path) not in payload
    assert _synthetic_token() not in payload


def test_repository_scan_cannot_claim_clean_for_lfs_pointer(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    path = root / "tracked-secret.env"
    path.write_text(
        "version https://git-lfs.github.com/spec/v1\n"
        "oid sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
        "size 123\n",
        encoding="utf-8",
    )
    scanner = _scanner(
        secret_repository_scanner,
        "scan_secret_repository",
        "scan_repository_secrets",
        "scan_repository",
    )

    result = _call_scan(scanner, root, max_files=100, max_file_bytes=1024)

    assert "git_lfs_pointer" in _reason_payload(result)


def test_repository_scan_detects_utf16_secret_without_disclosure(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    token = _synthetic_token()
    (root / "utf16-secret.env").write_text(f"TOKEN={token}\n", encoding="utf-16")
    scanner = _scanner(
        secret_repository_scanner,
        "scan_secret_repository",
        "scan_repository_secrets",
        "scan_repository",
    )

    result = _call_scan(scanner, root, max_files=100, max_file_bytes=4096)
    payload = _payload(result)
    serialized = json.dumps(payload)

    assert int(payload.get("finding_count", len(payload.get("findings", [])))) >= 1
    assert token not in serialized


def test_staged_audit_uses_index_bytes_not_unstaged_worktree(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    path = root / "staged.env"
    path.write_text("clean\n", encoding="utf-8")
    assert _git(root, "add", "staged.env").returncode == 0
    path.write_bytes(b"SECRET_KEY=\xffbroken")

    audit = audit_staged_index(root, max_files=100, max_file_bytes=1024)

    assert audit.complete is True


def test_staged_scan_cannot_claim_clean_for_lfs_pointer(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    path = root / "staged-lfs.env"
    path.write_text(
        "version https://git-lfs.github.com/spec/v1\n"
        "oid sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
        "size 123\n",
        encoding="utf-8",
    )
    assert _git(root, "add", "staged-lfs.env").returncode == 0
    scanner = _scanner(
        secret_staged_scanner,
        "scan_staged_secrets",
        "scan_staged_repository",
        "scan_staged",
    )

    result = _call_scan(scanner, root, max_files=100, max_file_bytes=1024)

    assert "git_lfs_pointer" in _reason_payload(result)


def test_coverage_reasons_are_stable_codes_not_paths(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    private_name = "customer-private-secret.env"
    (root / private_name).write_text("X" * 256, encoding="utf-8")

    audit = audit_working_tree(root, max_files=100, max_file_bytes=32)
    serialized = json.dumps(dataclasses.asdict(audit))

    assert private_name not in serialized
    assert str(root) not in serialized
    assert "max_file_bytes" in serialized


def test_declared_binary_format_is_explicit_but_not_decoded_as_text(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "image.png").write_bytes(os.urandom(128))

    audit = audit_working_tree(root, max_files=100, max_file_bytes=1024)

    assert audit.complete is True
    assert "declared_binary_format" in audit.exclusions
