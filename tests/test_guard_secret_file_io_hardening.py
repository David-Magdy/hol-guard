from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.secrets.secret_repository_scanner import scan_repository_secrets


def _token() -> str:
    return "".join(("gh", "p_", "Ab3d", "Ef5h", "Ij7l", "Mn9p", "Qr2t", "Uv4x", "Yz6B", "cd8F"))


@pytest.mark.skipif(os.name == "nt", reason="creating symlinks requires additional Windows runner privileges")
def test_explicit_symlink_scan_target_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    token = _token()
    (outside / "credentials.env").write_text(f"GITHUB_TOKEN={token}\n", encoding="utf-8")
    target = tmp_path / "linked-workspace"
    target.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="must not be a symbolic link"):
        scan_repository_secrets(target)


def test_read_failure_returns_partial_coverage_instead_of_crashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "config.env").write_text("SAFE=true\n", encoding="utf-8")

    def denied_read(_descriptor: int, _size: int) -> bytes:
        raise OSError("simulated read failure")

    monkeypatch.setattr("codex_plugin_scanner.guard.secrets.secret_repository_scanner.os.read", denied_read)

    result = scan_repository_secrets(root)

    assert result.truncated is True
    assert "working_file_unavailable" in result.errors
    assert result.findings == ()


def test_file_identity_change_returns_partial_coverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "config.env").write_text("SAFE=true\n", encoding="utf-8")
    real_fstat = os.fstat
    calls = 0

    def changing_fstat(descriptor: int) -> os.stat_result:
        nonlocal calls
        calls += 1
        current = real_fstat(descriptor)
        if calls != 2:
            return current
        values = list(current)
        values[8] = float(current.st_mtime) + 1.0
        return os.stat_result(values)

    monkeypatch.setattr("codex_plugin_scanner.guard.secrets.secret_repository_scanner.os.fstat", changing_fstat)

    result = scan_repository_secrets(root)

    assert result.truncated is True
    assert "working_file_changed_during_scan" in result.errors
    assert json.dumps(result.to_public_dict()).find(str(root)) == -1
