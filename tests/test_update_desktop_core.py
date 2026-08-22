"""Signed Core feed updates for frozen Desktop installs."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import update_desktop_core


def test_executable_is_desktop_core_for_app_bundle_and_managed_sidecar(tmp_path: Path) -> None:
    bundled = tmp_path / "HOL Guard.app" / "Contents" / "MacOS" / "hol-guard"
    bundled.parent.mkdir(parents=True)
    bundled.write_text("core", encoding="utf-8")
    managed = tmp_path / "org.hol.guard.desktop" / "core" / "versions" / "3.0.0a200" / "hol-guard"
    managed.parent.mkdir(parents=True)
    managed.write_text("core", encoding="utf-8")
    sibling_dir = tmp_path / "runtime"
    sibling_dir.mkdir()
    sibling_core = sibling_dir / "hol-guard"
    sibling_desktop = sibling_dir / "hol-guard-desktop"
    sibling_core.write_text("core", encoding="utf-8")
    sibling_desktop.write_text("desktop", encoding="utf-8")

    assert update_desktop_core.executable_is_desktop_core(bundled) is True
    assert update_desktop_core.executable_is_desktop_core(managed) is True
    assert update_desktop_core.executable_is_desktop_core(sibling_core) is True
    assert update_desktop_core.executable_is_desktop_core(tmp_path / "venv" / "bin" / "python") is False


def test_apply_desktop_core_update_installs_verified_sidecar(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_desktop_core, "platform_target", lambda: "aarch64-apple-darwin")
    monkeypatch.setattr(update_desktop_core, "desktop_core_root", lambda: tmp_path / "core")
    monkeypatch.setattr(update_desktop_core, "_macos_codesign_ok", lambda _path: True)
    monkeypatch.setattr(update_desktop_core, "_macos_signing_team", lambda _path: "TEAMID")
    binary = b"signed-core-bytes"
    manifest = {
        "schema": update_desktop_core.UPDATE_SCHEMA,
        "channel": "alpha",
        "version": "3.0.0a200",
        "sourceCommit": "a" * 40,
        "sourceTag": "alpha/v3.0.0a200",
        "target": "aarch64-apple-darwin",
        "artifact": "hol-guard-core-3.0.0a200-aarch64-apple-darwin",
        "sha256": update_desktop_core._sha256_hex(binary),
        "size": len(binary),
        "bootstrapSchema": update_desktop_core.BOOTSTRAP_SCHEMA,
        "minimumDesktopVersion": "0.1.0",
        "publishedAt": "2026-08-22T00:00:00Z",
    }

    def fetch_bytes(url: str, limit: int) -> bytes:
        _ = limit
        if url.endswith(".json"):
            return json.dumps(manifest).encode("utf-8")
        return binary

    result = update_desktop_core.apply_desktop_core_update(
        current_version="3.0.0a138",
        target_version="3.0.0a200",
        include_alpha=True,
        fetch_bytes=fetch_bytes,
    )

    assert result.changed is True
    assert result.version == "3.0.0a200"
    assert result.executable.is_file()
    pointer = json.loads((tmp_path / "core" / "current.json").read_text(encoding="utf-8"))
    assert pointer["schema"] == update_desktop_core.INSTALL_SCHEMA
    assert pointer["version"] == "3.0.0a200"
    assert pointer["sha256"] == update_desktop_core._sha256_hex(binary)


def test_apply_desktop_core_update_rejects_integrity_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(update_desktop_core, "platform_target", lambda: "aarch64-apple-darwin")
    manifest = {
        "schema": update_desktop_core.UPDATE_SCHEMA,
        "channel": "alpha",
        "version": "3.0.0a200",
        "sourceCommit": "a" * 40,
        "sourceTag": "alpha/v3.0.0a200",
        "target": "aarch64-apple-darwin",
        "artifact": "hol-guard-core-3.0.0a200-aarch64-apple-darwin",
        "sha256": "b" * 64,
        "size": 4,
        "bootstrapSchema": update_desktop_core.BOOTSTRAP_SCHEMA,
        "minimumDesktopVersion": "0.1.0",
        "publishedAt": "2026-08-22T00:00:00Z",
    }

    def fetch_bytes(url: str, limit: int) -> bytes:
        _ = limit
        if url.endswith(".json"):
            return json.dumps(manifest).encode("utf-8")
        return b"nope"

    with pytest.raises(update_desktop_core.DesktopCoreUpdateError) as error:
        update_desktop_core.apply_desktop_core_update(
            current_version="3.0.0a138",
            target_version="3.0.0a200",
            include_alpha=True,
            fetch_bytes=fetch_bytes,
        )
    assert error.value.reason_code == "desktop_core_integrity_mismatch"


def test_download_bytes_rejects_untrusted_source() -> None:
    with pytest.raises(update_desktop_core.DesktopCoreUpdateError) as error:
        update_desktop_core._download_bytes(
            "https://example.com/hol-guard-core",
            16,
            network_policy=None,
        )
    assert error.value.reason_code == "desktop_core_source_untrusted"
