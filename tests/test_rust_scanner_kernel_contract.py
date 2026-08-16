"""Contract tests for the optional Rust scanner hot-path kernel."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.rust_kernel import KERNEL_PROTOCOL, scan_inventory


CARGO = shutil.which("cargo")


@pytest.mark.skipif(CARGO is None, reason="Cargo is unavailable")
def test_rust_kernel_builds_and_emits_valid_deterministic_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = Path(__file__).resolve().parents[1]
    manifest = repository / "rust" / "scanner-kernel" / "Cargo.toml"
    subprocess.run(
        [CARGO, "build", "--locked", "--manifest-path", str(manifest)],
        check=True,
        cwd=repository,
        timeout=120,
    )
    binary_name = "hol-guard-scanner-kernel.exe" if os.name == "nt" else "hol-guard-scanner-kernel"
    binary = manifest.parent / "target" / "debug" / binary_name
    monkeypatch.setenv("HOL_GUARD_SCANNER_KERNEL", str(binary))
    (tmp_path / "b.txt").write_text("second", encoding="utf-8")
    (tmp_path / "a.txt").write_text("first", encoding="utf-8")
    native = tmp_path / "server.bin"
    native.write_bytes(b"\x7fELF" + b"\x00" * 128 + b"/var/run/docker.sock")

    first = scan_inventory(tmp_path, require_rust=True)
    second = scan_inventory(tmp_path, require_rust=True)

    assert first.protocol == KERNEL_PROTOCOL
    assert first.engine == "rust"
    assert first == second
    assert [record.path for record in first.records] == ["a.txt", "b.txt", "server.bin"]
    native_record = next(record for record in first.records if record.path == "server.bin")
    assert native_record.format == "elf"
    assert "container-socket" in native_record.indicators


@pytest.mark.skipif(CARGO is None, reason="Cargo is unavailable")
def test_rust_kernel_json_is_strict_and_does_not_emit_file_contents(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[1]
    manifest = repository / "rust" / "scanner-kernel" / "Cargo.toml"
    subprocess.run(
        [CARGO, "build", "--locked", "--manifest-path", str(manifest)],
        check=True,
        cwd=repository,
        timeout=120,
    )
    binary_name = "hol-guard-scanner-kernel.exe" if os.name == "nt" else "hol-guard-scanner-kernel"
    binary = manifest.parent / "target" / "debug" / binary_name
    secret = "github_pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    (tmp_path / "secret.txt").write_text(secret, encoding="utf-8")

    completed = subprocess.run(
        [str(binary), "scan", str(tmp_path), "--max-files", "100", "--max-bytes", "1048576"],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    payload = json.loads(completed.stdout)

    assert payload["protocol"] == KERNEL_PROTOCOL
    assert secret not in completed.stdout
    assert payload["records"][0]["sha256"]


def test_python_fallback_is_deterministic_and_rejects_escaping_links(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOL_GUARD_SCANNER_KERNEL", str(tmp_path / "missing-kernel"))
    (tmp_path / "z.txt").write_text("z", encoding="utf-8")
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    outside = tmp_path.parent / "outside-kernel-test"
    outside.write_text("outside", encoding="utf-8")
    if hasattr(os, "symlink"):
        try:
            (tmp_path / "escape").symlink_to(outside)
        except OSError:
            pass

    first = scan_inventory(tmp_path)
    second = scan_inventory(tmp_path)

    assert first.engine == "python"
    assert first == second
    assert [record.path for record in first.records] == sorted(record.path for record in first.records)
    link = next((record for record in first.records if record.path == "escape"), None)
    if link is not None:
        assert link.symlink_escapes_root is True
