"""Native artifact parser and Rust parity tests."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.assurance.limits import ScanLimits
from codex_plugin_scanner.assurance.native_scan import detect_native_format, scan_native_bytes


def test_native_magic_detection() -> None:
    assert detect_native_format(b"\x7fELF" + b"\0" * 16) == "elf"
    assert detect_native_format(b"MZ" + b"\0" * 16) == "pe"
    assert detect_native_format(b"\0asm\x01\0\0\0") == "wasm"
    assert detect_native_format(b"plain text") is None


def test_python_fallback_never_claims_signature_verification(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("codex_plugin_scanner.assurance.native_scan._find_engine", lambda: None)
    result = scan_native_bytes(b"MZ" + b"\0" * 256 + b"/var/run/docker.sock", "tool.exe", ScanLimits())
    assert result.rust_used is False
    assert result.summary["signature"]["verified"] is False
    assert "ASSURANCE_NATIVE_FALLBACK_LIMITATION" in {finding.rule_id for finding in result.findings}
    assert "container-control" in result.capabilities


def test_minimal_wasm_is_structurally_inspected() -> None:
    result = scan_native_bytes(b"\0asm\x01\0\0\0", "module.wasm", ScanLimits())
    assert result.summary["format"] == "wasm"
    assert result.summary["signature"]["verified"] is False


def test_rust_engine_outputs_bounded_contract_when_available(tmp_path: Path) -> None:
    engine_value = os.environ.get("HOL_GUARD_SCANNER_ENGINE")
    if not engine_value:
        pytest.skip("Rust scanner engine is not configured")
    engine = Path(engine_value)
    fixture = tmp_path / "module.wasm"
    fixture.write_bytes(b"\0asm\x01\0\0\0")
    completed = subprocess.run(
        [
            str(engine),
            "inspect",
            "--path",
            str(fixture),
            "--display-path",
            "module.wasm",
            "--max-bytes",
            "1024",
            "--max-strings",
            "100",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    payload = json.loads(completed.stdout)
    assert payload["schema_version"] == "hol-guard.scanner-engine.v1"
    assert payload["summary"]["format"] == "wasm"
    assert payload["summary"]["signature"]["verified"] is False


def test_rust_engine_and_fallback_agree_on_format(monkeypatch: pytest.MonkeyPatch) -> None:
    engine_value = os.environ.get("HOL_GUARD_SCANNER_ENGINE")
    if not engine_value:
        pytest.skip("Rust scanner engine is not configured")
    data = b"\0asm\x01\0\0\0"
    accelerated = scan_native_bytes(data, "module.wasm", ScanLimits())
    monkeypatch.setattr("codex_plugin_scanner.assurance.native_scan._find_engine", lambda: None)
    fallback = scan_native_bytes(data, "module.wasm", ScanLimits())
    assert accelerated.summary["format"] == fallback.summary["format"] == "wasm"
    assert accelerated.rust_used is True
