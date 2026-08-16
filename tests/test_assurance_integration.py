"""Integration, schema, determinism, and parser robustness tests."""

from __future__ import annotations

import json
import random
from pathlib import Path

import jsonschema

from codex_plugin_scanner.assurance.archive_scan import scan_archive_bytes
from codex_plugin_scanner.assurance.limits import ScanLimits
from codex_plugin_scanner.assurance.native_scan import scan_native_bytes
from codex_plugin_scanner.assurance.orchestrator import scan_extension_assurance
from codex_plugin_scanner.models import ScanOptions
from codex_plugin_scanner.reporting import build_json_payload
from codex_plugin_scanner.scanner import scan_plugin


def test_legacy_scan_result_contains_independent_assurance(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# extension\n", encoding="utf-8")
    result = scan_plugin(tmp_path, ScanOptions())
    assert result.assurance is not None
    assert result.assurance["schema_version"] == "hol-guard.assurance-report.v1"
    assert result.assurance["decision"]["disposition"] in {"allow", "warn", "review", "block", "error"}
    payload = build_json_payload(result)
    assert payload["assurance"] == result.assurance


def test_assurance_report_matches_schema(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# extension\n", encoding="utf-8")
    payload = scan_extension_assurance(tmp_path).to_payload()
    schema_path = Path(__file__).parents[1] / "schemas" / "assurance-report.v1.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(payload)


def test_assurance_evidence_is_deterministic_except_time(tmp_path: Path) -> None:
    (tmp_path / "plugin.py").write_text("print('hello')\n", encoding="utf-8")
    first = scan_extension_assurance(tmp_path).to_payload()
    second = scan_extension_assurance(tmp_path).to_payload()
    assert first["artifact_digest"] == second["artifact_digest"]
    assert [item["fingerprint"] for item in first["findings"]] == [
        item["fingerprint"] for item in second["findings"]
    ]
    assert first["capabilities"] == second["capabilities"]


def test_random_native_inputs_do_not_crash() -> None:
    generator = random.Random(20260816)
    magics = (b"MZ", b"\x7fELF", b"\0asm", b"\xcf\xfa\xed\xfe")
    for index in range(128):
        prefix = magics[index % len(magics)]
        payload = prefix + generator.randbytes(generator.randint(0, 4096))
        result = scan_native_bytes(payload, f"fuzz-{index}.bin", ScanLimits(max_file_bytes=8192))
        assert result.summary["signature"]["verified"] is False


def test_random_archive_inputs_fail_closed_without_crashing() -> None:
    generator = random.Random(42)
    for index in range(64):
        payload = b"PK\x03\x04" + generator.randbytes(generator.randint(0, 2048))
        result = scan_archive_bytes(
            payload,
            f"fuzz-{index}.zip",
            ScanLimits(max_archive_bytes=4096, max_archive_member_bytes=4096),
            depth=0,
            budget=[0, 0],
        )
        assert result.complete is False
        assert result.findings
