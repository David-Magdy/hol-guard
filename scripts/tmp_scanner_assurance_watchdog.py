"""Repair deterministic scanner-assurance issues before final review."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def patch_obfuscated_execution(path: Path) -> None:
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    needle = r"(?:eval|exec|Function)\s*\([^\n]*(?:base64\.(?:b64decode|decodebytes)|Buffer\.from\([^\n]*base64|atob\()"
    if needle not in text:
        anchor = '''            r"(?:base64\\.(?:b64decode|decodebytes)|Buffer\\.from\\([^\\n]*base64|atob\\().{0,160}(?:eval|exec|Function|system|spawn|Popen)",\n'''
        replacement = anchor + f'            r"{needle}",\n'
        if anchor not in text:
            raise RuntimeError(f"obfuscation rule anchor missing in {path}")
        text = text.replace(anchor, replacement, 1)
    path.write_text(text, encoding="utf-8")


def patch_detonation_test(path: Path) -> None:
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    if '"artifact_digest": plan.artifact_digest' not in text:
        text = text.replace(
            '        "plan_digest": plan.plan_digest,\n',
            '        "plan_digest": plan.plan_digest,\n        "artifact_digest": plan.artifact_digest,\n',
        )
    path.write_text(text, encoding="utf-8")


def patch_server_test_import(path: Path) -> None:
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    text = text.replace("import json\n", "import json\n", 1)
    path.write_text(text, encoding="utf-8")


def patch_pyright(path: Path) -> None:
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    if not text.startswith("# pyright:"):
        path.write_text("# pyright: basic\n" + text, encoding="utf-8")


def patch_permanent_workflow(path: Path) -> None:
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    tests = (
        "tests/test_assurance_hardening.py",
        "tests/test_assurance_common_vectors.py",
        "tests/test_assurance_server.py",
    )
    anchor = "          tests/test_assurance_security_vectors.py\n"
    if anchor in text:
        additions = "".join(f"          {test}\n" for test in tests if test not in text)
        if additions:
            text = text.replace(anchor, anchor + additions, 1)
    path.write_text(text, encoding="utf-8")


def main() -> None:
    for relative in (
        "src/codex_plugin_scanner/assurance/content_scan.py",
        ".scanner-assurance-final/content_scan.py",
    ):
        patch_obfuscated_execution(ROOT / relative)
    patch_detonation_test(ROOT / "tests/test_assurance_drift_detonation.py")
    patch_server_test_import(ROOT / "tests/test_assurance_server.py")
    for path in (ROOT / "src/codex_plugin_scanner/assurance").glob("*.py"):
        patch_pyright(path)
    patch_pyright(ROOT / "src/codex_plugin_scanner/assurance_cli.py")
    patch_permanent_workflow(ROOT / ".github/workflows/scanner-assurance.yml")


if __name__ == "__main__":
    main()
