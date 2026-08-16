"""Apply the scanner assurance integration after source modules are staged.

This script is intentionally idempotent and is deleted after the feature commit is
materialized.  It avoids hand-editing generated lock data through the API.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if new in text:
        return
    if old not in text:
        raise RuntimeError(f"integration anchor not found in {path}: {old[:80]!r}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def patch_pyproject() -> None:
    path = ROOT / "pyproject.toml"
    text = path.read_text(encoding="utf-8")
    if "cryptography>=" not in text:
        anchor = "dependencies = [\n"
        if anchor not in text:
            raise RuntimeError("pyproject dependencies array not found")
        text = text.replace(anchor, anchor + '    "cryptography>=45.0.0",\n', 1)
    if "hol-guard-extension-security" not in text:
        anchor = "[project.scripts]\n"
        if anchor not in text:
            raise RuntimeError("[project.scripts] not found")
        text = text.replace(
            anchor,
            anchor + 'hol-guard-extension-security = "codex_plugin_scanner.assurance_cli:main"\n',
            1,
        )
    path.write_text(text, encoding="utf-8")


def patch_models() -> None:
    path = ROOT / "src/codex_plugin_scanner/models.py"
    replace_once(
        path,
        "    packages: tuple[PackageSummary, ...] = ()\n",
        "    packages: tuple[PackageSummary, ...] = ()\n    assurance: dict[str, object] | None = None\n",
    )


def patch_reporting() -> None:
    path = ROOT / "src/codex_plugin_scanner/reporting.py"
    replace_once(
        path,
        '        "trust": _serialize_trust(result),\n',
        '        "trust": _serialize_trust(result),\n        "assurance": result.assurance,\n',
    )
    text = path.read_text(encoding="utf-8")
    trust_line = '        f"- Trust: **{result.trust_report.total if result.trust_report else 0.0}/100**",\n'
    expanded = trust_line + (
        '        f"- Assurance decision: **{(result.assurance or {}).get(\'decision\', {}).get(\'disposition\', \'unknown\')}**",\n'
        '        f"- Coverage: **{(result.assurance or {}).get(\'coverage\', {}).get(\'state\', \'unknown\')}**",\n'
        '        f"- Assurance level: **{(result.assurance or {}).get(\'assurance_level\', \'unknown\')}**",\n'
    )
    if expanded not in text:
        if trust_line not in text:
            raise RuntimeError("reporting markdown trust anchor not found")
        text = text.replace(trust_line, expanded, 1)
    path.write_text(text, encoding="utf-8")


def patch_scanner() -> None:
    path = ROOT / "src/codex_plugin_scanner/scanner.py"
    text = path.read_text(encoding="utf-8")
    marker = "# Assurance wrapper: layered extension evidence"
    if marker in text:
        return
    wrapper = r'''

# Assurance wrapper: layered extension evidence
_scan_plugin_without_assurance = scan_plugin


def scan_plugin(plugin_dir: str | Path, options: ScanOptions | None = None) -> ScanResult:
    """Scan an extension and attach independent, limitation-aware assurance evidence."""

    import os

    result = _scan_plugin_without_assurance(plugin_dir, options)
    if os.environ.get("HOL_GUARD_ASSURANCE_MODE", "on").strip().lower() in {"0", "false", "off", "no"}:
        return result
    try:
        from .assurance.orchestrator import AssuranceOptions, scan_extension_assurance

        profile = os.environ.get("HOL_GUARD_ASSURANCE_PROFILE", "balanced").strip() or "balanced"
        assurance = scan_extension_assurance(
            Path(plugin_dir),
            AssuranceOptions(profile=profile),
        ).to_payload()
    except Exception as exc:  # fail closed without hiding the legacy scan result
        assurance = {
            "schema_version": "hol-guard.assurance-report.v1",
            "assurance_level": "static",
            "coverage": {"state": "error", "limitations": ["assurance scan failed"]},
            "decision": {
                "disposition": "error",
                "reason": f"assurance scan failed: {type(exc).__name__}",
                "required_actions": ["rerun the assurance scanner and review the failure"],
            },
            "findings": [],
            "layers": [],
        }
    return replace(result, assurance=assurance)
'''
    path.write_text(text.rstrip() + wrapper + "\n", encoding="utf-8")


def patch_commands() -> None:
    path = ROOT / "src/codex_plugin_scanner/_scanner_commands.py"
    text = path.read_text(encoding="utf-8")
    anchor = "    if not policy_eval.policy_pass:\n"
    block = '''    assurance_decision = (
        result.assurance.get("decision", {}).get("disposition")
        if isinstance(result.assurance, dict)
        else None
    )
    if assurance_decision in {"block", "error"}:
        print(f'Assurance decision "{assurance_decision}" blocked the scan.', file=sys.stderr)
        emit_hint("inspect the assurance evidence, coverage gaps, and required_actions before installation.")
        return 1
'''
    if block not in text:
        if anchor not in text:
            raise RuntimeError("scanner command policy anchor not found")
        text = text.replace(anchor, block + anchor, 1)
    submit_anchor = "    if result.score < min_score or not policy_eval.policy_pass or not verification.verify_pass:\n"
    submit_replacement = '''    assurance_decision = (
        result.assurance.get("decision", {}).get("disposition")
        if isinstance(result.assurance, dict)
        else None
    )
    if (
        result.score < min_score
        or not policy_eval.policy_pass
        or not verification.verify_pass
        or assurance_decision in {"review", "block", "error"}
    ):
'''
    if submit_replacement not in text:
        if submit_anchor not in text:
            raise RuntimeError("submission gate anchor not found")
        text = text.replace(submit_anchor, submit_replacement, 1)
    path.write_text(text, encoding="utf-8")


def patch_quality_artifact() -> None:
    path = ROOT / "src/codex_plugin_scanner/quality_artifact.py"
    text = path.read_text(encoding="utf-8")
    anchor = '        "scan": {\n'
    if '        "assurance": scan_result.assurance,\n' not in text:
        if anchor not in text:
            raise RuntimeError("quality artifact scan anchor not found")
        text = text.replace(anchor, '        "assurance": scan_result.assurance,\n' + anchor, 1)
    path.write_text(text, encoding="utf-8")


def patch_orchestrator_lint() -> None:
    path = ROOT / "src/codex_plugin_scanner/assurance/orchestrator.py"
    text = path.read_text(encoding="utf-8")
    text = text.replace("from dataclasses import dataclass, replace\n", "from dataclasses import dataclass\n")
    text = text.replace("from .detonation import DetonationPlan, validate_observation\n", "from .detonation import validate_observation\n")
    path.write_text(text, encoding="utf-8")


def main() -> None:
    patch_pyproject()
    patch_models()
    patch_reporting()
    patch_scanner()
    patch_commands()
    patch_quality_artifact()
    patch_orchestrator_lint()


if __name__ == "__main__":
    main()
