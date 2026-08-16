"""Install the final assurance implementation and integrate it with HOL Guard."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OVERLAY = ROOT / ".scanner-assurance-final"
ASSURANCE = ROOT / "src/codex_plugin_scanner/assurance"


ASSURANCE_MODULES = (
    "__init__.py",
    "archive_scan.py",
    "content_scan.py",
    "dependency_scan.py",
    "detonation.py",
    "drift.py",
    "evidence.py",
    "ingestion.py",
    "inventory.py",
    "limits.py",
    "models.py",
    "native_scan.py",
    "orchestrator.py",
    "policy.py",
    "provenance.py",
    "server.py",
    "surface_scan.py",
    "upload.py",
)


def main() -> None:
    install_overlay()
    patch_rust_source()
    patch_pyproject()
    patch_core_models()
    patch_reporting()
    patch_cli_ui()
    patch_scanner()
    patch_scanner_commands()
    patch_quality_artifact()
    patch_core_schemas()
    patch_tests()
    patch_permanent_workflow()
    write_documentation()


def install_overlay() -> None:
    ASSURANCE.mkdir(parents=True, exist_ok=True)
    for name in ASSURANCE_MODULES:
        source = OVERLAY / name
        if not source.is_file():
            raise RuntimeError(f"missing final assurance overlay: {name}")
        shutil.copyfile(source, ASSURANCE / name)
    shutil.copyfile(OVERLAY / "assurance_cli.py", ROOT / "src/codex_plugin_scanner/assurance_cli.py")
    rust_root = ROOT / "rust/scanner-engine"
    (rust_root / "src").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(OVERLAY / "Cargo.toml", rust_root / "Cargo.toml")
    shutil.copyfile(OVERLAY / "main.rs", rust_root / "src/main.rs")
    schema_map = {
        "assurance-report.v1.json": "assurance-report.v1.json",
        "extension-security-evidence.v1.json": "extension-security-evidence.v1.json",
        "assurance-policy.v1.json": "assurance-policy.v1.json",
        "detonation-plan.v1.json": "detonation-plan.v1.json",
        "detonation-observation.v1.json": "detonation-observation.v1.json",
    }
    schemas = ROOT / "schemas"
    schemas.mkdir(exist_ok=True)
    for source_name, destination_name in schema_map.items():
        shutil.copyfile(OVERLAY / source_name, schemas / destination_name)


def patch_rust_source() -> None:
    path = ROOT / "rust/scanner-engine/src/main.rs"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        '    if slice(data, pe_offset, 4) != Some(b"PE\\0\\0") {',
        '    if !slice(data, pe_offset, 4).is_some_and(|value| value == b"PE\\0\\0") {',
    )
    old = '''        if matches!(\n            magic,\n            b"\\xfe\\xed\\xfa\\xce"\n                | b"\\xce\\xfa\\xed\\xfe"\n                | b"\\xfe\\xed\\xfa\\xcf"\n                | b"\\xcf\\xfa\\xed\\xfe"\n                | b"\\xca\\xfe\\xba\\xbe"\n                | b"\\xbe\\xba\\xfe\\xca"\n                | b"\\xca\\xfe\\xba\\xbf"\n                | b"\\xbf\\xba\\xfe\\xca"\n        ) {'''
    new = '''        if magic == b"\\xfe\\xed\\xfa\\xce"\n            || magic == b"\\xce\\xfa\\xed\\xfe"\n            || magic == b"\\xfe\\xed\\xfa\\xcf"\n            || magic == b"\\xcf\\xfa\\xed\\xfe"\n            || magic == b"\\xca\\xfe\\xba\\xbe"\n            || magic == b"\\xbe\\xba\\xfe\\xca"\n            || magic == b"\\xca\\xfe\\xba\\xbf"\n            || magic == b"\\xbf\\xba\\xfe\\xca"\n        {'''
    text = text.replace(old, new)
    text = text.replace(
        '    let little = matches!(magic, b"\\xce\\xfa\\xed\\xfe" | b"\\xcf\\xfa\\xed\\xfe" | b"\\xbe\\xba\\xfe\\xca" | b"\\xbf\\xba\\xfe\\xca");',
        '    let little = magic == b"\\xce\\xfa\\xed\\xfe" || magic == b"\\xcf\\xfa\\xed\\xfe" || magic == b"\\xbe\\xba\\xfe\\xca" || magic == b"\\xbf\\xba\\xfe\\xca";',
    )
    text = text.replace(
        '    let is_64 = matches!(magic, b"\\xfe\\xed\\xfa\\xcf" | b"\\xcf\\xfa\\xed\\xfe" | b"\\xca\\xfe\\xba\\xbf" | b"\\xbf\\xba\\xfe\\xca");',
        '    let is_64 = magic == b"\\xfe\\xed\\xfa\\xcf" || magic == b"\\xcf\\xfa\\xed\\xfe" || magic == b"\\xca\\xfe\\xba\\xbf" || magic == b"\\xbf\\xba\\xfe\\xca";',
    )
    text = text.replace(
        '    let is_fat = matches!(magic, b"\\xca\\xfe\\xba\\xbe" | b"\\xbe\\xba\\xfe\\xca" | b"\\xca\\xfe\\xba\\xbf" | b"\\xbf\\xba\\xfe\\xca");',
        '    let is_fat = magic == b"\\xca\\xfe\\xba\\xbe" || magic == b"\\xbe\\xba\\xfe\\xca" || magic == b"\\xca\\xfe\\xba\\xbf" || magic == b"\\xbf\\xba\\xfe\\xca";',
    )
    path.write_text(text, encoding="utf-8")

    native = ASSURANCE / "native_scan.py"
    native_text = native.read_text(encoding="utf-8")
    native_text = native_text.replace(
        "    digest = _hash_file(path)\n    engine = _find_engine()",
        '''    try:\n        digest = _hash_file(path)\n    except OSError:\n        return _error_result(display_path, "Native artifact changed or could not be hashed.")\n    engine = _find_engine()''',
    )
    native.write_text(native_text, encoding="utf-8")


def patch_pyproject() -> None:
    path = ROOT / "pyproject.toml"
    text = path.read_text(encoding="utf-8")
    dependencies: list[str] = []
    if "cryptography>=" not in text:
        dependencies.append('    "cryptography>=45.0.0",')
    if "tomli>=" not in text:
        dependencies.append('    "tomli>=2.0.1; python_version < \'3.11\'",')
    if dependencies:
        text = text.replace("dependencies = [\n", "dependencies = [\n" + "\n".join(dependencies) + "\n", 1)
    if "[project.scripts]" not in text:
        text += "\n[project.scripts]\n"
    if "hol-guard-extension-security" not in text:
        text = text.replace(
            "[project.scripts]\n",
            '[project.scripts]\nhol-guard-extension-security = "codex_plugin_scanner.assurance_cli:main"\n',
            1,
        )
    path.write_text(text, encoding="utf-8")


def patch_core_models() -> None:
    path = ROOT / "src/codex_plugin_scanner/models.py"
    text = path.read_text(encoding="utf-8")
    if "assurance: dict[str, object] | None" not in text:
        anchor = "    packages: tuple[PackageSummary, ...] = ()\n"
        if anchor not in text:
            raise RuntimeError("ScanResult package field anchor not found")
        text = text.replace(
            anchor,
            anchor + "    assurance: dict[str, object] | None = None\n",
            1,
        )
    path.write_text(text, encoding="utf-8")


def patch_reporting() -> None:
    path = ROOT / "src/codex_plugin_scanner/reporting.py"
    text = path.read_text(encoding="utf-8")
    marker = "# Layered assurance reporting wrapper"
    if marker in text:
        text = text[: text.index(marker)].rstrip() + "\n"
    text += '''\n\n# Layered assurance reporting wrapper\n_build_json_payload_without_assurance = build_json_payload\n_format_markdown_without_assurance = format_markdown\n\n\ndef build_json_payload(\n    result: ScanResult,\n    *,\n    profile: str = "default",\n    policy_pass: bool = True,\n    verify_pass: bool = True,\n    raw_score: int | None = None,\n    effective_score: int | None = None,\n) -> dict[str, object]:\n    payload = _build_json_payload_without_assurance(\n        result,\n        profile=profile,\n        policy_pass=policy_pass,\n        verify_pass=verify_pass,\n        raw_score=raw_score,\n        effective_score=effective_score,\n    )\n    payload["assurance"] = result.assurance\n    return payload\n\n\ndef format_markdown(result: ScanResult) -> str:\n    rendered = _format_markdown_without_assurance(result)\n    assurance = result.assurance\n    if not isinstance(assurance, dict):\n        return rendered\n    coverage = assurance.get("coverage")\n    decision = assurance.get("decision")\n    lines = [rendered, "", "## Layered Assurance", ""]\n    if isinstance(decision, dict):\n        lines.append(f"- Disposition: **{decision.get('disposition', 'unknown')}**")\n        lines.append(f"- Reason: {decision.get('reason', 'not available')}")\n    if isinstance(coverage, dict):\n        lines.append(f"- Coverage: **{coverage.get('state', 'unknown')}**")\n        limitations = coverage.get("limitations")\n        if isinstance(limitations, list):\n            lines.extend(f"- Limitation: {item}" for item in limitations if isinstance(item, str))\n    return "\\n".join(lines)\n'''
    path.write_text(text, encoding="utf-8")


def patch_cli_ui() -> None:
    path = ROOT / "src/codex_plugin_scanner/cli_ui.py"
    text = path.read_text(encoding="utf-8")
    marker = "# Layered assurance plain-text wrapper"
    if marker in text:
        text = text[: text.index(marker)].rstrip() + "\n"
    text += '''\n\n# Layered assurance plain-text wrapper\n_build_plain_text_without_assurance = build_plain_text\n\n\ndef build_plain_text(result):\n    rendered = _build_plain_text_without_assurance(result)\n    assurance = getattr(result, "assurance", None)\n    if not isinstance(assurance, dict):\n        return rendered\n    coverage = assurance.get("coverage")\n    decision = assurance.get("decision")\n    lines = [rendered, "", "Layered assurance"]\n    if isinstance(decision, dict):\n        lines.append(f"  Disposition: {decision.get('disposition', 'unknown')}")\n        lines.append(f"  Reason: {decision.get('reason', 'not available')}")\n    if isinstance(coverage, dict):\n        lines.append(f"  Coverage: {coverage.get('state', 'unknown')}")\n        limitations = coverage.get("limitations")\n        if isinstance(limitations, list):\n            for item in limitations:\n                if isinstance(item, str):\n                    lines.append(f"  Limitation: {item}")\n    return "\\n".join(lines)\n'''
    path.write_text(text, encoding="utf-8")


def patch_scanner() -> None:
    path = ROOT / "src/codex_plugin_scanner/scanner.py"
    text = path.read_text(encoding="utf-8")
    markers = (
        "# Assurance wrapper:",
        "# Layered extension assurance wrapper",
        "_scan_plugin_without_assurance = scan_plugin",
        "_scan_plugin_core_without_assurance = scan_plugin",
    )
    positions = [text.find(marker) for marker in markers if marker in text]
    if positions:
        text = text[: min(position for position in positions if position >= 0)].rstrip() + "\n"
    text += '''\n\n# Layered extension assurance wrapper\n_scan_plugin_core_without_assurance = scan_plugin\n\n\ndef scan_plugin(plugin_dir: str | Path, options: ScanOptions | None = None) -> ScanResult:\n    """Run the compatibility scanner and attach independent assurance evidence."""\n\n    import os\n\n    result = _scan_plugin_core_without_assurance(plugin_dir, options)\n    if os.environ.get("HOL_GUARD_ASSURANCE_MODE", "on").strip().lower() in {\n        "0",\n        "false",\n        "off",\n        "no",\n    }:\n        return result\n    try:\n        from .assurance.orchestrator import AssuranceOptions, scan_extension_assurance\n\n        profile = os.environ.get("HOL_GUARD_ASSURANCE_PROFILE", "balanced").strip() or "balanced"\n        assurance = scan_extension_assurance(\n            Path(plugin_dir),\n            AssuranceOptions(profile=profile),\n        ).to_payload()\n    except Exception as exc:\n        assurance = {\n            "schema_version": "hol-guard.assurance-report.v1",\n            "assurance_level": "static",\n            "coverage": {\n                "state": "error",\n                "limitations": [\n                    "The layered assurance scan failed; a compatibility scan is not a substitute."\n                ],\n            },\n            "decision": {\n                "disposition": "error",\n                "reason": f"layered assurance failed: {type(exc).__name__}",\n                "required_actions": [\n                    "rerun hol-guard-extension-security and review the failure"\n                ],\n            },\n            "findings": [],\n            "layers": [],\n        }\n    return replace(result, assurance=assurance)\n'''
    path.write_text(text, encoding="utf-8")


def patch_scanner_commands() -> None:
    path = ROOT / "src/codex_plugin_scanner/_scanner_commands.py"
    text = path.read_text(encoding="utf-8")
    helper_marker = "def _assurance_disposition"
    if helper_marker not in text:
        insert = '''\n\ndef _assurance_disposition(result) -> str | None:\n    assurance = getattr(result, "assurance", None)\n    if not isinstance(assurance, dict):\n        return None\n    decision = assurance.get("decision")\n    if not isinstance(decision, dict):\n        return "error"\n    disposition = decision.get("disposition")\n    return disposition if isinstance(disposition, str) else "error"\n\n'''
        anchor = "RuleSpecLookup = Callable[[str], RuleSpec | None]\n"
        if anchor not in text:
            raise RuntimeError("scanner command helper anchor not found")
        text = text.replace(anchor, anchor + insert, 1)
    text = _insert_before_final_return(
        text,
        "run_scan",
        "run_lint",
        '''    assurance_disposition = _assurance_disposition(result)\n    if assurance_disposition in {"block", "error"}:\n        print(\n            f'Layered assurance produced a blocking disposition: {assurance_disposition}.',\n            file=sys.stderr,\n        )\n        return 1\n''',
        marker="Layered assurance produced a blocking disposition",
    )
    text = _insert_before_final_return_expression(
        text,
        "run_lint",
        "run_verify",
        '''    assurance_disposition = _assurance_disposition(result)\n    if assurance_disposition in {"block", "error"}:\n        return 1\n''',
        marker="assurance_disposition = _assurance_disposition(result)",
    )
    start, end = _function_bounds(text, "run_submit", "run_doctor")
    block = text[start:end]
    if "Submission blocked by layered assurance" not in block:
        anchor = "    verification = verify_plugin(resolved, online=args.online)\n"
        if anchor not in block:
            raise RuntimeError("submission assurance anchor not found")
        block = block.replace(
            anchor,
            anchor
            + '''    assurance_disposition = _assurance_disposition(result)\n    if assurance_disposition not in {"allow", "warn"}:\n        print(\n            "Submission blocked by layered assurance: only allow/warn evidence is publishable.",\n            file=sys.stderr,\n        )\n        return 1\n''',
            1,
        )
        text = text[:start] + block + text[end:]
    path.write_text(text, encoding="utf-8")


def patch_quality_artifact() -> None:
    path = ROOT / "src/codex_plugin_scanner/quality_artifact.py"
    text = path.read_text(encoding="utf-8")
    marker = "# Layered assurance quality-artifact wrapper"
    if marker in text:
        text = text[: text.index(marker)].rstrip() + "\n"
    text += '''\n\n# Layered assurance quality-artifact wrapper\n_build_quality_artifact_without_assurance = build_quality_artifact\n\n\ndef build_quality_artifact(\n    plugin_dir: Path,\n    scan_result: ScanResult,\n    verification: VerificationResult,\n    policy: PolicyEvaluation,\n    profile: str,\n    *,\n    raw_score: int | None = None,\n) -> dict[str, object]:\n    payload = _build_quality_artifact_without_assurance(\n        plugin_dir,\n        scan_result,\n        verification,\n        policy,\n        profile,\n        raw_score=raw_score,\n    )\n    payload["assurance"] = scan_result.assurance\n    return payload\n'''
    path.write_text(text, encoding="utf-8")


def patch_core_schemas() -> None:
    for relative in ("schemas/scan-result.v1.json", "schemas/plugin-quality.v1.json"):
        path = ROOT / relative
        if not path.is_file():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        properties = payload.setdefault("properties", {})
        if not isinstance(properties, dict):
            raise RuntimeError(f"schema properties are malformed: {relative}")
        properties["assurance"] = {"type": ["object", "null"]}
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def patch_tests() -> None:
    path = ROOT / "tests/test_assurance_drift_detonation.py"
    if path.is_file():
        text = path.read_text(encoding="utf-8")
        if '"artifact_digest": plan.artifact_digest' not in text:
            text = text.replace(
                '        "plan_digest": plan.plan_digest,\n',
                '        "plan_digest": plan.plan_digest,\n        "artifact_digest": plan.artifact_digest,\n',
            )
        path.write_text(text, encoding="utf-8")


def patch_permanent_workflow() -> None:
    path = ROOT / ".github/workflows/scanner-assurance.yml"
    if not path.is_file():
        raise RuntimeError("permanent scanner assurance workflow is missing")
    text = path.read_text(encoding="utf-8")
    required_tests = (
        "tests/test_assurance_hardening.py",
        "tests/test_assurance_common_vectors.py",
        "tests/test_assurance_server.py",
    )
    anchor = "tests/test_assurance_security_vectors.py"
    if anchor in text:
        addition = "\n".join(f"          {test}" for test in required_tests)
        for test in required_tests:
            if test not in text:
                text = text.replace(f"          {anchor}\n", f"          {anchor}\n{addition}\n", 1)
                break
    path.write_text(text, encoding="utf-8")


def write_documentation() -> None:
    path = ROOT / "docs/ai-plugin-scanner/layered-assurance.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '''# Layered extension assurance\n\nHOL Guard separates five questions that a single static “safe” badge cannot answer:\n\n1. What direct risks were detected?\n2. What content was completely analyzed, partially analyzed, or opaque?\n3. Is the artifact bound to trusted provenance and the exact bytes that were reviewed?\n4. What security-relevant capabilities, dependencies, native code, MCP commands, and endpoints changed?\n5. What happened when a reviewed command was exercised inside a no-network, read-only, non-root sandbox?\n\n`hol-guard-extension-security scan` emits `hol-guard.assurance-report.v1`. The report always includes limitations. A clean static result is not proof of safety. Native parsing is structural analysis, not complete disassembly or reachability proof. Sandbox observations apply only to the exact artifact digest, plan, command, and environment that were exercised.\n\n## Consuming-side verification\n\nCloud and registry systems must validate the evidence digest and exact artifact binding, authenticate the tenant independently of the submitted body, enforce freshness and sequence monotonicity, recompute the managed policy decision, verify trusted DSSE signatures, quarantine blocking evidence, and expose only publishable evidence by default. `EvidenceStore` and `create_evidence_ingestion_app` implement this reference path.\n\n## Rust hot path\n\n`rust/scanner-engine` performs bounded PE, ELF, Mach-O, and WebAssembly parsing, complete artifact hashing, section entropy analysis, mitigation extraction, import/export enumeration where supported, and sensitive API indicators. The Python fallback is explicit, produces partial coverage, and cannot satisfy a managed policy that requires Rust for native artifacts.\n\n## Detonation\n\nPlans require immutable container image digests and exact extension artifact digests. Execution rehashes the artifact before launch, disables networking, uses a read-only root and extension mount, runs as a non-root user, drops every capability, enables `no-new-privileges`, and applies CPU, memory, process, file-descriptor, temporary-filesystem, output, and time limits. Observations bind both the plan digest and artifact digest.\n''',
        encoding="utf-8",
    )


def _function_bounds(text: str, name: str, next_name: str) -> tuple[int, int]:
    start = text.index(f"def {name}(")
    end = text.index(f"def {next_name}(", start)
    return start, end


def _insert_before_final_return(
    text: str,
    name: str,
    next_name: str,
    snippet: str,
    *,
    marker: str,
) -> str:
    start, end = _function_bounds(text, name, next_name)
    block = text[start:end]
    if marker in block:
        return text
    position = block.rfind("    return 0\n")
    if position < 0:
        raise RuntimeError(f"final return not found in {name}")
    block = block[:position] + snippet + block[position:]
    return text[:start] + block + text[end:]


def _insert_before_final_return_expression(
    text: str,
    name: str,
    next_name: str,
    snippet: str,
    *,
    marker: str,
) -> str:
    start, end = _function_bounds(text, name, next_name)
    block = text[start:end]
    if marker in block:
        return text
    matches = list(re.finditer(r"^    return 0 if .*? else 1\n", block, flags=re.MULTILINE))
    if not matches:
        raise RuntimeError(f"final return expression not found in {name}")
    position = matches[-1].start()
    block = block[:position] + snippet + block[position:]
    return text[:start] + block + text[end:]


if __name__ == "__main__":
    main()
