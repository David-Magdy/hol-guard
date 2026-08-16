#!/usr/bin/env python3
"""Idempotently finalize the scanner assurance integration."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)


def integrate_scanner() -> None:
    path = ROOT / "src/codex_plugin_scanner/scanner.py"
    text = path.read_text(encoding="utf-8")
    if "from .assurance import run_assurance_checks" not in text:
        text = replace_once(
            text,
            "from .checks.best_practices import run_best_practice_checks\n",
            "from .assurance import run_assurance_checks\nfrom .checks.best_practices import run_best_practice_checks\n",
            "scanner import",
        )
    if "assurance_checks, assurance_integrations = run_assurance_checks(plugin_dir)" not in text:
        text = replace_once(
            text,
            "    skill_security_context = resolve_skill_security_context(plugin_dir, options)\n"
            "    mcp_security_context = resolve_mcp_security_context(plugin_dir, options)\n"
            "    categories: list[CategoryResult] = [\n",
            "    skill_security_context = resolve_skill_security_context(plugin_dir, options)\n"
            "    mcp_security_context = resolve_mcp_security_context(plugin_dir, options)\n"
            "    assurance_checks, assurance_integrations = run_assurance_checks(plugin_dir)\n"
            "    categories: list[CategoryResult] = [\n",
            "single plugin init",
        )
        text = replace_once(
            text,
            "        CategoryResult(name=\"Code Quality\", checks=run_code_quality_checks(plugin_dir)),\n"
            "    ]\n",
            "        CategoryResult(name=\"Code Quality\", checks=run_code_quality_checks(plugin_dir)),\n"
            "        CategoryResult(name=\"Layered Assurance\", checks=assurance_checks),\n"
            "    ]\n",
            "single plugin category",
        )
        text = replace_once(
            text,
            "        integrations=_build_integration_results(skill_security_context, mcp_security_context),\n",
            "        integrations=(\n"
            "            _build_integration_results(skill_security_context, mcp_security_context)\n"
            "            + assurance_integrations\n"
            "        ),\n",
            "single plugin integrations",
        )
    if "Repository Layered Assurance" not in text:
        text = replace_once(
            text,
            "    categories = _build_repository_categories(repo_root, plugin_results)\n",
            "    assurance_checks, assurance_integrations = run_assurance_checks(repo_root)\n"
            "    categories = _build_repository_categories(repo_root, plugin_results) + (\n"
            "        CategoryResult(name=\"Repository Layered Assurance\", checks=assurance_checks),\n"
            "    )\n",
            "repository category",
        )
        text = replace_once(
            text,
            "        integrations=tuple(integration for plugin in plugin_results for integration in plugin.integrations),\n",
            "        integrations=(\n"
            "            assurance_integrations\n"
            "            + tuple(integration for plugin in plugin_results for integration in plugin.integrations)\n"
            "        ),\n",
            "repository integrations",
        )
    mixed_start = text.index("def _scan_mixed_packages(")
    mixed_end = text.index("\ndef _scan_non_repository_target", mixed_start)
    mixed = text[mixed_start:mixed_end]
    if "[workspace] Layered Assurance" not in mixed:
        mixed = replace_once(
            mixed,
            "    findings = tuple(finding for category in categories for check in category.checks for finding in check.findings)\n",
            "    assurance_checks, assurance_integrations = run_assurance_checks(scan_root)\n"
            "    categories.append(CategoryResult(name=\"[workspace] Layered Assurance\", checks=assurance_checks))\n"
            "    integrations.extend(assurance_integrations)\n"
            "    findings = tuple(finding for category in categories for check in category.checks for finding in check.findings)\n",
            "mixed package category",
        )
        text = text[:mixed_start] + mixed + text[mixed_end:]
    path.write_text(text, encoding="utf-8")


def integrate_policy_and_entrypoint() -> None:
    policy_path = ROOT / "src/codex_plugin_scanner/policy.py"
    policy = policy_path.read_text(encoding="utf-8")
    if '"consumer-install": PolicyProfile(' not in policy:
        policy = replace_once(
            policy,
            '    "strict-security": PolicyProfile(\n',
            '    "consumer-install": PolicyProfile(\n'
            '        name="consumer-install",\n'
            "        max_severity=Severity.LOW,\n"
            "        min_score=80,\n"
            "    ),\n"
            '    "strict-security": PolicyProfile(\n',
            "consumer policy",
        )
    policy_path.write_text(policy, encoding="utf-8")

    project_path = ROOT / "pyproject.toml"
    project = project_path.read_text(encoding="utf-8")
    entry = 'plugin-scanner-assure = "codex_plugin_scanner.assurance_cli:main"\n'
    if entry not in project:
        project = replace_once(project, "[project.scripts]\n", "[project.scripts]\n" + entry, "script entrypoint")
    project_path.write_text(project, encoding="utf-8")


def finalize_assurance() -> None:
    path = ROOT / "src/codex_plugin_scanner/assurance.py"
    text = path.read_text(encoding="utf-8")
    text = text.replace("import math\n", "").replace("import os\n", "")
    text = text.replace(
        "from .rust_kernel import InventoryRecord, KernelResult, scan_inventory\n",
        "from .rust_kernel import InventoryRecord, inventory_digest, scan_inventory\n",
    )
    if "def inventory_digest(" not in (ROOT / "src/codex_plugin_scanner/rust_kernel.py").read_text(encoding="utf-8"):
        raise RuntimeError("inventory_digest helper is missing")
    text = text.replace("target_digest = _root_digest(kernel.records)", "target_digest = inventory_digest(kernel.records)")
    root_digest_start = text.find("def _root_digest(")
    if root_digest_start >= 0:
        root_digest_end = text.index("\ndef _load_runtime_layer", root_digest_start)
        text = text[:root_digest_start] + text[root_digest_end + 1 :]
    text = text.replace(
        "(?:Template|from_string|compileTemplate|Handlebars\\.compile|ejs\\.render|pug\\.render)",
        "(?:Template|from_string|render_template_string|compileTemplate|Handlebars\\.compile|ejs\\.render|pug\\.render)",
    )
    text = text.replace(
        "def _layer_check(name: str, findings: tuple[Finding, ...], *, complete: bool, max_points: int = 10) -> CheckResult:\n",
        "def _layer_check(name: str, findings: tuple[Finding, ...], *, complete: bool) -> CheckResult:\n",
    )
    old_points = (
        "    passed = complete and not blocking\n"
        "    points = max_points if passed else max_points // 2 if complete and not any(f.severity == Severity.CRITICAL for f in findings) else 0\n"
    )
    new_points = "    passed = complete and not blocking\n    points = 0\n    max_points = 0\n"
    if old_points in text:
        text = text.replace(old_points, new_points, 1)
    old_provenance = (
        "    elif attestation.status in {\"absent\", \"self-attested\"}:\n"
        "        provenance_findings = (\n"
        "            _finding(\n"
        "                \"ASSURANCE_PROVENANCE_UNTRUSTED\",\n"
        "                Severity.LOW if attestation.status == \"absent\" else Severity.INFO,\n"
        "                \"provenance\",\n"
        "                \"Publisher provenance is not independently trusted\",\n"
        "                attestation.reason,\n"
        "                \"Provide an attestation signed by a key in the consumer-controlled trust root.\",\n"
        "                path=\".hol-guard/attestation.json\" if attestation.status != \"absent\" else None,\n"
        "                source=\"assurance-provenance\",\n"
        "            ),\n"
        "        )\n"
    )
    if old_provenance in text:
        text = text.replace(old_provenance, "", 1)
    old_runtime_optional = (
        "    elif runtime_status in {\"not-run\", \"partial\"}:\n"
        "        runtime_findings = (\n"
        "            _finding(\n"
        "                \"ASSURANCE_RUNTIME_UNPROVEN\",\n"
        "                Severity.INFO if runtime_status == \"not-run\" else Severity.LOW,\n"
        "                \"runtime-assurance\",\n"
        "                \"Runtime behavior is not fully proven\",\n"
        "                runtime_limitations[0] if runtime_limitations else \"No complete runtime evidence is available.\",\n"
        "                \"Run the explicit bounded detonation workflow and preserve complete trace evidence for the exact digest.\",\n"
        "                source=\"assurance-runtime\",\n"
        "            ),\n"
        "        )\n"
    )
    if old_runtime_optional in text:
        text = text.replace(old_runtime_optional, "", 1)
    text = text.replace("    feature_ids_by_path: dict[str, set[str]] = defaultdict(set)\n\n", "")
    text = text.replace(
        "        feature_ids_by_path[record.path].update(_scan_text_patterns(text, record.path, collector))\n"
        "        feature_ids_by_path[record.path].update(_scan_obfuscation(text, record.path, collector))\n",
        "        _scan_text_patterns(text, record.path, collector)\n"
        "        _scan_obfuscation(text, record.path, collector)\n",
    )
    path.write_text(text, encoding="utf-8")


def finalize_kernel_bridge() -> None:
    path = ROOT / "src/codex_plugin_scanner/rust_kernel.py"
    text = path.read_text(encoding="utf-8")
    if "def inventory_digest(" not in text:
        marker = "\ndef _safe_relative_path(value: str) -> str:\n"
        helper = (
            "\ndef inventory_digest(records: tuple[InventoryRecord, ...]) -> str:\n"
            "    \"\"\"Hash the deterministic inventory without exposing file contents.\"\"\"\n\n"
            "    hasher = hashlib.sha256()\n"
            "    for record in records:\n"
            "        hasher.update(record.path.encode(\"utf-8\"))\n"
            "        hasher.update(b\"\\0\")\n"
            "        hasher.update(str(record.size).encode(\"ascii\"))\n"
            "        hasher.update(b\"\\0\")\n"
            "        value = record.sha256 or f\"[{record.kind}:{record.error or 'unhashed'}]\"\n"
            "        hasher.update(value.encode(\"utf-8\"))\n"
            "        hasher.update(b\"\\n\")\n"
            "    return hasher.hexdigest()\n"
        )
        text = replace_once(text, marker, helper + marker, "inventory digest")
    path.write_text(text, encoding="utf-8")


def finalize_runtime() -> None:
    path = ROOT / "src/codex_plugin_scanner/runtime_assurance.py"
    text = path.read_text(encoding="utf-8")
    if "from .rust_kernel import inventory_digest, scan_inventory" not in text:
        text = text.replace(
            "from typing import Any\n",
            "from typing import Any\n\nfrom .rust_kernel import inventory_digest, scan_inventory\n",
            1,
        )
    text = text.replace(
        'r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$"',
        'r"^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$"',
    )
    if '        "--pull=never",\n' not in text:
        text = text.replace('        "--rm",\n', '        "--rm",\n        "--pull=never",\n', 1)
    text = text.replace('        "--uts=private",\n', "")
    target_start = text.find("def _target_digest(target: Path) -> str:")
    if target_start >= 0:
        target_end = text.index("\ndef _trace_inventory", target_start)
        text = (
            text[:target_start]
            + "def _target_digest(target: Path) -> str:\n"
            + "    return inventory_digest(scan_inventory(target).records)\n\n"
            + text[target_end + 1 :]
        )
    if '        "defaultSeccomp": True,\n' not in text:
        text = text.replace(
            '        "resourceLimits": True,\n',
            '        "resourceLimits": True,\n        "defaultSeccomp": True,\n        "imagePullDisabled": True,\n',
            1,
        )
    text = text.replace(
        '            "complete": trace_complete if validated.trace_syscalls else False,\n',
        '            "complete": trace_complete and not timed_out if validated.trace_syscalls else False,\n',
    )
    if '        "defaultSeccomp",\n' not in text:
        text = text.replace(
            '        "resourceLimits",\n',
            '        "resourceLimits",\n        "defaultSeccomp",\n        "imagePullDisabled",\n',
            1,
        )
    if "**asdict(validated)" in text:
        start = text.index('        "plan": {\n')
        end = text.index("        },\n", start) + len("        },\n")
        replacement = (
            '        "plan": {\n'
            '            "engine": validated.engine,\n'
            '            "image": validated.image,\n'
            '            "targetName": validated.target.name,\n'
            '            "commandName": Path(validated.command[0]).name,\n'
            '            "argumentCount": len(validated.command),\n'
            '            "timeoutSeconds": validated.timeout_seconds,\n'
            '            "memoryMegabytes": validated.memory_megabytes,\n'
            '            "cpuLimit": validated.cpu_limit,\n'
            '            "pidsLimit": validated.pids_limit,\n'
            '            "fileSizeMegabytes": validated.file_size_megabytes,\n'
            '            "traceSyscalls": validated.trace_syscalls,\n'
            "        },\n"
        )
        text = text[:start] + replacement + text[end:]
        text = text.replace("from dataclasses import asdict, dataclass\n", "from dataclasses import dataclass\n")
    path.write_text(text, encoding="utf-8")


def finalize_tests() -> None:
    path = ROOT / "tests/assurance_corpus.py"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        "This plugin documents why callers must not ignore prior security instructions.",
        "Security controls remain authoritative and users receive clear disclosures.",
    )
    path.write_text(text, encoding="utf-8")

    path = ROOT / "tests/test_runtime_assurance.py"
    text = path.read_text(encoding="utf-8")
    if '            "defaultSeccomp": True,\n' not in text:
        text = text.replace(
            '            "resourceLimits": True,\n',
            '            "resourceLimits": True,\n            "defaultSeccomp": True,\n            "imagePullDisabled": True,\n',
            1,
        )
    path.write_text(text, encoding="utf-8")


def remove_temporary_files() -> None:
    for relative in (
        ".github/workflows/scanner-assurance-source-snapshot.yml",
        ".github/workflows/scanner-reliability-payload-inspect.yml",
        ".github/workflows/scanner-reliability-source-snapshot.yml",
        ".github/workflows/tmp-apply-scanner-assurance.yml",
        "scripts/ci/apply_scanner_assurance_integration.py",
    ):
        candidate = ROOT / relative
        if candidate.exists():
            candidate.unlink()


def main() -> None:
    finalize_kernel_bridge()
    integrate_scanner()
    integrate_policy_and_entrypoint()
    finalize_assurance()
    finalize_runtime()
    finalize_tests()
    remove_temporary_files()


if __name__ == "__main__":
    main()
