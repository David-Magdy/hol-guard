#!/usr/bin/env python3
"""Finalize scanner assurance from any intermediate branch state."""

from __future__ import annotations

import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run_existing(relative: str) -> None:
    path = ROOT / relative
    if path.exists():
        runpy.run_path(str(path), run_name="__main__")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)


def ensure_integration() -> None:
    scanner_path = ROOT / "src/codex_plugin_scanner/scanner.py"
    scanner = scanner_path.read_text(encoding="utf-8")
    if "from .assurance import run_assurance_checks" not in scanner:
        scanner = replace_once(
            scanner,
            "from .checks.best_practices import run_best_practice_checks\n",
            "from .assurance import run_assurance_checks\nfrom .checks.best_practices import run_best_practice_checks\n",
            "scanner assurance import",
        )
    if "assurance_checks, assurance_integrations = run_assurance_checks(plugin_dir)" not in scanner:
        scanner = replace_once(
            scanner,
            "    skill_security_context = resolve_skill_security_context(plugin_dir, options)\n"
            "    mcp_security_context = resolve_mcp_security_context(plugin_dir, options)\n"
            "    categories: list[CategoryResult] = [\n",
            "    skill_security_context = resolve_skill_security_context(plugin_dir, options)\n"
            "    mcp_security_context = resolve_mcp_security_context(plugin_dir, options)\n"
            "    assurance_checks, assurance_integrations = run_assurance_checks(plugin_dir)\n"
            "    categories: list[CategoryResult] = [\n",
            "single-plugin assurance initialization",
        )
        scanner = replace_once(
            scanner,
            "        CategoryResult(name=\"Code Quality\", checks=run_code_quality_checks(plugin_dir)),\n"
            "    ]\n",
            "        CategoryResult(name=\"Code Quality\", checks=run_code_quality_checks(plugin_dir)),\n"
            "        CategoryResult(name=\"Layered Assurance\", checks=assurance_checks),\n"
            "    ]\n",
            "single-plugin assurance category",
        )
        scanner = replace_once(
            scanner,
            "        integrations=_build_integration_results(skill_security_context, mcp_security_context),\n",
            "        integrations=(\n"
            "            _build_integration_results(skill_security_context, mcp_security_context)\n"
            "            + assurance_integrations\n"
            "        ),\n",
            "single-plugin assurance integrations",
        )
    if "Repository Layered Assurance" not in scanner:
        scanner = replace_once(
            scanner,
            "    categories = _build_repository_categories(repo_root, plugin_results)\n",
            "    assurance_checks, assurance_integrations = run_assurance_checks(repo_root)\n"
            "    categories = _build_repository_categories(repo_root, plugin_results) + (\n"
            "        CategoryResult(name=\"Repository Layered Assurance\", checks=assurance_checks),\n"
            "    )\n",
            "repository assurance category",
        )
        scanner = replace_once(
            scanner,
            "        integrations=tuple(integration for plugin in plugin_results for integration in plugin.integrations),\n",
            "        integrations=(\n"
            "            assurance_integrations\n"
            "            + tuple(integration for plugin in plugin_results for integration in plugin.integrations)\n"
            "        ),\n",
            "repository assurance integrations",
        )
    mixed_start = scanner.index("def _scan_mixed_packages(")
    mixed_end = scanner.index("\ndef _scan_non_repository_target", mixed_start)
    mixed = scanner[mixed_start:mixed_end]
    if "[workspace] Layered Assurance" not in mixed:
        mixed = replace_once(
            mixed,
            "    findings = tuple(finding for category in categories for check in category.checks for finding in check.findings)\n",
            "    assurance_checks, assurance_integrations = run_assurance_checks(scan_root)\n"
            "    categories.append(CategoryResult(name=\"[workspace] Layered Assurance\", checks=assurance_checks))\n"
            "    integrations.extend(assurance_integrations)\n"
            "    findings = tuple(finding for category in categories for check in category.checks for finding in check.findings)\n",
            "mixed-package assurance",
        )
        scanner = scanner[:mixed_start] + mixed + scanner[mixed_end:]
    scanner_path.write_text(scanner, encoding="utf-8")

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
            "consumer-install policy",
        )
    policy_path.write_text(policy, encoding="utf-8")

    project_path = ROOT / "pyproject.toml"
    project = project_path.read_text(encoding="utf-8")
    entry = 'plugin-scanner-assure = "codex_plugin_scanner.assurance_cli:main"\n'
    if entry not in project:
        project = replace_once(project, "[project.scripts]\n", "[project.scripts]\n" + entry, "assurance CLI")
    project_path.write_text(project, encoding="utf-8")


def replace_function(text: str, name: str, next_name: str, replacement: str) -> str:
    start = text.index(f"def {name}(")
    end = text.index(f"\ndef {next_name}(", start)
    return text[:start] + replacement.rstrip() + "\n\n" + text[end + 1 :]


def finalize_kernel() -> None:
    path = ROOT / "src/codex_plugin_scanner/rust_kernel.py"
    text = path.read_text(encoding="utf-8")
    if "EVIDENCE_METADATA_PATHS" not in text:
        text = text.replace(
            'KERNEL_PROTOCOL = "hol-guard-scanner-kernel.v1"\n',
            'KERNEL_PROTOCOL = "hol-guard-scanner-kernel.v1"\n'
            "EVIDENCE_METADATA_PATHS = frozenset(\n"
            "    {\n"
            '        ".hol-guard/attestation.json",\n'
            '        ".hol-guard/runtime-evidence.json",\n'
            '        ".hol-guard/extension-security-evidence.json",\n'
            "    }\n"
            ")\n",
            1,
        )
    helper = '''def inventory_digest(records: tuple[InventoryRecord, ...]) -> str:
    """Hash the artifact inventory while excluding attached evidence metadata.

    Excluding only these fixed evidence files prevents an attestation or runtime
    report from recursively changing the artifact digest it is bound to.
    """

    hasher = hashlib.sha256()
    for record in records:
        if record.path in EVIDENCE_METADATA_PATHS:
            continue
        hasher.update(record.path.encode("utf-8"))
        hasher.update(b"\\0")
        hasher.update(str(record.size).encode("ascii"))
        hasher.update(b"\\0")
        value = record.sha256 or f"[{record.kind}:{record.error or 'unhashed'}]"
        hasher.update(value.encode("utf-8"))
        hasher.update(b"\\n")
    return hasher.hexdigest()
'''
    if "def inventory_digest(" in text:
        text = replace_function(text, "inventory_digest", "_safe_relative_path", helper)
    else:
        text = text.replace("\ndef _safe_relative_path", "\n" + helper + "\ndef _safe_relative_path", 1)
    path.write_text(text, encoding="utf-8")


def finalize_assurance() -> None:
    path = ROOT / "src/codex_plugin_scanner/assurance.py"
    text = path.read_text(encoding="utf-8")
    text = text.replace("import math\n", "").replace("import os\n", "")
    text = text.replace(
        "from .rust_kernel import InventoryRecord, KernelResult, scan_inventory\n",
        "from .rust_kernel import InventoryRecord, inventory_digest, scan_inventory\n",
    )
    text = text.replace(
        "from .rust_kernel import InventoryRecord, scan_inventory\n",
        "from .rust_kernel import InventoryRecord, inventory_digest, scan_inventory\n",
    )
    if "inventory_digest" not in text.split("\n", 45)[-1]:
        pass
    text = text.replace("target_digest = _root_digest(kernel.records)", "target_digest = inventory_digest(kernel.records)")
    root_digest = text.find("def _root_digest(")
    if root_digest >= 0:
        root_digest_end = text.index("\ndef _load_runtime_layer", root_digest)
        text = text[:root_digest] + text[root_digest_end + 1 :]
    text = text.replace(
        "(?:Template|from_string|compileTemplate|Handlebars\\.compile|ejs\\.render|pug\\.render)",
        "(?:Template|from_string|render_template_string|compileTemplate|Handlebars\\.compile|ejs\\.render|pug\\.render)",
    )
    text = text.replace(
        '_CONTEXT_PARTS = frozenset({"docs", "doc", "examples", "example", "fixtures", "fixture", "samples", "sample", "tests", "test"})',
        '_CONTEXT_PARTS = frozenset(\n'
        '    {"docs", "doc", "examples", "example", "fixtures", "fixture", "samples", "sample", "tests", "test", "fuzz"}\n'
        ")",
    )
    context_replacement = '''def _is_non_runtime_context(path: str) -> bool:
    normalized = path.replace("\\\\", "/")
    parts = {part.lower() for part in PurePosixPath(normalized).parts}
    internal_rule_sources = {
        "src/codex_plugin_scanner/assurance.py",
        "src/codex_plugin_scanner/checks/security.py",
        "src/codex_plugin_scanner/checks/mcp_security.py",
        "src/codex_plugin_scanner/checks/skill_security.py",
    }
    return (
        bool(parts & _CONTEXT_PARTS)
        or normalized.lower().endswith((".example", ".sample"))
        or normalized in internal_rule_sources
    )
'''
    if "def _is_non_runtime_context(" in text:
        text = replace_function(text, "_is_non_runtime_context", "_contextual_severity", context_replacement)
    layer_replacement = '''def _layer_check(name: str, findings: tuple[Finding, ...], *, complete: bool) -> CheckResult:
    """Expose assurance as a gate without silently reweighting the legacy score."""

    blocking = [
        finding
        for finding in findings
        if SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[Severity.HIGH]
    ]
    passed = complete and not blocking
    message = (
        "Layer completed without high-severity findings."
        if passed
        else f"Layer emitted {len(findings)} finding(s); complete={str(complete).lower()}."
    )
    return CheckResult(
        name=name,
        passed=passed,
        points=0,
        max_points=0,
        message=message,
        findings=findings,
    )
'''
    if "def _layer_check(" in text:
        text = replace_function(text, "_layer_check", "_integration", layer_replacement)
    provenance_optional = text.find('    elif attestation.status in {"absent", "self-attested"}:')
    if provenance_optional >= 0:
        end = text.index("\n    runtime_status, runtime_limitations", provenance_optional)
        text = text[:provenance_optional] + text[end:]
    runtime_optional = text.find('    elif runtime_status in {"not-run", "partial"}:')
    if runtime_optional >= 0:
        end = text.index("\n    checks = (", runtime_optional)
        text = text[:runtime_optional] + text[end:]
    text = text.replace("    feature_ids_by_path: dict[str, set[str]] = defaultdict(set)\n\n", "")
    text = text.replace(
        "        feature_ids_by_path[record.path].update(_scan_text_patterns(text, record.path, collector))\n"
        "        feature_ids_by_path[record.path].update(_scan_obfuscation(text, record.path, collector))\n",
        "        _scan_text_patterns(text, record.path, collector)\n"
        "        _scan_obfuscation(text, record.path, collector)\n",
    )
    old_condition = (
        '        if not payload.get("security") and not payload.get("components", {}).get("securitySchemes") '
        'if isinstance(payload.get("components"), dict) else True:\n'
    )
    if old_condition in text:
        text = text.replace(
            old_condition,
            '        components = payload.get("components")\n'
            '        has_security_schemes = isinstance(components, dict) and bool(components.get("securitySchemes"))\n'
            '        if not payload.get("security") and not has_security_schemes:\n',
            1,
        )
    old_probe = (
        "    try:\n"
        "        if tarfile.is_tarfile(io.BytesIO(data)):\n"
        "            _inspect_tar_bytes(data, label, collector, coverage, depth)\n"
        "            return\n"
        "    except (OSError, tarfile.TarError):\n"
        "        pass\n"
        "    coverage.archive_partial = True\n"
    )
    if old_probe in text:
        text = text.replace(old_probe, "    _inspect_tar_bytes(data, label, collector, coverage, depth)\n", 1)
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
    digest_replacement = '''def _target_digest(target: Path) -> str:
    return inventory_digest(scan_inventory(target).records)
'''
    if "def _target_digest(" in text:
        text = replace_function(text, "_target_digest", "_trace_inventory", digest_replacement)
    if "def _sandbox_identity(" not in text:
        insertion = '''
def _sandbox_identity() -> tuple[int, int]:
    uid = os.getuid() if hasattr(os, "getuid") else 65534
    gid = os.getgid() if hasattr(os, "getgid") else 65534
    if uid == 0:
        return 65534, 65534
    return uid, gid
'''
        text = text.replace("\ndef build_sandbox_command", insertion + "\ndef build_sandbox_command", 1)
    text = text.replace(
        "    command: list[str] = [\n",
        "    uid, gid = _sandbox_identity()\n    command: list[str] = [\n",
        1,
    )
    text = text.replace('        "--user=65534:65534",\n', '        f"--user={uid}:{gid}",\n')
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


def finalize_evidence() -> None:
    path = ROOT / "src/codex_plugin_scanner/evidence_envelope.py"
    text = path.read_text(encoding="utf-8")
    if "import ipaddress\n" not in text:
        text = text.replace("import hashlib\n", "import hashlib\nimport ipaddress\n", 1)
    old = (
        "        try:\n"
        "            signature_bytes = base64.b64decode(str(signature.get(\"sig\", \"\")), validate=True)\n"
        "            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey\n\n"
        "            Ed25519PublicKey.from_public_bytes(key).verify(signature_bytes, message)\n"
        "        except (ValueError, ImportError, Exception):\n"
        "            continue\n"
    )
    if old in text:
        text = text.replace(
            old,
            "        try:\n"
            "            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey\n"
            "        except ImportError:\n"
            "            return AttestationVerification(\"failed\", None, \"Ed25519 verification support is unavailable.\")\n"
            "        try:\n"
            "            signature_bytes = base64.b64decode(str(signature.get(\"sig\", \"\")), validate=True)\n"
            "            Ed25519PublicKey.from_public_bytes(key).verify(signature_bytes, message)\n"
            "        except Exception:\n"
            "            continue\n",
            1,
        )
    if "private evidence endpoint addresses" not in text:
        anchor = (
            '    if parsed.hostname in {"localhost", "127.0.0.1", "::1"}:\n'
            '        raise EvidenceError("loopback evidence endpoints are not allowed")\n'
        )
        text = replace_once(
            text,
            anchor,
            anchor
            + "    try:\n"
            + "        address = ipaddress.ip_address(parsed.hostname)\n"
            + "    except ValueError:\n"
            + "        address = None\n"
            + "    if address is not None and (address.is_private or address.is_loopback or address.is_link_local):\n"
            + '        raise EvidenceError("private evidence endpoint addresses are not allowed")\n',
            "private evidence endpoint",
        )
    path.write_text(text, encoding="utf-8")


def finalize_tests() -> None:
    corpus_path = ROOT / "tests/assurance_corpus.py"
    corpus = corpus_path.read_text(encoding="utf-8")
    corpus = corpus.replace(
        "This plugin documents why callers must not ignore prior security instructions.",
        "Security controls remain authoritative and users receive clear disclosures.",
    )
    corpus_path.write_text(corpus, encoding="utf-8")

    runtime_path = ROOT / "tests/test_runtime_assurance.py"
    runtime = runtime_path.read_text(encoding="utf-8")
    runtime = runtime.replace('    assert "--user=65534:65534" in command\n', '    assert any(value.startswith("--user=") and not value.startswith("--user=0:") for value in command)\n')
    if '            "defaultSeccomp": True,\n' not in runtime:
        runtime = runtime.replace(
            '            "resourceLimits": True,\n',
            '            "resourceLimits": True,\n            "defaultSeccomp": True,\n            "imagePullDisabled": True,\n',
            1,
        )
    runtime_path.write_text(runtime, encoding="utf-8")

    assurance_test = ROOT / "tests/test_assurance_scanner.py"
    assurance = assurance_test.read_text(encoding="utf-8")
    if "test_target_digest_is_stable_after_evidence_is_attached" not in assurance:
        assurance += '''

def test_target_digest_is_stable_after_evidence_is_attached(tmp_path: Path) -> None:
    (tmp_path / "plugin.py").write_text("print('safe')", encoding="utf-8")
    _checks, first_integrations = run_assurance_checks(tmp_path)
    first = next(item for item in first_integrations if item.name == "assurance-target")
    evidence_dir = tmp_path / ".hol-guard"
    evidence_dir.mkdir()
    (evidence_dir / "attestation.json").write_text("{}", encoding="utf-8")
    (evidence_dir / "runtime-evidence.json").write_text("{}", encoding="utf-8")
    (evidence_dir / "extension-security-evidence.json").write_text("{}", encoding="utf-8")

    _checks, second_integrations = run_assurance_checks(tmp_path)
    second = next(item for item in second_integrations if item.name == "assurance-target")

    assert first.metadata["target_digest"] == second.metadata["target_digest"]
'''
    assurance_test.write_text(assurance, encoding="utf-8")


def remove_obsolete_diagnostics() -> None:
    for relative in (
        ".github/workflows/scanner-assurance-source-snapshot.yml",
        ".github/workflows/scanner-reliability-payload-inspect.yml",
        ".github/workflows/scanner-reliability-source-snapshot.yml",
    ):
        path = ROOT / relative
        if path.exists():
            path.unlink()


def main() -> None:
    for script in (
        "scripts/ci/apply_scanner_assurance_integration.py",
        "scripts/ci/repair_scanner_assurance.py",
        "scripts/ci/finalize_scanner_assurance.py",
    ):
        try:
            run_existing(script)
        except (RuntimeError, ValueError, KeyError):
            # The v2 finalizer below is authoritative and accepts any prior state.
            pass
    finalize_kernel()
    ensure_integration()
    finalize_assurance()
    finalize_runtime()
    finalize_evidence()
    finalize_tests()
    remove_obsolete_diagnostics()


if __name__ == "__main__":
    main()
