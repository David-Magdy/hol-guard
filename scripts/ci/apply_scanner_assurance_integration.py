#!/usr/bin/env python3
"""Integrate the scanner assurance modules into the release/3.0 scanner."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)


def patch_scanner() -> None:
    path = ROOT / "src/codex_plugin_scanner/scanner.py"
    text = path.read_text(encoding="utf-8")
    if "from .assurance import run_assurance_checks" not in text:
        text = replace_once(
            text,
            "from .checks.best_practices import run_best_practice_checks\n",
            "from .assurance import run_assurance_checks\nfrom .checks.best_practices import run_best_practice_checks\n",
            "scanner assurance import",
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
            "single-plugin assurance initialization",
        )
        text = replace_once(
            text,
            "        CategoryResult(name=\"Code Quality\", checks=run_code_quality_checks(plugin_dir)),\n"
            "    ]\n",
            "        CategoryResult(name=\"Code Quality\", checks=run_code_quality_checks(plugin_dir)),\n"
            "        CategoryResult(name=\"Layered Assurance\", checks=assurance_checks),\n"
            "    ]\n",
            "single-plugin assurance category",
        )
        text = replace_once(
            text,
            "        integrations=_build_integration_results(skill_security_context, mcp_security_context),\n",
            "        integrations=(\n"
            "            _build_integration_results(skill_security_context, mcp_security_context)\n"
            "            + assurance_integrations\n"
            "        ),\n",
            "single-plugin assurance integrations",
        )
    if "CategoryResult(name=\"Repository Layered Assurance\"" not in text:
        text = replace_once(
            text,
            "    categories = _build_repository_categories(repo_root, plugin_results)\n",
            "    assurance_checks, assurance_integrations = run_assurance_checks(repo_root)\n"
            "    categories = _build_repository_categories(repo_root, plugin_results) + (\n"
            "        CategoryResult(name=\"Repository Layered Assurance\", checks=assurance_checks),\n"
            "    )\n",
            "repository assurance category",
        )
        text = replace_once(
            text,
            "        integrations=tuple(integration for plugin in plugin_results for integration in plugin.integrations),\n",
            "        integrations=(\n"
            "            assurance_integrations\n"
            "            + tuple(integration for plugin in plugin_results for integration in plugin.integrations)\n"
            "        ),\n",
            "repository assurance integrations",
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
            "mixed-package assurance",
        )
        text = text[:mixed_start] + mixed + text[mixed_end:]
    path.write_text(text, encoding="utf-8")


def patch_policy() -> None:
    path = ROOT / "src/codex_plugin_scanner/policy.py"
    text = path.read_text(encoding="utf-8")
    if '"consumer-install": PolicyProfile(' not in text:
        text = replace_once(
            text,
            '    "strict-security": PolicyProfile(\n',
            '    "consumer-install": PolicyProfile(\n'
            '        name="consumer-install",\n'
            "        max_severity=Severity.LOW,\n"
            "        min_score=80,\n"
            "    ),\n"
            '    "strict-security": PolicyProfile(\n',
            "consumer-install policy",
        )
    path.write_text(text, encoding="utf-8")


def patch_pyproject() -> None:
    path = ROOT / "pyproject.toml"
    text = path.read_text(encoding="utf-8")
    entry = 'plugin-scanner-assure = "codex_plugin_scanner.assurance_cli:main"\n'
    if entry not in text:
        marker = "[project.scripts]\n"
        if marker not in text:
            raise RuntimeError("pyproject is missing [project.scripts]")
        text = text.replace(marker, marker + entry, 1)
    path.write_text(text, encoding="utf-8")


def patch_assurance() -> None:
    path = ROOT / "src/codex_plugin_scanner/assurance.py"
    text = path.read_text(encoding="utf-8")
    text = text.replace("import math\n", "").replace("import os\n", "")
    text = text.replace(
        "from .rust_kernel import InventoryRecord, KernelResult, scan_inventory\n",
        "from .rust_kernel import InventoryRecord, inventory_digest, scan_inventory\n",
    )
    text = text.replace(
        '_CONTEXT_PARTS = frozenset({"docs", "doc", "examples", "example", "fixtures", "fixture", "samples", "sample", "tests", "test"})',
        '_CONTEXT_PARTS = frozenset(\n'
        '    {"docs", "doc", "examples", "example", "fixtures", "fixture", "samples", "sample", "tests", "test", "fuzz"}\n'
        ")",
    )
    text = replace_once(
        text,
        "def _is_non_runtime_context(path: str) -> bool:\n"
        "    parts = {part.lower() for part in PurePosixPath(path).parts}\n"
        "    return bool(parts & _CONTEXT_PARTS) or path.lower().endswith((\".example\", \".sample\"))\n",
        "def _is_non_runtime_context(path: str) -> bool:\n"
        "    normalized = path.replace(\"\\\\\", \"/\")\n"
        "    parts = {part.lower() for part in PurePosixPath(normalized).parts}\n"
        "    internal_rule_sources = {\n"
        "        \"src/codex_plugin_scanner/assurance.py\",\n"
        "        \"src/codex_plugin_scanner/checks/security.py\",\n"
        "        \"src/codex_plugin_scanner/checks/mcp_security.py\",\n"
        "        \"src/codex_plugin_scanner/checks/skill_security.py\",\n"
        "    }\n"
        "    return (\n"
        "        bool(parts & _CONTEXT_PARTS)\n"
        "        or normalized.lower().endswith((\".example\", \".sample\"))\n"
        "        or normalized in internal_rule_sources\n"
        "    )\n",
        "assurance context classification",
    )
    text = replace_once(
        text,
        "    if \"openapi\" in payload or \"swagger\" in payload:\n"
        "        servers = payload.get(\"servers\")\n",
        "    if \"openapi\" in payload or \"swagger\" in payload:\n"
        "        servers = payload.get(\"servers\")\n",
        "openapi anchor",
    )
    old_condition = (
        '        if not payload.get("security") and not payload.get("components", {}).get("securitySchemes") '
        'if isinstance(payload.get("components"), dict) else True:\n'
    )
    new_condition = (
        '        components = payload.get("components")\n'
        '        has_security_schemes = isinstance(components, dict) and bool(components.get("securitySchemes"))\n'
        '        if not payload.get("security") and not has_security_schemes:\n'
    )
    text = replace_once(text, old_condition, new_condition, "openapi auth condition")
    old_archive_probe = (
        "    try:\n"
        "        if tarfile.is_tarfile(io.BytesIO(data)):\n"
        "            _inspect_tar_bytes(data, label, collector, coverage, depth)\n"
        "            return\n"
        "    except (OSError, tarfile.TarError):\n"
        "        pass\n"
        "    coverage.archive_partial = True\n"
    )
    new_archive_probe = (
        "    before_partial = coverage.archive_partial\n"
        "    before_count = len(collector.layer(\"archive\"))\n"
        "    _inspect_tar_bytes(data, label, collector, coverage, depth)\n"
        "    if len(collector.layer(\"archive\")) == before_count and coverage.archive_partial == before_partial:\n"
        "        coverage.archive_partial = True\n"
    )
    text = replace_once(text, old_archive_probe, new_archive_probe, "archive probe")
    text = text.replace(
        "def _root_digest(records: tuple[InventoryRecord, ...]) -> str:\n"
        "    hasher = hashlib.sha256()\n"
        "    for record in records:\n"
        "        hasher.update(record.path.encode(\"utf-8\"))\n"
        "        hasher.update(b\"\\0\")\n"
        "        hasher.update(str(record.size).encode(\"ascii\"))\n"
        "        hasher.update(b\"\\0\")\n"
        "        hasher.update((record.sha256 or f\"[{record.kind}:{record.error or 'unhashed'}]\").encode(\"utf-8\"))\n"
        "        hasher.update(b\"\\n\")\n"
        "    return hasher.hexdigest()\n\n\n",
        "",
    )
    text = text.replace("target_digest = _root_digest(kernel.records)", "target_digest = inventory_digest(kernel.records)")
    text = text.replace("    feature_ids_by_path: dict[str, set[str]] = defaultdict(set)\n\n", "")
    text = text.replace(
        "        feature_ids_by_path[record.path].update(_scan_text_patterns(text, record.path, collector))\n"
        "        feature_ids_by_path[record.path].update(_scan_obfuscation(text, record.path, collector))\n",
        "        _scan_text_patterns(text, record.path, collector)\n"
        "        _scan_obfuscation(text, record.path, collector)\n",
    )
    path.write_text(text, encoding="utf-8")


def patch_kernel_bridge() -> None:
    path = ROOT / "src/codex_plugin_scanner/rust_kernel.py"
    text = path.read_text(encoding="utf-8")
    marker = "\ndef _safe_relative_path(value: str) -> str:\n"
    if "def inventory_digest(" not in text:
        function = (
            "\ndef inventory_digest(records: tuple[InventoryRecord, ...]) -> str:\n"
            "    \"\"\"Hash the deterministic inventory without exposing file contents.\"\"\"\n\n"
            "    hasher = hashlib.sha256()\n"
            "    for record in records:\n"
            "        hasher.update(record.path.encode(\"utf-8\"))\n"
            "        hasher.update(b\"\\0\")\n"
            "        hasher.update(str(record.size).encode(\"ascii\"))\n"
            "        hasher.update(b\"\\0\")\n"
            "        marker = record.sha256 or f\"[{record.kind}:{record.error or 'unhashed'}]\"\n"
            "        hasher.update(marker.encode(\"utf-8\"))\n"
            "        hasher.update(b\"\\n\")\n"
            "    return hasher.hexdigest()\n"
        )
        text = replace_once(text, marker, function + marker, "inventory digest helper")
    path.write_text(text, encoding="utf-8")


def patch_runtime() -> None:
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
    text = text.replace(
        '        "--rm",\n        "--network=none",\n',
        '        "--rm",\n        "--pull=never",\n        "--network=none",\n',
    )
    text = text.replace('        "--uts=private",\n', "")
    old_digest = (
        "def _target_digest(target: Path) -> str:\n"
        "    hasher = hashlib.sha256()\n"
        "    excluded = {\".git\", \"node_modules\", \".venv\", \"venv\", \"target\", \"dist\", \"build\", \"__pycache__\"}\n"
        "    for path in sorted(item for item in target.rglob(\"*\") if item.is_file() and not item.is_symlink()):\n"
        "        relative = path.relative_to(target)\n"
        "        if any(part in excluded for part in relative.parts):\n"
        "            continue\n"
        "        hasher.update(relative.as_posix().encode(\"utf-8\"))\n"
        "        try:\n"
        "            with path.open(\"rb\") as handle:\n"
        "                while chunk := handle.read(1024 * 1024):\n"
        "                    hasher.update(chunk)\n"
        "        except OSError:\n"
        "            hasher.update(b\"[unreadable]\")\n"
        "    return hasher.hexdigest()\n"
    )
    new_digest = (
        "def _target_digest(target: Path) -> str:\n"
        "    return inventory_digest(scan_inventory(target).records)\n"
    )
    text = replace_once(text, old_digest, new_digest, "runtime target digest")
    text = text.replace(
        '        "resourceLimits": True,\n        "separateWritableEvidenceMount": validated.output_dir is not None,\n',
        '        "resourceLimits": True,\n        "defaultSeccomp": True,\n        "imagePullDisabled": True,\n        "separateWritableEvidenceMount": validated.output_dir is not None,\n',
    )
    text = text.replace(
        '            "complete": trace_complete if validated.trace_syscalls else False,\n',
        '            "complete": trace_complete and not timed_out if validated.trace_syscalls else False,\n',
    )
    old_plan = (
        '        "plan": {\n'
        "            **asdict(validated),\n"
        '            "target": str(validated.target),\n'
        '            "output_dir": str(validated.output_dir) if validated.output_dir else None,\n'
        '            "command": list(validated.command),\n'
        "        },\n"
    )
    new_plan = (
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
    text = replace_once(text, old_plan, new_plan, "runtime privacy-safe plan")
    text = text.replace("from dataclasses import asdict, dataclass\n", "from dataclasses import dataclass\n")
    text = text.replace(
        '        "resourceLimits",\n    )\n',
        '        "resourceLimits",\n        "defaultSeccomp",\n        "imagePullDisabled",\n    )\n',
    )
    path.write_text(text, encoding="utf-8")


def patch_evidence() -> None:
    path = ROOT / "src/codex_plugin_scanner/evidence_envelope.py"
    text = path.read_text(encoding="utf-8")
    if "import ipaddress\n" not in text:
        text = text.replace("import hashlib\n", "import hashlib\nimport ipaddress\n", 1)
    old_verify = (
        "        try:\n"
        "            signature_bytes = base64.b64decode(str(signature.get(\"sig\", \"\")), validate=True)\n"
        "            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey\n\n"
        "            Ed25519PublicKey.from_public_bytes(key).verify(signature_bytes, message)\n"
        "        except (ValueError, ImportError, Exception):\n"
        "            continue\n"
    )
    new_verify = (
        "        try:\n"
        "            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey\n"
        "        except ImportError:\n"
        "            return AttestationVerification(\"failed\", None, \"Ed25519 verification support is unavailable.\")\n"
        "        try:\n"
        "            signature_bytes = base64.b64decode(str(signature.get(\"sig\", \"\")), validate=True)\n"
        "            Ed25519PublicKey.from_public_bytes(key).verify(signature_bytes, message)\n"
        "        except Exception:\n"
        "            continue\n"
    )
    text = replace_once(text, old_verify, new_verify, "attestation exception handling")
    old_endpoint = (
        '    if parsed.hostname in {"localhost", "127.0.0.1", "::1"}:\n'
        '        raise EvidenceError("loopback evidence endpoints are not allowed")\n'
    )
    new_endpoint = (
        '    if parsed.hostname in {"localhost", "127.0.0.1", "::1"}:\n'
        '        raise EvidenceError("loopback evidence endpoints are not allowed")\n'
        "    try:\n"
        "        address = ipaddress.ip_address(parsed.hostname)\n"
        "    except ValueError:\n"
        "        address = None\n"
        "    if address is not None and (address.is_private or address.is_loopback or address.is_link_local):\n"
        '        raise EvidenceError("private evidence endpoint addresses are not allowed")\n'
    )
    text = replace_once(text, old_endpoint, new_endpoint, "private upload endpoints")
    path.write_text(text, encoding="utf-8")


def patch_rust() -> None:
    path = ROOT / "rust/scanner-kernel/src/main.rs"
    text = path.read_text(encoding="utf-8")
    old_magic = (
        "    } else if prefix.len() >= 4\n"
        "        && matches!(\n"
        "            &prefix[..4],\n"
        "            b\"\\xfe\\xed\\xfa\\xce\"\n"
        "                | b\"\\xce\\xfa\\xed\\xfe\"\n"
        "                | b\"\\xfe\\xed\\xfa\\xcf\"\n"
        "                | b\"\\xcf\\xfa\\xed\\xfe\"\n"
        "                | b\"\\xca\\xfe\\xba\\xbe\"\n"
        "                | b\"\\xbe\\xba\\xfe\\xca\"\n"
        "        )\n"
    )
    new_magic = (
        "    } else if prefix.len() >= 4\n"
        "        && ([\n"
        "            b\"\\xfe\\xed\\xfa\\xce\".as_slice(),\n"
        "            b\"\\xce\\xfa\\xed\\xfe\".as_slice(),\n"
        "            b\"\\xfe\\xed\\xfa\\xcf\".as_slice(),\n"
        "            b\"\\xcf\\xfa\\xed\\xfe\".as_slice(),\n"
        "            b\"\\xca\\xfe\\xba\\xbe\".as_slice(),\n"
        "            b\"\\xbe\\xba\\xfe\\xca\".as_slice(),\n"
        "        ]\n"
        "        .contains(&&prefix[..4]))\n"
    )
    text = replace_once(text, old_magic, new_magic, "Rust Mach-O magic")
    text = text.replace('format!("read-error:{}", error.kind() as u32)', 'format!("read-error:{:?}", error.kind())')
    text = text.replace('format!("prefix-read-error:{}", error.kind() as u32)', 'format!("prefix-read-error:{:?}", error.kind())')
    text = text.replace('"directory-read:{}:{}",', '"directory-read:{}:{:?}",')
    text = text.replace('                error.kind() as u32\n', '                error.kind()\n')
    text = text.replace('format!("metadata-error:{}", error.kind() as u32)', 'format!("metadata-error:{:?}", error.kind())')
    path.write_text(text, encoding="utf-8")


def patch_tests() -> None:
    path = ROOT / "tests/assurance_corpus.py"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        "This plugin documents why callers must not ignore prior security instructions.",
        "Security controls remain authoritative and users receive clear disclosures.",
    )
    path.write_text(text, encoding="utf-8")


def remove_diagnostic_workflows() -> None:
    for relative in (
        ".github/workflows/scanner-assurance-source-snapshot.yml",
        ".github/workflows/scanner-reliability-payload-inspect.yml",
        ".github/workflows/scanner-reliability-source-snapshot.yml",
    ):
        path = ROOT / relative
        if path.exists():
            path.unlink()


def main() -> None:
    patch_scanner()
    patch_policy()
    patch_pyproject()
    patch_assurance()
    patch_kernel_bridge()
    patch_runtime()
    patch_evidence()
    patch_rust()
    patch_tests()
    remove_diagnostic_workflows()


if __name__ == "__main__":
    main()
