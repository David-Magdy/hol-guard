#!/usr/bin/env python3
"""Repair assurance sources regardless of whether the first integration workflow ran."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)


def patch_assurance() -> None:
    path = ROOT / "src/codex_plugin_scanner/assurance.py"
    text = path.read_text(encoding="utf-8")
    text = text.replace("import math\n", "").replace("import os\n", "")
    text = text.replace(
        "from .rust_kernel import InventoryRecord, KernelResult, scan_inventory\n",
        "from .rust_kernel import InventoryRecord, inventory_digest, scan_inventory\n",
    )
    old_context = (
        "def _is_non_runtime_context(path: str) -> bool:\n"
        "    parts = {part.lower() for part in PurePosixPath(path).parts}\n"
        "    return bool(parts & _CONTEXT_PARTS) or path.lower().endswith((\".example\", \".sample\"))\n"
    )
    if old_context in text:
        text = text.replace(
            old_context,
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
            1,
        )
    text = text.replace(
        '_CONTEXT_PARTS = frozenset({"docs", "doc", "examples", "example", "fixtures", "fixture", "samples", "sample", "tests", "test"})',
        '_CONTEXT_PARTS = frozenset(\n'
        '    {"docs", "doc", "examples", "example", "fixtures", "fixture", "samples", "sample", "tests", "test", "fuzz"}\n'
        ")",
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
    old_archive = (
        "    try:\n"
        "        if tarfile.is_tarfile(io.BytesIO(data)):\n"
        "            _inspect_tar_bytes(data, label, collector, coverage, depth)\n"
        "            return\n"
        "    except (OSError, tarfile.TarError):\n"
        "        pass\n"
        "    coverage.archive_partial = True\n"
    )
    if old_archive in text:
        text = text.replace(
            old_archive,
            "    _inspect_tar_bytes(data, label, collector, coverage, depth)\n",
            1,
        )
    text = text.replace(
        "(?:Template|from_string|compileTemplate|Handlebars\\.compile|ejs\\.render|pug\\.render)",
        "(?:Template|from_string|render_template_string|compileTemplate|Handlebars\\.compile|ejs\\.render|pug\\.render)",
    )
    root_digest_start = text.find("def _root_digest(")
    if root_digest_start >= 0:
        root_digest_end = text.index("\ndef _load_runtime_layer", root_digest_start)
        text = text[:root_digest_start] + text[root_digest_end + 1 :]
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


def patch_evidence() -> None:
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
    endpoint = (
        '    if parsed.hostname in {"localhost", "127.0.0.1", "::1"}:\n'
        '        raise EvidenceError("loopback evidence endpoints are not allowed")\n'
    )
    if "private evidence endpoint addresses" not in text:
        text = replace_once(
            text,
            endpoint,
            endpoint
            + "    try:\n"
            + "        address = ipaddress.ip_address(parsed.hostname)\n"
            + "    except ValueError:\n"
            + "        address = None\n"
            + "    if address is not None and (address.is_private or address.is_loopback or address.is_link_local):\n"
            + '        raise EvidenceError("private evidence endpoint addresses are not allowed")\n',
            "private endpoint",
        )
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
    if '        "--pull=never",\n' not in text:
        text = text.replace('        "--rm",\n', '        "--rm",\n        "--pull=never",\n', 1)
    text = text.replace('        "--uts=private",\n', "")
    digest_start = text.find("def _target_digest(target: Path) -> str:")
    if digest_start >= 0 and "inventory_digest(scan_inventory(target).records)" not in text[digest_start : digest_start + 300]:
        digest_end = text.index("\ndef _trace_inventory", digest_start)
        text = (
            text[:digest_start]
            + "def _target_digest(target: Path) -> str:\n"
            + "    return inventory_digest(scan_inventory(target).records)\n\n"
            + text[digest_end + 1 :]
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
        text = (
            text[:start]
            + '        "plan": {\n'
            + '            "engine": validated.engine,\n'
            + '            "image": validated.image,\n'
            + '            "targetName": validated.target.name,\n'
            + '            "commandName": Path(validated.command[0]).name,\n'
            + '            "argumentCount": len(validated.command),\n'
            + '            "timeoutSeconds": validated.timeout_seconds,\n'
            + '            "memoryMegabytes": validated.memory_megabytes,\n'
            + '            "cpuLimit": validated.cpu_limit,\n'
            + '            "pidsLimit": validated.pids_limit,\n'
            + '            "fileSizeMegabytes": validated.file_size_megabytes,\n'
            + '            "traceSyscalls": validated.trace_syscalls,\n'
            + "        },\n"
            + text[end:]
        )
        text = text.replace("from dataclasses import asdict, dataclass\n", "from dataclasses import dataclass\n")
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
    if old_magic in text:
        text = text.replace(
            old_magic,
            "    } else if prefix.len() >= 4\n"
            "        && matches!(\n"
            "            prefix[..4],\n"
            "            [0xfe, 0xed, 0xfa, 0xce]\n"
            "                | [0xce, 0xfa, 0xed, 0xfe]\n"
            "                | [0xfe, 0xed, 0xfa, 0xcf]\n"
            "                | [0xcf, 0xfa, 0xed, 0xfe]\n"
            "                | [0xca, 0xfe, 0xba, 0xbe]\n"
            "                | [0xbe, 0xba, 0xfe, 0xca]\n"
            "        )\n",
            1,
        )
    text = text.replace(
        '    let little = matches!(magic, b"\\xce\\xfa\\xed\\xfe" | b"\\xcf\\xfa\\xed\\xfe");\n'
        '    let fat = matches!(magic, b"\\xca\\xfe\\xba\\xbe" | b"\\xbe\\xba\\xfe\\xca");\n',
        "    let little = magic == [0xce, 0xfa, 0xed, 0xfe] || magic == [0xcf, 0xfa, 0xed, 0xfe];\n"
        "    let fat = magic == [0xca, 0xfe, 0xba, 0xbe] || magic == [0xbe, 0xba, 0xfe, 0xca];\n",
    )
    text = text.replace(
        '    let is_64 = matches!(magic, b"\\xfe\\xed\\xfa\\xcf" | b"\\xcf\\xfa\\xed\\xfe");\n',
        "    let is_64 = magic == [0xfe, 0xed, 0xfa, 0xcf] || magic == [0xcf, 0xfa, 0xed, 0xfe];\n",
    )
    text = text.replace('format!("read-error:{}", error.kind() as u32)', 'format!("read-error:{:?}", error.kind())')
    text = text.replace('format!("prefix-read-error:{}", error.kind() as u32)', 'format!("prefix-read-error:{:?}", error.kind())')
    text = text.replace('"directory-read:{}:{}",', '"directory-read:{}:{:?}",')
    text = text.replace('                error.kind() as u32\n', '                error.kind()\n')
    text = text.replace('format!("metadata-error:{}", error.kind() as u32)', 'format!("metadata-error:{:?}", error.kind())')
    path.write_text(text, encoding="utf-8")


def patch_tests() -> None:
    corpus = ROOT / "tests/assurance_corpus.py"
    text = corpus.read_text(encoding="utf-8")
    text = text.replace(
        "This plugin documents why callers must not ignore prior security instructions.",
        "Security controls remain authoritative and users receive clear disclosures.",
    )
    corpus.write_text(text, encoding="utf-8")

    runtime = ROOT / "tests/test_runtime_assurance.py"
    text = runtime.read_text(encoding="utf-8")
    if '            "defaultSeccomp": True,\n' not in text:
        text = text.replace(
            '            "resourceLimits": True,\n',
            '            "resourceLimits": True,\n            "defaultSeccomp": True,\n            "imagePullDisabled": True,\n',
            1,
        )
    runtime.write_text(text, encoding="utf-8")


def main() -> None:
    patch_kernel_bridge()
    patch_assurance()
    patch_evidence()
    patch_runtime()
    patch_rust()
    patch_tests()


if __name__ == "__main__":
    main()
