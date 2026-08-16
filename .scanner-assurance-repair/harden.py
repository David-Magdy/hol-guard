"""Idempotent hardening transforms for the scanner assurance feature branch."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def write(relative: str, text: str) -> None:
    (ROOT / relative).write_text(text, encoding="utf-8")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if new in text:
        return text
    if old not in text:
        raise RuntimeError(f"missing hardening anchor: {label}")
    return text.replace(old, new, 1)


def regex_once(text: str, pattern: str, replacement: str, label: str) -> str:
    if re.search(pattern, text, re.DOTALL) is None:
        raise RuntimeError(f"missing hardening regex anchor: {label}")
    return re.sub(pattern, replacement, text, count=1, flags=re.DOTALL)


def patch_pyproject() -> None:
    text = read("pyproject.toml")
    dependency_anchor = "dependencies = [\n"
    additions = []
    if "cryptography>=" not in text:
        additions.append('    "cryptography>=45.0.0",\n')
    if "tomli>=" not in text:
        additions.append('    "tomli>=2.0.1; python_version < \'3.11\'",\n')
    if additions:
        text = replace_once(
            text,
            dependency_anchor,
            dependency_anchor + "".join(additions),
            "pyproject dependencies",
        )
    if "hol-guard-extension-security" not in text:
        text = replace_once(
            text,
            "[project.scripts]\n",
            '[project.scripts]\nhol-guard-extension-security = "codex_plugin_scanner.assurance_cli:main"\n',
            "project script",
        )
    write("pyproject.toml", text)


def patch_archive() -> None:
    relative = "src/codex_plugin_scanner/assurance/archive_scan.py"
    text = read(relative)
    if "import unicodedata" not in text:
        text = text.replace("import tarfile\n", "import tarfile\nimport unicodedata\n", 1)
    if "INCOMPLETE_ARCHIVE_RULES" not in text:
        anchor = "NATIVE_MAGICS = (\n"
        start = text.index(anchor)
        end = text.index("\n)\n", start) + 3
        text = text[:end] + '''\nINCOMPLETE_ARCHIVE_RULES = frozenset(\n    {\n        "ASSURANCE_ARCHIVE_DEPTH_LIMIT",\n        "ASSURANCE_ARCHIVE_INVALID",\n        "ASSURANCE_ARCHIVE_MEMBER_LIMIT",\n        "ASSURANCE_ARCHIVE_ENCRYPTED_MEMBER",\n        "ASSURANCE_ARCHIVE_COMPRESSION_BOMB",\n        "ASSURANCE_ARCHIVE_MEMBER_OVERSIZED",\n        "ASSURANCE_ARCHIVE_EXPANSION_LIMIT",\n        "ASSURANCE_ARCHIVE_MEMBER_READ_FAILED",\n    }\n)\n''' + text[end:]
    text = re.sub(
        r"            unix_mode = \(info\.external_attr >> 16\) & 0xFFFF\n            is_link = stat\.S_ISLNK\(unix_mode\)\n            is_special = unix_mode and not \(\n                stat\.S_ISREG\(unix_mode\) or stat\.S_ISDIR\(unix_mode\) or is_link\n            \)",
        '''            unix_mode = (info.external_attr >> 16) & 0xFFFF\n            file_type = stat.S_IFMT(unix_mode)\n            is_link = file_type == stat.S_IFLNK\n            is_special = file_type not in {0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK}''',
        text,
        count=1,
    )
    final_anchor = "    return ArchiveResult(\n        findings=tuple(_dedupe(findings)),\n"
    hardened_return = '''    if any(finding.rule_id in INCOMPLETE_ARCHIVE_RULES for finding in findings):\n        complete = False\n    return ArchiveResult(\n        findings=tuple(_dedupe(findings)),\n'''
    if text.count(hardened_return) < 2:
        text = text.replace(final_anchor, hardened_return)
    text = text.replace(
        '''def _normalized_member_name(name: str) -> str:\n    normalized = posixpath.normpath(name.replace("\\\\", "/"))\n    return normalized.removeprefix("./")\n''',
        '''def _normalized_member_name(name: str) -> str:\n    normalized = posixpath.normpath(name.replace("\\\\", "/"))\n    return unicodedata.normalize("NFC", normalized.removeprefix("./"))\n''',
    )
    write(relative, text)


def patch_dependency() -> None:
    relative = "src/codex_plugin_scanner/assurance/dependency_scan.py"
    text = read(relative)
    text = text.replace(
        "import tomllib\n",
        '''try:\n    import tomllib\nexcept ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility\n    import tomli as tomllib\n''',
        1,
    )
    text = text.replace(
        "        if record.source and MUTABLE_SOURCE_RE.search(record.source):\n",
        '''        if record.source and (\n            MUTABLE_SOURCE_RE.search(record.source)\n            or (record.ecosystem in {"cargo", "npm", "pypi"} and not record.pinned)\n        ):\n''',
        1,
    )
    old_equal = '''    if len(left) == len(right):\n        return sum(a != b for a, b in zip(left, right, strict=True)) == 1\n'''
    new_equal = '''    if len(left) == len(right):\n        differences = [\n            index\n            for index, (left_character, right_character) in enumerate(\n                zip(left, right, strict=True)\n            )\n            if left_character != right_character\n        ]\n        if len(differences) == 1:\n            return True\n        return (\n            len(differences) == 2\n            and differences[1] == differences[0] + 1\n            and left[differences[0]] == right[differences[1]]\n            and left[differences[1]] == right[differences[0]]\n        )\n'''
    text = replace_once(text, old_equal, new_equal, "Damerau typosquat")
    osv_anchor = '''        try:\n            osv_payload = query_osv(records, limits)\n        except (OSError, ValueError, urllib.error.URLError) as exc:\n'''
    osv_insert = '''        try:\n            osv_payload = query_osv(records, limits)\n            vulnerabilities = osv_payload.get("vulnerabilities", [])\n            if isinstance(vulnerabilities, list):\n                for vulnerability in vulnerabilities[:10_000]:\n                    if not isinstance(vulnerability, dict):\n                        continue\n                    advisory_id = str(vulnerability.get("id", "unknown"))\n                    package_name = str(vulnerability.get("package", "unknown"))\n                    findings.append(\n                        _finding(\n                            "ASSURANCE_KNOWN_VULNERABLE_DEPENDENCY",\n                            Severity.HIGH,\n                            Confidence.HIGH,\n                            "supply-chain",\n                            "Dependency has a known OSV advisory",\n                            "An exact dependency version matched a vulnerability advisory.",\n                            "Upgrade to a fixed version and regenerate the immutable lockfile.",\n                            None,\n                            {\n                                "advisory_id": advisory_id,\n                                "package": package_name,\n                                "ecosystem": vulnerability.get("ecosystem"),\n                            },\n                        )\n                    )\n        except (OSError, ValueError, urllib.error.URLError) as exc:\n'''
    text = replace_once(text, osv_anchor, osv_insert, "OSV findings")
    text = text.replace(
        '''    def redirect_request(self, req: object, fp: object, code: int, msg: str, headers: object, newurl: str) -> None:\n''',
        '''    def redirect_request(  # type: ignore[override]\n        self, req: object, fp: object, code: int, msg: str, headers: object, newurl: str\n    ) -> None:\n''',
        1,
    )
    write(relative, text)


def patch_rust() -> None:
    relative = "rust/scanner-engine/src/main.rs"
    text = read(relative)
    if not text.startswith("#![forbid(unsafe_op_in_unsafe_fn)]"):
        text = "#![forbid(unsafe_op_in_unsafe_fn)]\n\n" + text
    text = text.replace("use std::path::PathBuf;", "use std::path::{Path, PathBuf};", 1)
    text = text.replace("fn read_file_bounded(path: &PathBuf, limit: usize)", "fn read_file_bounded(path: &Path, limit: usize)", 1)
    text = text.replace(
        "    for (needle, severity, category, capability, label) in rules {\n",
        "    for &(needle, severity, category, capability, label) in rules {\n",
        1,
    )
    text = text.replace(
        "    for (needle, severity, capability, label) in indicators {\n",
        "    for &(needle, severity, capability, label) in indicators {\n",
        1,
    )
    write(relative, text)


def patch_surface() -> None:
    relative = "src/codex_plugin_scanner/assurance/surface_scan.py"
    text = read(relative)
    dict_anchor = '''    if isinstance(value, dict):\n        for raw_key, item in value.items():\n'''
    dict_insert = '''    if isinstance(value, dict):\n        command_value = next(\n            (\n                item\n                for raw_key, item in value.items()\n                if str(raw_key).lower() in {"command", "cmd", "executable"}\n            ),\n            None,\n        )\n        argument_value = next(\n            (\n                item\n                for raw_key, item in value.items()\n                if str(raw_key).lower() in {"args", "arguments"}\n            ),\n            None,\n        )\n        if command_value is not None:\n            combined: object = command_value\n            if isinstance(argument_value, list):\n                prefix = [command_value] if isinstance(command_value, str) else list(command_value) if isinstance(command_value, list) else []\n                combined = [*prefix, *argument_value]\n            _inspect_command(combined, path, findings, capabilities, commands)\n        for raw_key, item in value.items():\n'''
    text = replace_once(text, dict_anchor, dict_insert, "combined MCP command")
    text = text.replace(
        '''            if lowered in {"command", "cmd", "executable"}:\n                _inspect_command(item, path, findings, capabilities, commands)\n            elif lowered in {"args", "arguments"} and isinstance(item, list):\n''',
        '''            if lowered in {"command", "cmd", "executable"}:\n                pass\n            elif lowered in {"args", "arguments"} and isinstance(item, list):\n''',
        1,
    )
    text = text.replace(
        '''                for match in URL_RE.findall(item):\n                    endpoints.add(match)\n                    capabilities.add("outbound-network")\n''',
        '''                for match in URL_RE.findall(item):\n                    canonical = _canonical_endpoint(match)\n                    if canonical is not None:\n                        endpoints.add(canonical)\n                        capabilities.add("outbound-network")\n''',
        1,
    )
    text = text.replace(
        '''        for endpoint in URL_RE.findall(value):\n            endpoints.add(endpoint)\n''',
        '''        for endpoint in URL_RE.findall(value):\n            canonical = _canonical_endpoint(endpoint)\n            if canonical is not None:\n                endpoints.add(canonical)\n''',
        1,
    )
    runner_anchor = '''    if executable in PACKAGE_RUNNERS:\n        package = next((part for part in parts[1:] if not part.startswith("-")), "")\n        if package and not _package_runner_target_pinned(package):\n'''
    runner_insert = '''    runner_parts = parts\n    if executable in SHELL_LAUNCHERS and "-c" in parts:\n        index = parts.index("-c")\n        if index + 1 < len(parts):\n            try:\n                runner_parts = shlex.split(parts[index + 1], posix=True)\n            except ValueError:\n                runner_parts = [parts[index + 1]]\n    runner_executable = Path(runner_parts[0]).name.lower() if runner_parts else ""\n    if runner_executable in PACKAGE_RUNNERS:\n        package = next((part for part in runner_parts[1:] if not part.startswith("-")), "")\n        if package and not _package_runner_target_pinned(package):\n'''
    text = replace_once(text, runner_anchor, runner_insert, "nested package runner")
    if "def _canonical_endpoint" not in text:
        helper_anchor = "\ndef _package_runner_target_pinned(value: str) -> bool:\n"
        helper = '''\ndef _canonical_endpoint(value: str) -> str | None:\n    try:\n        parsed = urllib.parse.urlsplit(value)\n    except ValueError:\n        return None\n    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:\n        return None\n    host = parsed.hostname.lower().rstrip(".")\n    try:\n        port = parsed.port\n    except ValueError:\n        return None\n    default_port = 80 if parsed.scheme.lower() == "http" else 443\n    authority = host if port in {None, default_port} else f"{host}:{port}"\n    path = parsed.path or "/"\n    return urllib.parse.urlunsplit((parsed.scheme.lower(), authority, path, "", ""))\n\n\ndef _package_runner_target_pinned(value: str) -> bool:\n'''
        text = replace_once(text, helper_anchor, helper, "canonical endpoint helper")
    write(relative, text)


def patch_evidence() -> None:
    relative = "src/codex_plugin_scanner/assurance/evidence.py"
    text = read(relative)
    required_anchor = '''    required = {\n        "schema_version",\n'''
    allowed_prefix = '''    allowed = {\n        "schema_version",\n        "scanner_version",\n        "artifact_root",\n        "artifact_digest",\n        "generated_at",\n        "assurance_level",\n        "coverage",\n        "findings",\n        "decision",\n        "layers",\n        "capabilities",\n        "dependencies",\n        "native_artifacts",\n        "archive_artifacts",\n        "policy",\n        "drift",\n        "provenance",\n        "detonation",\n        "evidence_digest",\n    }\n    unknown = set(payload) - allowed\n    if unknown:\n        raise EvidenceError(f"unknown assurance fields: {', '.join(sorted(unknown))}")\n    required = {\n        "schema_version",\n'''
    text = replace_once(text, required_anchor, allowed_prefix, "strict assurance fields")
    old_parse = '''def parse_json_document(raw: bytes, *, maximum_bytes: int = 32 * 1024 * 1024) -> object:\n    if len(raw) > maximum_bytes:\n        raise EvidenceError("JSON document exceeds size limit")\n    try:\n        return json.loads(raw)\n    except (UnicodeDecodeError, json.JSONDecodeError) as exc:\n        raise EvidenceError("document is not valid UTF-8 JSON") from exc\n'''
    new_parse = '''def parse_json_document(raw: bytes, *, maximum_bytes: int = 32 * 1024 * 1024) -> object:\n    if len(raw) > maximum_bytes:\n        raise EvidenceError("JSON document exceeds size limit")\n    try:\n        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)\n    except (UnicodeDecodeError, json.JSONDecodeError) as exc:\n        raise EvidenceError("document is not valid UTF-8 JSON") from exc\n    _validate_json_depth(value, depth=0)\n    return value\n\n\ndef _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:\n    value: dict[str, object] = {}\n    for key, item in pairs:\n        if key in value:\n            raise EvidenceError(f"duplicate JSON object key: {key}")\n        value[key] = item\n    return value\n\n\ndef _validate_json_depth(value: object, *, depth: int) -> None:\n    if depth > 64:\n        raise EvidenceError("JSON document exceeds nesting limit")\n    if isinstance(value, dict):\n        for item in value.values():\n            _validate_json_depth(item, depth=depth + 1)\n    elif isinstance(value, list):\n        for item in value:\n            _validate_json_depth(item, depth=depth + 1)\n'''
    text = replace_once(text, old_parse, new_parse, "duplicate JSON rejection")
    write(relative, text)


def patch_provenance() -> None:
    relative = "src/codex_plugin_scanner/assurance/provenance.py"
    text = read(relative)
    text = text.replace("    evidence_digest: str,\n", "    evidence_digest: str | None,\n", 1)
    text = text.replace(
        '''    _validate_sha256(evidence_digest, "evidence_digest")\n    return {\n''',
        '''    if evidence_digest is not None:\n        _validate_sha256(evidence_digest, "evidence_digest")\n    predicate: dict[str, Any] = {\n        "scannerVersion": scanner_version,\n        "decision": decision,\n        "coverageState": coverage_state,\n        "assuranceLevel": assurance_level,\n        "issuedAt": datetime.now(timezone.utc).isoformat(),\n    }\n    if evidence_digest is not None:\n        predicate["evidenceDigest"] = {"sha256": evidence_digest}\n    return {\n''',
        1,
    )
    old_predicate = '''        "predicate": {\n            "evidenceDigest": {"sha256": evidence_digest},\n            "scannerVersion": scanner_version,\n            "decision": decision,\n            "coverageState": coverage_state,\n            "assuranceLevel": assurance_level,\n            "issuedAt": datetime.now(timezone.utc).isoformat(),\n        },\n'''
    text = replace_once(text, old_predicate, '        "predicate": predicate,\n', "optional evidence digest")
    old_validate = '''    evidence_digest_record = predicate.get("evidenceDigest")\n    evidence_digest = (\n        evidence_digest_record.get("sha256") if isinstance(evidence_digest_record, dict) else None\n    )\n    if not isinstance(evidence_digest, str):\n        raise ProvenanceError("statement predicate lacks an evidence digest")\n    _validate_sha256(evidence_digest, "statement evidence digest")\n'''
    new_validate = '''    evidence_digest_record = predicate.get("evidenceDigest")\n    evidence_digest = (\n        evidence_digest_record.get("sha256") if isinstance(evidence_digest_record, dict) else None\n    )\n    if evidence_digest is not None:\n        if not isinstance(evidence_digest, str):\n            raise ProvenanceError("statement evidence digest is malformed")\n        _validate_sha256(evidence_digest, "statement evidence digest")\n'''
    text = replace_once(text, old_validate, new_validate, "optional statement evidence digest")
    text = text.replace(
        '''    if expected_evidence_digest is not None and evidence_digest != expected_evidence_digest:\n        raise ProvenanceError("statement evidence digest does not match the evidence envelope")\n''',
        '''    if expected_evidence_digest is not None:\n        if evidence_digest is None:\n            raise ProvenanceError("statement lacks the required evidence digest")\n        if evidence_digest != expected_evidence_digest:\n            raise ProvenanceError("statement evidence digest does not match the evidence envelope")\n''',
        1,
    )
    if "def build_artifact_statement" not in text:
        anchor = "\ndef sign_statement(statement: dict[str, Any], private_key_path: Path) -> dict[str, Any]:\n"
        helper = '''\ndef build_artifact_statement(\n    *,\n    artifact_digest: str,\n    scanner_version: str,\n) -> dict[str, Any]:\n    return build_statement(\n        artifact_digest=artifact_digest,\n        evidence_digest=None,\n        scanner_version=scanner_version,\n        decision="not-evaluated",\n        coverage_state="not-evaluated",\n        assurance_level="artifact-provenance",\n    )\n\n\ndef sign_statement(statement: dict[str, Any], private_key_path: Path) -> dict[str, Any]:\n'''
        text = replace_once(text, anchor, helper, "artifact statement helper")
    write(relative, text)


def patch_detonation() -> None:
    relative = "src/codex_plugin_scanner/assurance/detonation.py"
    text = read(relative)
    if "from .inventory import build_inventory" not in text:
        text = text.replace(
            "from .models import canonical_json_bytes\n",
            "from .inventory import build_inventory\nfrom .limits import ScanLimits\nfrom .models import canonical_json_bytes\n",
            1,
        )
    text = text.replace(
        "    artifact_root: str\n    command: tuple[str, ...]\n",
        "    artifact_root: str\n    artifact_digest: str\n    command: tuple[str, ...]\n",
        1,
    )
    digest_anchor = '''    if not resolved.is_dir():\n        raise DetonationError("artifact root must be a directory")\n'''
    digest_insert = '''    if not resolved.is_dir():\n        raise DetonationError("artifact root must be a directory")\n    if any(character in str(resolved) for character in ("\\n", "\\r", ",")):\n        raise DetonationError("artifact path cannot be represented safely in a container mount")\n    inventory = build_inventory(resolved, ScanLimits())\n    if inventory.limit_reached or any(\n        gap.code in {\n            "INVENTORY_FILE_UNREADABLE",\n            "INVENTORY_FILE_READ_FAILED",\n            "INVENTORY_DIRECTORY_UNREADABLE",\n        }\n        for gap in inventory.gaps\n    ):\n        raise DetonationError("artifact must be completely digest-bound before detonation")\n    artifact_digest = inventory.artifact_digest\n'''
    text = replace_once(text, digest_anchor, digest_insert, "detonation artifact digest")
    text = text.replace(
        '        "artifact_root": str(resolved),\n',
        '        "artifact_root": str(resolved),\n        "artifact_digest": artifact_digest,\n',
        1,
    )
    text = text.replace(
        '''        artifact_root=str(resolved),\n        command=command,\n''',
        '''        artifact_root=str(resolved),\n        artifact_digest=artifact_digest,\n        command=command,\n''',
        1,
    )
    text = text.replace("def _validate_plan_integrity(plan: DetonationPlan) -> None:\n", "def validate_plan(plan: DetonationPlan) -> None:\n", 1)
    text = text.replace("    _validate_plan_integrity(plan)\n", "    validate_plan(plan)\n", 1)
    if "def load_plan" not in text:
        anchor = "\ndef write_plan(path: Path, plan: DetonationPlan) -> None:\n"
        helper = '''\ndef load_plan(path: Path) -> DetonationPlan:\n    try:\n        raw = json.loads(path.read_text(encoding="utf-8"))\n    except (OSError, json.JSONDecodeError) as exc:\n        raise DetonationError(f"failed to load detonation plan: {exc}") from exc\n    if not isinstance(raw, dict):\n        raise DetonationError("detonation plan must be an object")\n    allowed = {\n        "schema_version",\n        "runtime",\n        "image",\n        "artifact_root",\n        "artifact_digest",\n        "command",\n        "container_arguments",\n        "limits",\n        "network",\n        "root_filesystem",\n        "user",\n        "security_options",\n        "plan_digest",\n    }\n    unknown = set(raw) - allowed\n    if unknown:\n        raise DetonationError(f"unknown detonation plan fields: {', '.join(sorted(unknown))}")\n    try:\n        plan = DetonationPlan(\n            schema_version=str(raw["schema_version"]),\n            runtime=str(raw["runtime"]),\n            image=str(raw["image"]),\n            artifact_root=str(raw["artifact_root"]),\n            artifact_digest=str(raw["artifact_digest"]),\n            command=tuple(str(item) for item in raw["command"]),\n            container_arguments=tuple(str(item) for item in raw["container_arguments"]),\n            limits=DetonationLimits(**raw["limits"]),\n            network=str(raw["network"]),\n            root_filesystem=str(raw["root_filesystem"]),\n            user=str(raw["user"]),\n            security_options=tuple(str(item) for item in raw["security_options"]),\n            plan_digest=str(raw["plan_digest"]),\n        )\n    except (KeyError, TypeError) as exc:\n        raise DetonationError("detonation plan shape is invalid") from exc\n    validate_plan(plan)\n    return plan\n\n\ndef write_plan(path: Path, plan: DetonationPlan) -> None:\n'''
        text = replace_once(text, anchor, helper, "strict plan loader")
    validate_anchor = '''    if plan.network != "none" or plan.root_filesystem != "read-only":\n        raise DetonationError("detonation plan weakened mandatory isolation")\n'''
    validate_insert = '''    if plan.schema_version != "hol-guard.detonation-plan.v1":\n        raise DetonationError("unsupported detonation plan schema")\n    if not re.fullmatch(r"[0-9a-f]{64}", plan.artifact_digest):\n        raise DetonationError("detonation plan artifact digest is invalid")\n    if plan.network != "none" or plan.root_filesystem != "read-only":\n        raise DetonationError("detonation plan weakened mandatory isolation")\n'''
    text = replace_once(text, validate_anchor, validate_insert, "plan schema validation")
    write(relative, text)


def patch_orchestrator() -> None:
    relative = "src/codex_plugin_scanner/assurance/orchestrator.py"
    text = read(relative)
    text = text.replace(
        "from .detonation import validate_observation\n",
        "from .detonation import load_plan, validate_observation\n",
        1,
    )
    text = text.replace(
        "    detonation_payload, detonation_observed, plan_present = _load_detonation(options)\n",
        '''    detonation_payload, detonation_observed, plan_present = _load_detonation(\n        options, artifact_digest=inventory.artifact_digest\n    )\n''',
        1,
    )
    text = text.replace(
        '''def _load_detonation(\n    options: AssuranceOptions,\n) -> tuple[dict[str, Any] | None, bool, bool]:\n''',
        '''def _load_detonation(\n    options: AssuranceOptions,\n    *,\n    artifact_digest: str,\n) -> tuple[dict[str, Any] | None, bool, bool]:\n''',
        1,
    )
    old_plan_load = '''    try:\n        plan = json.loads(options.detonation_plan_path.read_text(encoding="utf-8"))\n    except (OSError, json.JSONDecodeError):\n        return {"planned": False, "observed": False, "reason": "detonation plan could not be loaded"}, False, False\n    plan_digest = plan.get("plan_digest") if isinstance(plan, dict) else None\n    if not isinstance(plan_digest, str):\n        return {"planned": False, "observed": False, "reason": "detonation plan digest is missing"}, False, False\n'''
    new_plan_load = '''    try:\n        plan = load_plan(options.detonation_plan_path)\n    except (OSError, ValueError) as exc:\n        return {\n            "planned": False,\n            "observed": False,\n            "reason": f"detonation plan validation failed: {type(exc).__name__}",\n        }, False, False\n    plan_digest = plan.plan_digest\n    if plan.artifact_digest != artifact_digest:\n        return {\n            "planned": False,\n            "observed": False,\n            "reason": "detonation plan is bound to a different artifact digest",\n        }, False, False\n'''
    text = replace_once(text, old_plan_load, new_plan_load, "bound detonation plan")
    text = text.replace(
        '''            "planned": True,\n            "observed": False,\n            "plan_digest": plan_digest,\n''',
        '''            "planned": True,\n            "observed": False,\n            "plan_digest": plan_digest,\n            "artifact_digest": plan.artifact_digest,\n''',
    )
    text = text.replace(
        '''        "plan_digest": plan_digest,\n        "observation_digest": observation.get("observation_digest"),\n''',
        '''        "plan_digest": plan_digest,\n        "artifact_digest": plan.artifact_digest,\n        "observation_digest": observation.get("observation_digest"),\n''',
        1,
    )
    old_findings = '''    findings.extend(_correlate(findings, capabilities, dependency_result, surface_result))\n    findings = _dedupe_sort(findings)[: options.limits.max_findings]\n'''
    new_findings = '''    findings.extend(_correlate(findings, capabilities, dependency_result, surface_result))\n    findings = _dedupe_sort(findings)\n    if len(findings) > options.limits.max_findings:\n        omitted = len(findings) - options.limits.max_findings + 1\n        component_complete = False\n        findings = findings[: options.limits.max_findings - 1]\n        findings.append(\n            SecurityFinding(\n                rule_id="ASSURANCE_FINDING_LIMIT_REACHED",\n                severity=Severity.HIGH,\n                confidence=Confidence.HIGH,\n                category="coverage",\n                title="Finding limit reached",\n                description="Additional findings were omitted after the managed result bound was reached.",\n                remediation="Review the highest-severity findings, split the artifact, and rerun without weakening managed limits.",\n                metadata={"omitted": omitted},\n            ).with_fingerprint()\n        )\n'''
    text = replace_once(text, old_findings, new_findings, "finding truncation coverage")
    text = text.replace(
        '''        if text_findings or entry.path.suffix.lower() in TEXT_SUFFIXES:\n            findings.extend(text_findings)\n            capabilities.update(text_capabilities)\n            analyzed_files += 1\n            analyzed_bytes += read_bytes\n''',
        '''        if text_findings or entry.path.suffix.lower() in TEXT_SUFFIXES:\n            findings.extend(text_findings)\n            capabilities.update(text_capabilities)\n            analyzed_files += 1\n            analyzed_bytes += read_bytes\n            if entry.size > read_bytes:\n                component_complete = False\n                findings.append(\n                    SecurityFinding(\n                        rule_id="ASSURANCE_TEXT_ANALYSIS_TRUNCATED",\n                        severity=Severity.MEDIUM,\n                        confidence=Confidence.HIGH,\n                        category="coverage",\n                        title="Text analysis was truncated",\n                        description="The complete file is digest-bound, but semantic analysis reached the managed text-byte limit.",\n                        remediation="Review the file independently or split generated content into auditable components.",\n                        locations=(EvidenceLocation(path=entry.relative_path),),\n                        metadata={"size": entry.size, "analyzed_bytes": read_bytes},\n                    ).with_fingerprint()\n                )\n''',
        1,
    )
    write(relative, text)


def patch_cli() -> None:
    relative = "src/codex_plugin_scanner/assurance_cli.py"
    text = read(relative)
    text = text.replace(
        "from .assurance.detonation import DetonationLimits, build_plan, execute_plan, write_plan\n",
        "from .assurance.detonation import DetonationLimits, build_plan, execute_plan, load_plan, write_plan\n",
        1,
    )
    text = text.replace(
        "    build_statement,\n",
        "    build_artifact_statement,\n    build_statement,\n",
        1,
    )
    if 'commands.add_parser("attest-artifact"' not in text:
        anchor = '''    attest = commands.add_parser("attest", help="Sign an assurance report as DSSE provenance")\n'''
        insert = '''    artifact_attest = commands.add_parser(\n        "attest-artifact", help="Sign exact artifact provenance before scanning"\n    )\n    artifact_attest.add_argument("target", nargs="?", default=".")\n    artifact_attest.add_argument("--private-key", type=Path, required=True)\n    artifact_attest.add_argument("--output", type=Path, required=True)\n\n    attest = commands.add_parser("attest", help="Sign an assurance report as DSSE provenance")\n'''
        text = replace_once(text, anchor, insert, "artifact attest parser")
    text = text.replace(
        '''        if args.command == "attest":\n            return _run_attest(args)\n''',
        '''        if args.command == "attest-artifact":\n            return _run_attest_artifact(args)\n        if args.command == "attest":\n            return _run_attest(args)\n''',
        1,
    )
    if "def _run_attest_artifact" not in text:
        anchor = "\ndef _run_attest(args: argparse.Namespace) -> int:\n"
        helper = '''\ndef _run_attest_artifact(args: argparse.Namespace) -> int:\n    report = scan_extension_assurance(args.target, AssuranceOptions(profile="audit"))\n    statement = build_artifact_statement(\n        artifact_digest=report.artifact_digest,\n        scanner_version=report.scanner_version,\n    )\n    signed = sign_statement(statement, args.private_key)\n    _emit_json(signed, args.output)\n    return 0\n\n\ndef _run_attest(args: argparse.Namespace) -> int:\n'''
        text = replace_once(text, anchor, helper, "artifact attest runner")
    old_detonate = '''def _run_detonate(args: argparse.Namespace) -> int:\n    raw = parse_json_document(args.plan.read_bytes())\n    if not isinstance(raw, dict):\n        raise ValueError("detonation plan must be an object")\n    limits = DetonationLimits(**raw["limits"])\n    from .assurance.detonation import DetonationPlan\n\n    plan = DetonationPlan(\n        schema_version=raw["schema_version"],\n        runtime=raw["runtime"],\n        image=raw["image"],\n        artifact_root=raw["artifact_root"],\n        command=tuple(raw["command"]),\n        container_arguments=tuple(raw["container_arguments"]),\n        limits=limits,\n        network=raw["network"],\n        root_filesystem=raw["root_filesystem"],\n        user=raw["user"],\n        security_options=tuple(raw["security_options"]),\n        plan_digest=raw["plan_digest"],\n    )\n    observation = execute_plan(plan)\n'''
    new_detonate = '''def _run_detonate(args: argparse.Namespace) -> int:\n    plan = load_plan(args.plan)\n    observation = execute_plan(plan)\n'''
    text = replace_once(text, old_detonate, new_detonate, "strict detonation CLI loader")
    text = text.replace(
        '    latest.add_argument("--subject", required=True)\n',
        '    latest.add_argument("--subject", required=True)\n    latest.add_argument("--publishable-only", action="store_true")\n',
        1,
    )
    text = text.replace(
        "    value = EvidenceStore(args.database).latest(args.tenant, args.subject)\n",
        '''    value = EvidenceStore(args.database).latest(\n        args.tenant, args.subject, publishable_only=args.publishable_only\n    )\n''',
        1,
    )
    write(relative, text)


def patch_tests() -> None:
    relative = "tests/test_assurance_policy_ingestion.py"
    text = read(relative)
    text = text.replace(
        '''def _benign_report(tmp_path: Path) -> dict[str, object]:\n    (tmp_path / "README.md").write_text''',
        '''def _benign_report(tmp_path: Path) -> dict[str, object]:\n    tmp_path.mkdir(parents=True, exist_ok=True)\n    (tmp_path / "README.md").write_text''',
        1,
    )
    if "test_blocking_evidence_is_quarantined" not in text:
        text += '''\n\ndef test_blocking_evidence_is_quarantined_for_investigation(tmp_path: Path) -> None:\n    plugin = tmp_path / "hostile"\n    plugin.mkdir()\n    (plugin / "steal.py").write_text(\n        "requests.get('http://169.254.169.254/latest/meta-data/')",\n        encoding="utf-8",\n    )\n    report = scan_extension_assurance(plugin).to_payload()\n    envelope = build_evidence_envelope(\n        report, tenant_id="tenant-a", subject_id="hostile-plugin"\n    )\n    result = EvidenceStore(tmp_path / "evidence.sqlite3").ingest(\n        envelope, policy=BUILTIN_POLICIES["balanced"]\n    )\n    assert result.status == "quarantined"\n    assert result.publishable is False\n    assert result.disposition in {"block", "error"}\n    assert EvidenceStore(tmp_path / "evidence.sqlite3").latest(\n        "tenant-a", "hostile-plugin", publishable_only=True\n    ) is None\n'''
    write(relative, text)


def main() -> None:
    patch_pyproject()
    patch_archive()
    patch_dependency()
    patch_rust()
    patch_surface()
    patch_evidence()
    patch_provenance()
    patch_detonation()
    patch_orchestrator()
    patch_cli()
    patch_tests()


if __name__ == "__main__":
    main()
