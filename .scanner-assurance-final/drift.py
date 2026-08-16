# pyright: basic
"""Deterministic extension baselines and security-relevant longitudinal drift."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import canonical_json_bytes


BASELINE_SCHEMA = "hol-guard.extension-baseline.v1"


class DriftError(ValueError):
    pass


def build_baseline(
    *,
    artifact_digest: str,
    files: tuple[dict[str, Any], ...],
    dependencies: tuple[dict[str, Any], ...],
    native_artifacts: tuple[dict[str, Any], ...],
    capabilities: tuple[str, ...],
    endpoints: tuple[str, ...],
    commands: tuple[str, ...],
    lifecycle_scripts: tuple[str, ...],
    security_controls: tuple[str, ...],
) -> dict[str, Any]:
    _validate_sha256(artifact_digest, "artifact_digest")
    normalized: dict[str, Any] = {
        "schema_version": BASELINE_SCHEMA,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "artifact_digest": artifact_digest,
        "files": sorted((dict(item) for item in files), key=_file_key),
        "dependencies": sorted((dict(item) for item in dependencies), key=_dependency_key),
        "native_artifacts": sorted((dict(item) for item in native_artifacts), key=_native_key),
        "capabilities": sorted(set(capabilities)),
        "endpoints": sorted(set(endpoints)),
        "commands": sorted(set(commands)),
        "lifecycle_scripts": sorted(set(lifecycle_scripts)),
        "security_controls": sorted(set(security_controls)),
    }
    normalized["baseline_digest"] = hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()
    validate_baseline(normalized)
    return normalized


def write_baseline(path: Path, baseline: dict[str, Any]) -> None:
    validate_baseline(baseline)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(baseline, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def load_baseline(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise DriftError(f"failed to read baseline: {exc}") from exc
    if len(raw) > 64 * 1024 * 1024:
        raise DriftError("baseline exceeds size limit")
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DriftError("baseline is not valid unambiguous UTF-8 JSON") from exc
    validate_baseline(payload)
    return dict(payload)


def validate_baseline(payload: object) -> None:
    if not isinstance(payload, dict):
        raise DriftError("baseline must be an object")
    allowed = {
        "schema_version",
        "created_at",
        "artifact_digest",
        "files",
        "dependencies",
        "native_artifacts",
        "capabilities",
        "endpoints",
        "commands",
        "lifecycle_scripts",
        "security_controls",
        "baseline_digest",
    }
    unknown = set(payload) - allowed
    missing = allowed - set(payload)
    if unknown or missing:
        raise DriftError("baseline fields are incomplete or unknown")
    if payload.get("schema_version") != BASELINE_SCHEMA:
        raise DriftError("unsupported baseline schema")
    artifact_digest = payload.get("artifact_digest")
    baseline_digest = payload.get("baseline_digest")
    if not isinstance(artifact_digest, str):
        raise DriftError("baseline artifact_digest is invalid")
    _validate_sha256(artifact_digest, "baseline artifact_digest")
    if not isinstance(baseline_digest, str):
        raise DriftError("baseline_digest is invalid")
    _validate_sha256(baseline_digest, "baseline_digest")
    for field_name in (
        "files",
        "dependencies",
        "native_artifacts",
        "capabilities",
        "endpoints",
        "commands",
        "lifecycle_scripts",
        "security_controls",
    ):
        if not isinstance(payload.get(field_name), list):
            raise DriftError(f"baseline {field_name} must be an array")
    unsigned = dict(payload)
    unsigned.pop("baseline_digest", None)
    actual = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    if actual != baseline_digest:
        raise DriftError("baseline digest mismatch")


def compare_baseline(
    approved: dict[str, Any],
    current: dict[str, Any],
) -> dict[str, Any]:
    validate_baseline(approved)
    validate_baseline(current)
    approved_files = _index(approved["files"], _file_key)
    current_files = _index(current["files"], _file_key)
    added_files = sorted(set(current_files) - set(approved_files))
    removed_files = sorted(set(approved_files) - set(current_files))
    modified_files = sorted(
        key
        for key in set(approved_files) & set(current_files)
        if _semantic_json(approved_files[key]) != _semantic_json(current_files[key])
    )

    added_dependencies, removed_dependencies, changed_dependencies = _compare_records(
        approved["dependencies"],
        current["dependencies"],
        _dependency_key,
    )
    added_native, removed_native, changed_native = _compare_records(
        approved["native_artifacts"],
        current["native_artifacts"],
        _native_key,
    )
    added_capabilities = _added(approved["capabilities"], current["capabilities"])
    removed_capabilities = _added(current["capabilities"], approved["capabilities"])
    added_endpoints = _added(approved["endpoints"], current["endpoints"])
    removed_endpoints = _added(current["endpoints"], approved["endpoints"])
    added_commands = _added(approved["commands"], current["commands"])
    removed_commands = _added(current["commands"], approved["commands"])
    added_scripts = _added(approved["lifecycle_scripts"], current["lifecycle_scripts"])
    removed_scripts = _added(current["lifecycle_scripts"], approved["lifecycle_scripts"])
    removed_controls = _added(current["security_controls"], approved["security_controls"])
    added_controls = _added(approved["security_controls"], current["security_controls"])

    reasons: list[str] = []
    if added_capabilities:
        reasons.append("new capabilities")
    if added_endpoints:
        reasons.append("new network endpoints")
    if added_commands:
        reasons.append("new execution commands")
    if added_scripts:
        reasons.append("new lifecycle scripts")
    if removed_controls:
        reasons.append("removed security controls")
    if added_native or changed_native:
        reasons.append("new or changed native artifacts")
    if added_dependencies or changed_dependencies:
        reasons.append("new or changed dependencies")
    executable_changes = [
        path
        for path in [*added_files, *modified_files]
        if _file_is_executable(current_files.get(path))
    ]
    if executable_changes:
        reasons.append("new or changed executable files")

    payload: dict[str, Any] = {
        "schema_version": "hol-guard.extension-drift.v1",
        "approved_artifact_digest": approved["artifact_digest"],
        "current_artifact_digest": current["artifact_digest"],
        "changed": approved["artifact_digest"] != current["artifact_digest"],
        "requires_reapproval": bool(reasons),
        "reapproval_reasons": reasons,
        "files": {
            "added": added_files,
            "removed": removed_files,
            "modified": modified_files,
            "executable_changes": executable_changes,
        },
        "dependencies": {
            "added": added_dependencies,
            "removed": removed_dependencies,
            "changed": changed_dependencies,
        },
        "native_artifacts": {
            "added": added_native,
            "removed": removed_native,
            "changed": changed_native,
        },
        "capabilities": {"added": added_capabilities, "removed": removed_capabilities},
        "endpoints": {"added": added_endpoints, "removed": removed_endpoints},
        "commands": {"added": added_commands, "removed": removed_commands},
        "lifecycle_scripts": {"added": added_scripts, "removed": removed_scripts},
        "security_controls": {"added": added_controls, "removed": removed_controls},
    }
    payload["drift_digest"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return payload


def _compare_records(
    approved: list[object],
    current: list[object],
    key_function: Any,
) -> tuple[list[str], list[str], list[str]]:
    approved_index = _index(approved, key_function)
    current_index = _index(current, key_function)
    added = sorted(set(current_index) - set(approved_index))
    removed = sorted(set(approved_index) - set(current_index))
    changed = sorted(
        key
        for key in set(approved_index) & set(current_index)
        if _semantic_json(approved_index[key]) != _semantic_json(current_index[key])
    )
    return added, removed, changed


def _index(values: Iterable[object], key_function: Any) -> dict[str, object]:
    result: dict[str, object] = {}
    for value in values:
        if not isinstance(value, dict):
            continue
        result[key_function(value)] = value
    return result


def _file_key(value: dict[str, Any]) -> str:
    return str(value.get("path", ""))


def _dependency_key(value: dict[str, Any]) -> str:
    return "|".join(
        (
            str(value.get("ecosystem", "")),
            str(value.get("name", "")),
            str(value.get("manifest", "")),
        )
    )


def _native_key(value: dict[str, Any]) -> str:
    return str(value.get("path", ""))


def _file_is_executable(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    mode = value.get("mode")
    path = str(value.get("path", "")).lower()
    return (isinstance(mode, int) and mode & 0o111 != 0) or path.endswith(
        (".exe", ".dll", ".so", ".dylib", ".wasm", ".sh", ".bash", ".ps1", ".bat", ".cmd")
    )


def _added(previous: list[object], current: list[object]) -> list[str]:
    return sorted(str(value) for value in set(current) - set(previous))


def _semantic_json(value: object) -> bytes:
    return canonical_json_bytes(value)


def _validate_sha256(value: str, field_name: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise DriftError(f"{field_name} must be a lowercase SHA-256 digest")


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DriftError(f"duplicate baseline key: {key}")
        result[key] = value
    return result
