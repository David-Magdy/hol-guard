"""Deterministic longitudinal drift baselines for approved extensions."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import canonical_json_bytes


BASELINE_SCHEMA = "hol-guard.extension-baseline.v1"
DRIFT_SCHEMA = "hol-guard.extension-drift.v1"


class DriftError(ValueError):
    pass


def build_baseline(
    *,
    artifact_digest: str,
    files: tuple[dict[str, Any], ...],
    dependencies: tuple[dict[str, Any], ...],
    native_artifacts: tuple[dict[str, Any], ...],
    capabilities: tuple[str, ...],
    endpoints: tuple[str, ...] = (),
    commands: tuple[str, ...] = (),
    lifecycle_scripts: tuple[str, ...] = (),
    security_controls: tuple[str, ...] = (),
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": BASELINE_SCHEMA,
        "artifact_digest": artifact_digest,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "files": sorted(files, key=lambda item: str(item.get("path", ""))),
        "dependencies": sorted(
            dependencies,
            key=lambda item: (
                str(item.get("ecosystem", "")),
                str(item.get("name", "")),
                str(item.get("version", "")),
            ),
        ),
        "native_artifacts": sorted(
            native_artifacts, key=lambda item: str(item.get("path", item.get("display_path", "")))
        ),
        "capabilities": sorted(set(capabilities)),
        "endpoints": sorted(set(endpoints)),
        "commands": sorted(set(commands)),
        "lifecycle_scripts": sorted(set(lifecycle_scripts)),
        "security_controls": sorted(set(security_controls)),
    }
    payload["baseline_digest"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return payload


def load_baseline(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DriftError(f"failed to load baseline: {exc}") from exc
    validate_baseline(payload)
    return payload


def validate_baseline(payload: object) -> None:
    if not isinstance(payload, dict):
        raise DriftError("baseline must be a JSON object")
    allowed = {
        "schema_version",
        "artifact_digest",
        "created_at",
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
    if unknown:
        raise DriftError(f"unknown baseline fields: {', '.join(sorted(unknown))}")
    if payload.get("schema_version") != BASELINE_SCHEMA:
        raise DriftError("unsupported baseline schema")
    expected = payload.get("baseline_digest")
    if not isinstance(expected, str):
        raise DriftError("baseline_digest is required")
    unsigned = dict(payload)
    unsigned.pop("baseline_digest", None)
    actual = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    if actual != expected:
        raise DriftError("baseline digest mismatch")
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
            raise DriftError(f"{field_name} must be an array")


def compare_baseline(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    validate_baseline(baseline)
    validate_baseline(current)
    file_changes = _compare_keyed(
        baseline["files"],
        current["files"],
        key=lambda item: str(item.get("path", "")),
        value=lambda item: (item.get("sha256"), item.get("mode"), item.get("size")),
    )
    dependency_changes = _compare_keyed(
        baseline["dependencies"],
        current["dependencies"],
        key=lambda item: f"{item.get('ecosystem')}:{item.get('name')}",
        value=lambda item: (item.get("version"), item.get("source"), item.get("integrity")),
    )
    native_changes = _compare_keyed(
        baseline["native_artifacts"],
        current["native_artifacts"],
        key=lambda item: str(item.get("path", item.get("display_path", ""))),
        value=lambda item: (item.get("sha256"), item.get("format"), item.get("architecture")),
    )
    set_changes = {
        name: _compare_sets(baseline[name], current[name])
        for name in (
            "capabilities",
            "endpoints",
            "commands",
            "lifecycle_scripts",
            "security_controls",
        )
    }
    security_regressions = {
        "new_capabilities": set_changes["capabilities"]["added"],
        "new_endpoints": set_changes["endpoints"]["added"],
        "new_commands": set_changes["commands"]["added"],
        "new_lifecycle_scripts": set_changes["lifecycle_scripts"]["added"],
        "removed_security_controls": set_changes["security_controls"]["removed"],
        "new_native_artifacts": native_changes["added"],
    }
    changed = any(
        (
            file_changes["added"],
            file_changes["removed"],
            file_changes["changed"],
            dependency_changes["added"],
            dependency_changes["removed"],
            dependency_changes["changed"],
            native_changes["added"],
            native_changes["removed"],
            native_changes["changed"],
            *(value for change in set_changes.values() for value in change.values()),
        )
    )
    risk_score = _risk_score(security_regressions, file_changes, dependency_changes)
    payload: dict[str, Any] = {
        "schema_version": DRIFT_SCHEMA,
        "baseline_digest": baseline["baseline_digest"],
        "current_baseline_digest": current["baseline_digest"],
        "artifact_digest_before": baseline["artifact_digest"],
        "artifact_digest_after": current["artifact_digest"],
        "changed": changed,
        "risk_score": risk_score,
        "requires_reapproval": risk_score > 0,
        "files": file_changes,
        "dependencies": dependency_changes,
        "native_artifacts": native_changes,
        "sets": set_changes,
        "security_regressions": security_regressions,
    }
    payload["drift_digest"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return payload


def write_baseline(path: Path, baseline: dict[str, Any]) -> None:
    validate_baseline(baseline)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(baseline, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def _compare_keyed(
    before: list[object],
    after: list[object],
    *,
    key: Any,
    value: Any,
) -> dict[str, Any]:
    before_map = {key(item): item for item in before if isinstance(item, dict)}
    after_map = {key(item): item for item in after if isinstance(item, dict)}
    added = sorted(set(after_map) - set(before_map))
    removed = sorted(set(before_map) - set(after_map))
    changed = sorted(
        item_key
        for item_key in set(before_map) & set(after_map)
        if value(before_map[item_key]) != value(after_map[item_key])
    )
    return {"added": added, "removed": removed, "changed": changed}


def _compare_sets(before: list[object], after: list[object]) -> dict[str, list[str]]:
    before_set = {str(item) for item in before}
    after_set = {str(item) for item in after}
    return {"added": sorted(after_set - before_set), "removed": sorted(before_set - after_set)}


def _risk_score(
    regressions: dict[str, list[str]],
    files: dict[str, list[str]],
    dependencies: dict[str, list[str]],
) -> int:
    score = 0
    score += 20 * len(regressions["new_capabilities"])
    score += 15 * len(regressions["new_endpoints"])
    score += 20 * len(regressions["new_commands"])
    score += 25 * len(regressions["new_lifecycle_scripts"])
    score += 30 * len(regressions["removed_security_controls"])
    score += 30 * len(regressions["new_native_artifacts"])
    score += 5 * len(dependencies["added"])
    score += 10 * len(dependencies["changed"])
    score += min(20, len(files["changed"]))
    return min(100, score)
