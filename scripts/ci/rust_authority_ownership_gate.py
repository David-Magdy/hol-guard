#!/usr/bin/env python3
"""Enforce HOL Guard's permanent Rust runtime authority boundary."""

from __future__ import annotations

import argparse
import ast
import json
import re
from pathlib import Path
from typing import Final

SCHEMA: Final = "hol-guard-rust-authority-ownership.v1"
MANIFEST = Path("ci/rust-authority-ownership.v1.json")

TEMPORARY_PATHS: Final = (
    Path(".github/workflows/rust-local-toolchain-export.yml"),
    Path(".github/workflows/rust-pretool-authority-bootstrap.yml"),
    Path(".github/workflows/rust-pretool-authority-orchestrator.yml"),
    Path(".github/workflows/rust-authority-batch1-finalize.yml"),
    Path(".github/workflows/rust-authority-batch1-merge-gate.yml"),
    Path(".github/workflows/rust-posttool-authority-bootstrap.yml"),
    Path(".github/workflows/rust-posttool-authority-orchestrator.yml"),
    Path(".github/workflows/rust-posttool-authority-lint-fix.yml"),
    Path(".github/workflows/rust-authority-batch2-merge-gate.yml"),
    Path(".github/workflows/rust-authority-batch2-retry-merge-v2.yml"),
    Path(".github/workflows/rust-authority-batch2-converge-v3.yml"),
    Path(".github/workflows/rust-authority-batch2-converge-v4.yml"),
    Path(".github/workflows/rust-authority-final-orchestrator.yml"),
    Path(".github/workflows/rust-authority-final-lint-fix.yml"),
    Path(".github/workflows/rust-authority-final-merge-gate.yml"),
    Path(".github/workflows/rust-authority-final-retry-merge-v2.yml"),
    Path(".github/workflows/rust-authority-batch3-converge-v3.yml"),
    Path("scripts/ci/bootstrap_rust_pretool_authority.sh"),
    Path("scripts/ci/bootstrap_rust_posttool_authority.sh"),
    Path("scripts/ci/fallback_rust_posttool_authority.py"),
    Path("scripts/ci/converge_rust_posttool_authority_v2.py"),
    Path("scripts/ci/harden_rust_policy_snapshot_v3.py"),
    Path("scripts/ci/select_rust_posttool_authority_candidate_v2.sh"),
    Path("scripts/ci/rust_authority_ownership_gate_v2.py"),
    Path("scripts/ci/rust_authority_ownership_gate_v3.py"),
    Path("scripts/ci/finalize_rust_authority_migration.py"),
    Path("scripts/ci/finalize_rust_authority_migration_v2.py"),
    Path("docs/guard/.batch1-merge-probe"),
    Path("docs/guard/rust-authority-batch-2-bootstrap.md"),
    Path("rust/AUTHORITY_BATCH_1"),
    Path("rust/AUTHORITY_BATCH_1_FINAL"),
    Path("rust/AUTHORITY_BATCH_2"),
    Path("rust/AUTHORITY_BATCH_2_FINAL"),
    Path("rust/AUTHORITY_FINAL"),
)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise RuntimeError(f"required authority source is missing: {path}") from exc


def _python_imports_function(path: Path, module_suffix: str, name: str) -> bool:
    tree = ast.parse(_read(path), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").endswith(module_suffix):
            if any(alias.name == name for alias in node.names):
                return True
    return False


def _manifest() -> dict[str, object]:
    value = json.loads(_read(MANIFEST))
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise RuntimeError("Rust authority ownership manifest has an invalid schema")
    surfaces = value.get("surfaces")
    if not isinstance(surfaces, dict):
        raise RuntimeError("Rust authority ownership manifest has no surfaces")
    for key in ("pre_tool_use", "post_tool_use"):
        surface = surfaces.get(key)
        if not isinstance(surface, dict):
            raise RuntimeError(f"Rust authority surface is missing: {key}")
        if surface.get("semantic_authority") != "rust" or surface.get("python_semantic_fallback") is not False:
            raise RuntimeError(f"Rust authority surface is not exclusive: {key}")
        if surface.get("native_failure") != "fail_closed":
            raise RuntimeError(f"Rust authority surface is not fail closed: {key}")
    return value


def _pretool_gate() -> None:
    pretool = Path("src/codex_plugin_scanner/guard/native_pretool.py")
    if _python_imports_function(pretool, "command_evaluation", "evaluate_command"):
        raise RuntimeError("native PreToolUse transport imports the Python command evaluator")
    if "evaluate_command(" in _read(pretool):
        raise RuntimeError("native PreToolUse transport calls the Python command evaluator")

    hook = _read(Path("src/codex_plugin_scanner/guard/daemon/hook_worker.py"))
    if "review_pre_tool_native" not in hook:
        raise RuntimeError("PreToolUse hook path is not bound to the native runtime")
    region = re.search(
        r'if event_name\s*==\s*"PreToolUse":[\s\S]*?(?=\n\s*if event_name\s*!=\s*"PostToolUse")',
        hook,
    )
    if region is None:
        raise RuntimeError("daemon has no Rust PreToolUse authority route")
    if "self.engine.review(" in region.group(0):
        raise RuntimeError("PreToolUse can reach the Python HookReviewEngine")
    if "native_pre_tool_unavailable" not in region.group(0):
        raise RuntimeError("PreToolUse does not fail closed when native is unavailable")

    command_model = Path("src/codex_plugin_scanner/guard/native_command_model.py")
    if command_model.exists():
        model = _read(command_model)
        if 'status.mode not in {"shadow", "force"}' not in model:
            raise RuntimeError("command-model bridge is not confined to shadow or force")
        if "Python remains authoritative" in model:
            raise RuntimeError("command-model bridge still declares Python authority")

    runtime = _read(Path("rust/crates/guard-runtime/src/main.rs"))
    command = _read(Path("rust/crates/guard-command/src/lib.rs"))
    combined = runtime + "\n" + command
    if not re.search(r"PreToolUse|pre_tool|pre-tool", combined):
        raise RuntimeError("Rust runtime does not implement PreToolUse authority")


def _posttool_gate() -> None:
    hook = _read(Path("src/codex_plugin_scanner/guard/daemon/hook_worker.py"))
    if re.search(
        r"if response is None:\s*response = self\.engine\.review\(request\)",
        hook,
    ):
        raise RuntimeError("supported PostToolUse still spills into Python semantic evaluation")

    native = _read(Path("src/codex_plugin_scanner/guard/native_runtime.py"))
    if "currently supported Python reference backend remains authoritative" in native:
        raise RuntimeError("native runtime still declares Python PostToolUse authority")

    core = _read(Path("rust/crates/guard-hook-core/src/lib.rs"))
    for required in ("review_post_tool", "read_bounded", "scan_text"):
        if required not in core:
            raise RuntimeError(f"Rust PostToolUse core is missing {required}")


def _mode_gate() -> None:
    relevant = [
        Path("src/codex_plugin_scanner/guard/native_runtime.py"),
        Path("src/codex_plugin_scanner/guard/native_command_model.py"),
        Path("docs/guard/all-harness-hook-review.md"),
        Path("docs/guard/harness-support.md"),
    ]
    strict_mode = re.compile(r"(?i)(native|rust|runtime)[-_ ]strict|strict[-_ ]mode|mode[=: ]+strict")
    found: list[str] = []
    for path in relevant:
        if path.exists() and strict_mode.search(_read(path)):
            found.append(str(path))
    if found:
        raise RuntimeError(f"retired strict-mode terminology remains: {found}")


def _policy_and_identity_gate() -> None:
    cargo = _read(Path("rust/crates/guard-runtime/Cargo.toml"))
    runtime = _read(Path("rust/crates/guard-runtime/src/main.rs"))
    native = _read(Path("src/codex_plugin_scanner/guard/native_runtime.py"))
    release = _read(Path("scripts/verify_native_runtime_release.py"))
    if "guard-policy-snapshot" not in cargo:
        raise RuntimeError("hol-guard-runtime does not link guard-policy-snapshot")
    if "PolicySnapshot" not in runtime and "policy_snapshot" not in runtime:
        raise RuntimeError("hol-guard-runtime does not consume policy snapshots")
    if "rule_digest" not in runtime:
        raise RuntimeError("native policy snapshot is not rule-digest bound")
    for required in (
        "native_manifest_runtime_mismatch",
        "native_manifest_version_mismatch",
        "native_manifest_rule_mismatch",
        "runtime_sha256",
    ):
        if required not in native and required not in release:
            raise RuntimeError(f"bundled runtime identity guard is missing: {required}")


def _workflow_gate() -> None:
    path = Path(".github/workflows/rust-authority-ownership.yml")
    source = _read(path)
    required_paths = (
        '"rust/**"',
        '"src/codex_plugin_scanner/guard/**"',
        '"ci/native_runtime/**"',
        '"scripts/**"',
        '".github/workflows/**"',
    )
    missing = [value for value in required_paths if value not in source]
    if missing:
        raise RuntimeError(f"authority workflow path coverage is incomplete: {missing}")
    required_commands = (
        "rust_pretool_authority_integration.py",
        "rust_posttool_failclosed_integration.py",
        "test_guard_native_runtime_differential.py",
        "test_guard_native_runtime_mutation_differential.py",
        "bench_guard_native_release_gate.py",
        "test_native_hol_guard_wheel.py",
    )
    missing_commands = [value for value in required_commands if value not in source]
    if missing_commands:
        raise RuntimeError(f"authority workflow integration coverage is incomplete: {missing_commands}")


def _docs_gate() -> None:
    architecture = _read(Path("docs/guard/all-harness-hook-review.md"))
    support = _read(Path("docs/guard/harness-support.md"))
    forbidden = (
        "PreToolUse, UserPromptSubmit, and PermissionRequest events raise",
        "causing the server to fall through to the legacy CLI path",
        "Python remains authoritative",
    )
    for value in forbidden:
        if value in architecture or value in support:
            raise RuntimeError(f"legacy Python authority documentation remains: {value}")
    if "Rust Authority Boundary" not in architecture or "Rust Authority Boundary" not in support:
        raise RuntimeError("Rust authority boundary is not documented on both harness pages")


def _hygiene_gate() -> None:
    residue = [str(path) for path in TEMPORARY_PATHS if path.exists()]
    if residue:
        raise RuntimeError(f"temporary Rust migration delivery residue remains: {residue}")


def run(root: Path) -> dict[str, object]:
    original = Path.cwd()
    try:
        if root != original:
            import os

            os.chdir(root)
        manifest = _manifest()
        _pretool_gate()
        _posttool_gate()
        _mode_gate()
        _policy_and_identity_gate()
        _workflow_gate()
        _docs_gate()
        _hygiene_gate()
        return {
            "schema": SCHEMA,
            "status": "passed",
            "manifest": manifest,
        }
    finally:
        if Path.cwd() != original:
            import os

            os.chdir(original)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--json", type=Path)
    parsed = parser.parse_args()
    payload = run(parsed.root.resolve())
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    print(rendered)
    if parsed.json is not None:
        parsed.json.parent.mkdir(parents=True, exist_ok=True)
        parsed.json.write_text(rendered + "\n", encoding="utf-8")
    raise SystemExit(0)
