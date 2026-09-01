#!/usr/bin/env python3
"""Prove Python hook ownership, oracle reachability, and package cleanup."""

from __future__ import annotations

import argparse
import ast
import json
import os
import subprocess
import sys
import tarfile
from hashlib import sha256
from pathlib import Path
from typing import Final
from zipfile import ZipFile

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

SCHEMA: Final = "hol-guard.python-capability-cleanup.v1"
CONTRACT: Final = "docs/guard/contracts/python-capability-ownership.v1.json"
_ALLOWED_CLASSES: Final = frozenset({"required_control_plane", "named_reference_oracle", "dead_duplicate"})
_IMPORT_ROOTS: Final = (
    "codex_plugin_scanner.cli",
    "codex_plugin_scanner.guard.cli.commands",
    "codex_plugin_scanner.guard.daemon.server",
    "codex_plugin_scanner.guard.daemon.hook_process_entrypoint",
)


def _read_json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def _paths(root: Path, patterns: list[str], excludes: list[str] | None = None) -> set[str]:
    excluded = {path for pattern in excludes or [] for path in root.glob(pattern) if path.is_file()}
    return {
        path.relative_to(root).as_posix()
        for pattern in patterns
        for path in root.glob(pattern)
        if path.is_file() and path not in excluded
    }


def _validate_contract(root: Path) -> tuple[dict[str, object], dict[str, str], set[str]]:
    contract = _read_json(root / CONTRACT)
    if contract.get("schema") != "hol-guard.python-capability-ownership.v1":
        raise RuntimeError("unexpected Python capability ownership schema")
    classes = contract.get("classes")
    if not isinstance(classes, list) or set(classes) != _ALLOWED_CLASSES:
        raise RuntimeError("ownership classes do not match the cleanup gate")
    scope_globs = contract.get("scope_globs")
    capabilities = contract.get("capabilities")
    if not isinstance(scope_globs, list) or not all(isinstance(item, str) for item in scope_globs):
        raise RuntimeError("scope_globs must be a list of strings")
    if not isinstance(capabilities, list) or not capabilities:
        raise RuntimeError("capabilities must be a non-empty list")
    scope = _paths(root, scope_globs)
    owners: dict[str, str] = {}
    for capability in capabilities:
        if not isinstance(capability, dict):
            raise RuntimeError("capability entries must be objects")
        capability_id = capability.get("id")
        capability_class = capability.get("class")
        patterns = capability.get("patterns")
        if not isinstance(capability_id, str) or not capability_id:
            raise RuntimeError("capability id is required")
        if capability_class not in _ALLOWED_CLASSES:
            raise RuntimeError(f"invalid class for {capability_id}: {capability_class}")
        if not isinstance(patterns, list) or not all(isinstance(item, str) for item in patterns):
            raise RuntimeError(f"patterns missing for {capability_id}")
        files = _paths(root, patterns, capability.get("exclude_patterns"))
        if not files:
            raise RuntimeError(f"capability has no files: {capability_id}")
        for path in files:
            previous = owners.get(path)
            if previous is not None:
                raise RuntimeError(f"capability overlap for {path}: {previous}, {capability_id}")
            owners[path] = capability_id
    missing = sorted(scope - set(owners))
    extra = sorted(set(owners) - scope)
    if missing or extra:
        raise RuntimeError(f"ownership coverage mismatch: missing={missing}, extra={extra}")
    return contract, owners, scope


def _module_name(root: Path, path: Path) -> str:
    relative = path.relative_to(root / "src").with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _resolve_import(module_name: str, level: int, imported: str | None) -> str:
    if level == 0:
        return imported or ""
    package = module_name.split(".")[:-1]
    base = package[: len(package) - level + 1]
    if imported:
        base.append(imported)
    return ".".join(base)


def _module_imports(root: Path) -> tuple[dict[str, set[str]], list[str]]:
    modules: dict[str, Path] = {}
    for path in (root / "src").rglob("*.py"):
        modules[_module_name(root, path)] = path
    imports: dict[str, set[str]] = {}
    dynamic: list[str] = []
    for name, path in modules.items():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        targets: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in modules:
                        targets.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                target = _resolve_import(name, node.level, node.module)
                if target in modules:
                    targets.add(target)
                for alias in node.names:
                    candidate = f"{target}.{alias.name}" if target else alias.name
                    if candidate in modules:
                        targets.add(candidate)
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "importlib"
                and node.func.attr == "import_module"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            ):
                dynamic.append(f"{name}:{node.lineno}:{node.args[0].value}")
        imports[name] = targets
    return imports, dynamic


def _reachable(roots: tuple[str, ...], imports: dict[str, set[str]]) -> set[str]:
    pending = [root for root in roots if root in imports]
    reached: set[str] = set()
    while pending:
        module = pending.pop()
        if module in reached:
            continue
        reached.add(module)
        pending.extend(imported for imported in imports.get(module, ()) if imported not in reached)
    return reached


def _production_importers(root: Path, candidate_module: str) -> list[str]:
    import_graph, dynamic = _module_imports(root)
    importers = sorted(module for module, targets in import_graph.items() if candidate_module in targets)
    importers.extend(item for item in dynamic if candidate_module in item)
    return importers


def _pyproject_excludes(root: Path) -> list[str]:
    with (root / "pyproject.toml").open("rb") as stream:
        document = tomllib.load(stream)
    value = document.get("tool", {}).get("hatch", {}).get("build", {}).get("exclude", [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise RuntimeError("tool.hatch.build.exclude must be a list of strings")
    return value


def _artifact_contains(artifact: Path, package_name: str) -> bool:
    if artifact.name.endswith(".whl"):
        with ZipFile(artifact) as archive:
            return package_name in archive.namelist()
    if artifact.name.endswith(".tar.gz"):
        with tarfile.open(artifact, "r:gz") as archive:
            return any(name.endswith(f"/{package_name}") or name == package_name for name in archive.getnames())
    raise RuntimeError(f"unsupported package artifact: {artifact}")


def _validate_fixture(root: Path, relative: str) -> dict[str, object]:
    fixture = _read_json(root / relative)
    if fixture.get("schema") != "hol-guard.native-hook-parity.v1" or fixture.get("version") != 1:
        raise RuntimeError("invalid native hook parity fixture header")
    cases = fixture.get("cases")
    if not isinstance(cases, list) or not cases:
        raise RuntimeError("parity fixture must contain cases")
    ids: set[str] = set()
    allowed_actions = {"allow", "review", "block", "require-reapproval", "sandbox-required"}
    for case in cases:
        if not isinstance(case, dict):
            raise RuntimeError("parity fixture cases must be objects")
        required = {"id", "event", "input_class", "expected_action"}
        if set(case) != required:
            raise RuntimeError(f"parity case fields must be language-neutral: {case}")
        case_id = case["id"]
        if not isinstance(case_id, str) or not case_id or case_id in ids:
            raise RuntimeError("parity case ids must be unique non-empty strings")
        if case["event"] not in {"PreToolUse", "PostToolUse", "Unknown"}:
            raise RuntimeError(f"unsupported parity event: {case['event']}")
        if case["expected_action"] not in allowed_actions:
            raise RuntimeError(f"unsupported parity action: {case['expected_action']}")
        ids.add(case_id)
    return {"case_count": len(cases), "sha256": sha256((root / relative).read_bytes()).hexdigest()}


def _verify_import_surface(root: Path, oracle_modules: list[str], candidate_module: str) -> None:
    source = root / "src"
    clean_env = os.environ.copy()
    for key in (
        "HOL_GUARD_NATIVE",
        "HOL_GUARD_NATIVE_DIAGNOSTIC",
        "HOL_GUARD_PYTHON_ORACLE",
        "HOL_GUARD_TEST_MODE",
        "PYTEST_CURRENT_TEST",
    ):
        clean_env.pop(key, None)
    code = (
        "import sys; "
        "import codex_plugin_scanner.guard.cli.commands_support; "
        "loaded = set(sys.modules); "
        f"forbidden = {oracle_modules!r} + [{candidate_module!r}]; "
        "assert not (loaded & set(forbidden)), sorted(loaded & set(forbidden))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=root,
        env={**clean_env, "PYTHONPATH": str(source)},
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"production import surface reached retired Python hook code: {detail}")


def _candidate_evidence(
    root: Path,
    candidate: str,
    owners: dict[str, str],
    exclusions: list[str],
) -> tuple[str, dict[str, object]]:
    path = root / candidate
    if not path.is_file():
        raise RuntimeError(f"retained deletion candidate is missing: {candidate}")
    if owners.get(candidate) is None or owners[candidate] == "python_reference_oracle":
        raise RuntimeError(f"candidate is not classified as dead_duplicate: {candidate}")
    if candidate not in exclusions:
        raise RuntimeError(f"dead candidate is not excluded from Hatch builds: {candidate}")
    module = _module_name(root, path)
    importers = _production_importers(root, module)
    if importers:
        raise RuntimeError(f"dead candidate still has source import reachability: {candidate}: {importers}")
    return module, {
        "path": candidate,
        "module": module,
        "loc": len(path.read_text(encoding="utf-8").splitlines()),
        "source_importers": [],
        "package_excluded": True,
    }


def run(root: Path, wheel: Path | None = None) -> dict[str, object]:
    root = root.resolve()
    contract, owners, scope = _validate_contract(root)
    excluded_candidates = contract.get("package_excluded_candidates")
    deletion_candidates = contract.get("deletion_candidates")
    oracle_tests = contract.get("oracle_tests")
    if not isinstance(excluded_candidates, list) or not all(isinstance(item, str) for item in excluded_candidates):
        raise RuntimeError("package_excluded_candidates must be a list")
    if not isinstance(deletion_candidates, list) or not deletion_candidates:
        raise RuntimeError("deletion candidates must be recorded")
    if not isinstance(oracle_tests, list) or not all(isinstance(item, str) for item in oracle_tests):
        raise RuntimeError("oracle_tests must be a list")
    missing_tests = [path for path in oracle_tests if not (root / path).is_file()]
    if missing_tests:
        raise RuntimeError(f"named oracle tests are missing: {missing_tests}")
    fixture_relative = contract.get("parity_fixture")
    if not isinstance(fixture_relative, str):
        raise RuntimeError("parity_fixture is required")
    fixture = _validate_fixture(root, fixture_relative)
    exclusions = _pyproject_excludes(root)
    candidate_modules: list[str] = []
    candidate_evidence: list[dict[str, object]] = []
    for candidate in excluded_candidates:
        module, evidence = _candidate_evidence(root, candidate, owners, exclusions)
        candidate_modules.append(module)
        candidate_evidence.append(evidence)
    oracle_modules = contract.get("lazy_oracle_modules", [])
    if not isinstance(oracle_modules, list) or not all(isinstance(item, str) for item in oracle_modules):
        raise RuntimeError("lazy_oracle_modules must be a list")
    _verify_import_surface(root, oracle_modules, candidate_modules[0])
    if wheel is not None:
        for candidate in excluded_candidates:
            package_name = candidate.removeprefix("src/")
            if _artifact_contains(wheel, package_name):
                raise RuntimeError(f"package artifact contains excluded dead module: {package_name}")
    source_loc: dict[str, int] = {}
    for path, capability_id in owners.items():
        source_loc[capability_id] = source_loc.get(capability_id, 0) + len(
            (root / path).read_text(encoding="utf-8").splitlines()
        )
    import_graph, dynamic_imports = _module_imports(root)
    reached = _reachable(_IMPORT_ROOTS, import_graph)
    return {
        "schema": SCHEMA,
        "status": "passed",
        "slice": contract.get("slice"),
        "scope_files": len(scope),
        "capabilities": {
            capability: sum(1 for owner in owners.values() if owner == capability)
            for capability in set(owners.values())
        },
        "source_loc_by_capability": source_loc,
        "production_import_roots": list(_IMPORT_ROOTS),
        "production_reachable_modules": len(reached),
        "lazy_oracle_modules": oracle_modules,
        "fixture": fixture,
        "candidate_evidence": candidate_evidence,
        "package_exclusions": [candidate for candidate in excluded_candidates if candidate in exclusions],
        "dependency_delta": contract.get("dependency_delta"),
        "dynamic_import_count": len(dynamic_imports),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--wheel", "--artifact", dest="artifact", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    try:
        payload = run(args.root, args.artifact)
    except (OSError, RuntimeError, tomllib.TOMLDecodeError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(rendered + "\n", encoding="utf-8")
