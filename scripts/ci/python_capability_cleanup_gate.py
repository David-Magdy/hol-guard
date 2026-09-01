#!/usr/bin/env python3
"""Prove Python hook ownership, oracle reachability, and package cleanup."""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
import tarfile
from hashlib import sha256
from itertools import product
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
_MAX_DYNAMIC_IMPORT_DESTINATION: Final = 256
_IMPORT_DESTINATION_RE: Final = re.compile(
    r"^(?:\.+(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)?|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)$"
)


class _DynamicImport:
    __slots__ = ("destination_count", "destination_kind", "destination_values", "line", "module")

    def __init__(
        self,
        module: str,
        line: int,
        destination_kind: str,
        destination_count: int,
        destination_values: tuple[str, ...] | None,
    ) -> None:
        self.module = module
        self.line = line
        self.destination_kind = destination_kind
        self.destination_count = destination_count
        self.destination_values = destination_values


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
    dynamic_import_policy = contract.get("dynamic_import_policy")
    if not isinstance(dynamic_import_policy, dict):
        raise RuntimeError("dynamic_import_policy must be an object")
    if dynamic_import_policy.get("mode") != "literal_or_bounded":
        raise RuntimeError("unsupported dynamic import policy")
    max_destination_length = dynamic_import_policy.get("max_destination_length")
    if max_destination_length != _MAX_DYNAMIC_IMPORT_DESTINATION:
        raise RuntimeError("dynamic import destination bound is out of sync")
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


def _assignment_name(target: ast.AST) -> str | None:
    return target.id if isinstance(target, ast.Name) else None


def _assignment_targets(target: ast.AST, value: object) -> dict[str, object]:
    """Bind names in a static tuple assignment without evaluating code."""

    if isinstance(target, ast.Name):
        return {target.id: value}
    if not isinstance(target, (ast.Tuple, ast.List)) or not isinstance(value, tuple):
        return {}
    bindings: dict[str, object] = {}
    if len(target.elts) != len(value):
        return bindings
    for child, child_value in zip(target.elts, value, strict=True):
        bindings.update(_assignment_targets(child, child_value))
    return bindings


def _static_sequence(node: ast.AST, assignments: dict[str, ast.AST], seen: set[str]) -> tuple[object, ...] | None:
    if isinstance(node, ast.Name):
        if node.id in seen or node.id not in assignments:
            return None
        return _static_sequence(assignments[node.id], assignments, {*seen, node.id})
    if not isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return None
    values: list[object] = []
    for element in node.elts:
        if isinstance(element, ast.Constant) and isinstance(element.value, str):
            values.append(element.value)
            continue
        nested = _static_sequence(element, assignments, seen)
        if nested is None:
            return None
        values.append(nested)
    return tuple(values)


def _static_strings(
    node: ast.AST,
    assignments: dict[str, ast.AST],
    bindings: dict[str, frozenset[str]],
    seen: set[str] | None = None,
) -> frozenset[str] | None:
    """Resolve a bounded string expression, without importing or executing it."""

    seen = seen or set()
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return frozenset({node.value})
    if isinstance(node, ast.Name):
        if node.id in bindings:
            return bindings[node.id]
        assignment = assignments.get(node.id)
        if assignment is None or node.id in seen:
            return None
        return _static_strings(assignment, assignments, bindings, {*seen, node.id})
    if isinstance(node, ast.IfExp):
        left = _static_strings(node.body, assignments, bindings, seen)
        right = _static_strings(node.orelse, assignments, bindings, seen)
        if left is None or right is None:
            return None
        return left | right
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_strings(node.left, assignments, bindings, seen)
        right = _static_strings(node.right, assignments, bindings, seen)
        if left is None or right is None or len(left) * len(right) > 32:
            return None
        return frozenset("".join(parts) for parts in product(left, right))
    return None


def _static_assignments(tree: ast.Module) -> tuple[dict[str, ast.AST], dict[str, frozenset[str]]]:
    assignments: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        value: ast.AST | None = None
        targets: list[ast.AST] = []
        if isinstance(node, ast.Assign):
            value = node.value
            targets = node.targets
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            value = node.value
            targets = [node.target]
        if value is not None:
            for target in targets:
                name = _assignment_name(target)
                if name is not None:
                    assignments[name] = value
    bindings: dict[str, frozenset[str]] = {}
    for name, value in assignments.items():
        resolved = _static_strings(value, assignments, bindings)
        if resolved is not None:
            bindings[name] = resolved
    for node in ast.walk(tree):
        if not isinstance(node, (ast.For, ast.AsyncFor)):
            continue
        sequence = _static_sequence(node.iter, assignments, set())
        if sequence is None:
            continue
        # A loop target is bounded when every value it can receive is a static
        # string or a tuple/list of static strings.
        target_values: dict[str, set[str]] = {}
        for item in sequence:
            for name, target_value in _assignment_targets(node.target, item).items():
                if isinstance(target_value, str):
                    target_values.setdefault(name, set()).add(target_value)
        for name, values in target_values.items():
            if values:
                bindings[name] = frozenset(values)
    return assignments, bindings


def _function_parameter_bindings(
    tree: ast.Module,
    assignments: dict[str, ast.AST],
    bindings: dict[str, frozenset[str]],
) -> dict[tuple[str, int], frozenset[str]]:
    """Prove direct helper parameters from all same-module callsites."""

    functions = {
        node.name: node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    calls: dict[str, list[ast.Call]] = {name: [] for name in functions}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in calls:
            calls[node.func.id].append(node)
    result: dict[tuple[str, int], frozenset[str]] = {}
    for name, function in functions.items():
        function_calls = calls[name]
        if not function_calls:
            continue
        positional = list(function.args.posonlyargs) + list(function.args.args)
        for index, _parameter in enumerate(positional):
            values: set[str] = set()
            proven = True
            for call in function_calls:
                if index >= len(call.args):
                    proven = False
                    break
                resolved = _static_strings(call.args[index], assignments, bindings)
                if resolved is None:
                    proven = False
                    break
                values.update(resolved)
            if proven and values:
                result[(name, index)] = frozenset(values)
    return result


def _import_module_call(node: ast.Call, import_aliases: set[str], importlib_aliases: set[str]) -> bool:
    if isinstance(node.func, ast.Name):
        return node.func.id in import_aliases
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "import_module"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in importlib_aliases
    )


class _DynamicImportVisitor(ast.NodeVisitor):
    def __init__(
        self,
        module_name: str,
        assignments: dict[str, ast.AST],
        bindings: dict[str, frozenset[str]],
        parameter_bindings: dict[tuple[str, int], frozenset[str]],
        import_aliases: set[str],
        importlib_aliases: set[str],
    ) -> None:
        self._module_name = module_name
        self._assignments = assignments
        self._bindings = bindings
        self._parameter_bindings = parameter_bindings
        self._import_aliases = import_aliases
        self._importlib_aliases = importlib_aliases
        self._function_stack: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        self.evidence: list[_DynamicImport] = []
        self.unbounded: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        if _import_module_call(node, self._import_aliases, self._importlib_aliases) and node.args:
            destination = node.args[0]
            values = _static_strings(destination, self._assignments, self._bindings)
            kind = "literal_or_static"
            if values is None and isinstance(destination, ast.Name) and self._function_stack:
                function = self._function_stack[-1]
                positional = list(function.args.posonlyargs) + list(function.args.args)
                try:
                    index = next(index for index, parameter in enumerate(positional) if parameter.arg == destination.id)
                except StopIteration:
                    index = -1
                if index >= 0:
                    values = self._parameter_bindings.get((function.name, index))
                    kind = "bounded_callsite" if values is not None else "unbounded"
            if values is None:
                kind = "unbounded"
                self.unbounded.append(f"{self._module_name}:{node.lineno}")
                count = 0
            else:
                invalid = sorted(value for value in values if not _valid_import_destination(value))
                if invalid:
                    kind = "invalid_static"
                    self.unbounded.append(f"{self._module_name}:{node.lineno}")
                count = len(values)
            self.evidence.append(_DynamicImport(self._module_name, node.lineno, kind, count, None))
        self.generic_visit(node)


def _valid_import_destination(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= _MAX_DYNAMIC_IMPORT_DESTINATION
        and "\x00" not in value
        and bool(_IMPORT_DESTINATION_RE.fullmatch(value))
    )


def _dynamic_import_destinations(root: Path) -> tuple[list[_DynamicImport], list[str]]:
    """Inspect every importlib destination and reject unbounded provenance."""

    evidence: list[_DynamicImport] = []
    unbounded: list[str] = []
    for path in (root / "src").rglob("*.py"):
        module_name = _module_name(root, path)
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        assignments, bindings = _static_assignments(tree)
        parameter_bindings = _function_parameter_bindings(tree, assignments, bindings)
        importlib_aliases = {"importlib"}
        import_aliases: set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "importlib":
                        importlib_aliases.add(alias.asname or "importlib")
            elif isinstance(node, ast.ImportFrom) and node.module == "importlib":
                for alias in node.names:
                    if alias.name == "import_module":
                        import_aliases.add(alias.asname or alias.name)
        visitor = _DynamicImportVisitor(
            module_name,
            assignments,
            bindings,
            parameter_bindings,
            import_aliases,
            importlib_aliases,
        )
        visitor.visit(tree)
        evidence.extend(visitor.evidence)
        unbounded.extend(visitor.unbounded)
    return evidence, unbounded


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
    import_graph, _ = _module_imports(root)
    dynamic_imports, dynamic_unbounded = _dynamic_import_destinations(root)
    if dynamic_unbounded:
        raise RuntimeError(
            "dynamic import destination is not literal or statically bounded: " + ", ".join(sorted(dynamic_unbounded))
        )
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
        "dynamic_import_destinations_checked": True,
        "dynamic_import_unbounded": dynamic_unbounded,
        "dynamic_import_evidence": [
            {
                "module": item.module,
                "line": item.line,
                "destination_kind": item.destination_kind,
                "destination_count": item.destination_count,
            }
            for item in dynamic_imports
        ],
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
