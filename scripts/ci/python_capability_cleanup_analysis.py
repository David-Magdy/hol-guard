"""Static Python import analysis used by the capability cleanup gate."""

from __future__ import annotations

import ast
import re
from itertools import product
from pathlib import Path

_MAX_DYNAMIC_IMPORT_DESTINATION = 256
_IMPORT_DESTINATION_RE = re.compile(r"^(?:\.+(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)?|[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)$")


class DynamicImport:
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


def module_name(root: Path, path: Path) -> str:
    relative = path.relative_to(root / "src").with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def resolve_import(module_name_value: str, level: int, imported: str | None) -> str:
    if level == 0:
        return imported or ""
    package = module_name_value.split(".")[:-1]
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
        module: str,
        assignments: dict[str, ast.AST],
        bindings: dict[str, frozenset[str]],
        parameter_bindings: dict[tuple[str, int], frozenset[str]],
        import_aliases: set[str],
        importlib_aliases: set[str],
    ) -> None:
        self._module = module
        self._assignments = assignments
        self._bindings = bindings
        self._parameter_bindings = parameter_bindings
        self._import_aliases = import_aliases
        self._importlib_aliases = importlib_aliases
        self._function_stack: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        self.evidence: list[DynamicImport] = []
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
                self.unbounded.append(f"{self._module}:{node.lineno}")
                count = 0
            else:
                invalid = sorted(value for value in values if not valid_import_destination(value))
                if invalid:
                    kind = "invalid_static"
                    self.unbounded.append(f"{self._module}:{node.lineno}")
                count = len(values)
            self.evidence.append(DynamicImport(self._module, node.lineno, kind, count, None))
        self.generic_visit(node)


def valid_import_destination(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= _MAX_DYNAMIC_IMPORT_DESTINATION
        and "\x00" not in value
        and bool(_IMPORT_DESTINATION_RE.fullmatch(value))
    )


def dynamic_import_destinations(root: Path) -> tuple[list[DynamicImport], list[str]]:
    """Inspect every importlib destination and reject unbounded provenance."""

    evidence: list[DynamicImport] = []
    unbounded: list[str] = []
    for path in (root / "src").rglob("*.py"):
        module = module_name(root, path)
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
            module,
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


def module_imports(root: Path) -> tuple[dict[str, set[str]], list[str]]:
    modules: dict[str, Path] = {}
    for path in (root / "src").rglob("*.py"):
        modules[module_name(root, path)] = path
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
                target = resolve_import(name, node.level, node.module)
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


def reachable(roots: tuple[str, ...], imports: dict[str, set[str]]) -> set[str]:
    pending = [root for root in roots if root in imports]
    reached: set[str] = set()
    while pending:
        module = pending.pop()
        if module in reached:
            continue
        reached.add(module)
        pending.extend(imported for imported in imports.get(module, ()) if imported not in reached)
    return reached


def production_importers(root: Path, candidate_module: str) -> list[str]:
    import_graph, dynamic = module_imports(root)
    importers = sorted(module for module, targets in import_graph.items() if candidate_module in targets)
    importers.extend(item for item in dynamic if candidate_module in item)
    return importers
