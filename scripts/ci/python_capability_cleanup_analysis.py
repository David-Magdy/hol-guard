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


def _assigned_names(target: ast.AST) -> tuple[str, ...]:
    if isinstance(target, ast.Name):
        return (target.id,)
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for child in target.elts:
            names.extend(_assigned_names(child))
        return tuple(names)
    return ()


class _StaticScope:
    __slots__ = (
        "assignments",
        "bindings",
        "loop_nodes",
        "merged_assignments",
        "merged_bindings",
        "node",
        "parameters",
        "parent",
    )

    def __init__(self, node: ast.AST | None, parent: _StaticScope | None) -> None:
        self.node = node
        self.parent = parent
        self.assignments: dict[str, ast.AST] = {}
        self.bindings: dict[str, frozenset[str]] = {}
        self.loop_nodes: list[ast.For | ast.AsyncFor] = []
        self.merged_assignments: dict[str, ast.AST] = {}
        self.merged_bindings: dict[str, frozenset[str]] = {}
        self.parameters: frozenset[str] = frozenset()


def _function_parameters(node: ast.AST | None) -> frozenset[str]:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return frozenset()
    arguments = node.args
    parameters = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    if arguments.vararg is not None:
        parameters.append(arguments.vararg)
    if arguments.kwarg is not None:
        parameters.append(arguments.kwarg)
    return frozenset(argument.arg for argument in parameters)


class _StaticScopeAnalysis:
    """Collect static bindings without allowing sibling lexical scopes to leak."""

    def __init__(self, tree: ast.Module) -> None:
        self.tree = tree
        self.root = _StaticScope(None, None)
        self.scopes: list[_StaticScope] = [self.root]
        self._node_scopes: dict[int, _StaticScope] = {}
        self._walk(tree, self.root)
        for scope in self.scopes:
            self._finalize(scope)

    def scope_for(self, node: ast.AST) -> _StaticScope:
        return self._node_scopes.get(id(node), self.root)

    def _walk(self, node: ast.AST, scope: _StaticScope) -> None:
        self._node_scopes[id(node)] = scope
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for decorator in node.decorator_list:
                self._walk(decorator, scope)
            for default in [*node.args.defaults, *node.args.kw_defaults]:
                if default is not None:
                    self._walk(default, scope)
            if node.returns is not None:
                self._walk(node.returns, scope)
            lexical_parent = scope.parent if isinstance(scope.node, ast.ClassDef) else scope
            child = _StaticScope(node, lexical_parent)
            self.scopes.append(child)
            self._node_scopes[id(node)] = child
            for statement in node.body:
                self._walk(statement, child)
            return
        if isinstance(node, ast.ClassDef):
            for decorator in node.decorator_list:
                self._walk(decorator, scope)
            for base in node.bases:
                self._walk(base, scope)
            for keyword in node.keywords:
                self._walk(keyword, scope)
            child = _StaticScope(node, scope)
            self.scopes.append(child)
            self._node_scopes[id(node)] = child
            for statement in node.body:
                self._walk(statement, child)
            return
        if isinstance(node, ast.Assign):
            for target in node.targets:
                for name in _assigned_names(target):
                    scope.assignments[name] = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            for name in _assigned_names(node.target):
                scope.assignments[name] = node.value
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            scope.loop_nodes.append(node)
        for child in ast.iter_child_nodes(node):
            self._walk(child, scope)

    def _finalize(self, scope: _StaticScope) -> None:
        parent = scope.parent
        merged_assignments = dict(parent.merged_assignments) if parent is not None else {}
        merged_assignments.update(scope.assignments)
        scope.parameters = _function_parameters(scope.node)
        for parameter in scope.parameters:
            merged_assignments.pop(parameter, None)
        merged_bindings = dict(parent.merged_bindings) if parent is not None else {}
        for name in scope.assignments:
            merged_bindings.pop(name, None)
        for parameter in scope.parameters:
            merged_bindings.pop(parameter, None)
        local_bindings: dict[str, frozenset[str]] = {}
        for name, value in scope.assignments.items():
            if name in scope.parameters:
                continue
            resolved = _static_strings(value, merged_assignments, merged_bindings)
            if resolved is not None:
                local_bindings[name] = resolved
                merged_bindings[name] = resolved
        for node in scope.loop_nodes:
            sequence = _static_sequence(node.iter, merged_assignments, set())
            if sequence is None:
                continue
            target_values: dict[str, set[str]] = {}
            for item in sequence:
                for name, target_value in _assignment_targets(node.target, item).items():
                    if name not in scope.parameters and isinstance(target_value, str):
                        target_values.setdefault(name, set()).add(target_value)
            for name, values in target_values.items():
                if values:
                    resolved = frozenset(values)
                    local_bindings[name] = resolved
                    merged_bindings[name] = resolved
        scope.bindings = local_bindings
        scope.merged_assignments = merged_assignments
        scope.merged_bindings = merged_bindings


def _static_assignments(tree: ast.Module) -> tuple[dict[str, ast.AST], dict[str, frozenset[str]]]:
    analysis = _StaticScopeAnalysis(tree)
    return analysis.root.assignments, analysis.root.bindings


def _function_parameter_bindings(analysis: _StaticScopeAnalysis) -> dict[tuple[int, int], frozenset[str]]:
    """Prove direct helper parameters from all same-module callsites."""

    functions = [
        scope.node for scope in analysis.scopes if isinstance(scope.node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    names = {function.name for function in functions}
    calls: dict[str, list[ast.Call]] = {name: [] for name in names}
    for node in ast.walk(analysis.tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in calls:
            calls[node.func.id].append(node)
    result: dict[tuple[int, int], frozenset[str]] = {}
    for function in functions:
        function_calls = calls[function.name]
        if not function_calls:
            continue
        positional = [*function.args.posonlyargs, *function.args.args]
        for index, _parameter in enumerate(positional):
            values: set[str] = set()
            proven = True
            for call in function_calls:
                if index >= len(call.args):
                    proven = False
                    break
                caller_scope = analysis.scope_for(call)
                resolved = _static_strings(
                    call.args[index], caller_scope.merged_assignments, caller_scope.merged_bindings
                )
                if resolved is None:
                    proven = False
                    break
                values.update(resolved)
            if proven and values:
                result[(id(function), index)] = frozenset(values)
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
        analysis: _StaticScopeAnalysis,
        parameter_bindings: dict[tuple[int, int], frozenset[str]],
        import_aliases: set[str],
        importlib_aliases: set[str],
    ) -> None:
        self._module = module
        self._analysis = analysis
        self._parameter_bindings = parameter_bindings
        self._import_aliases = import_aliases
        self._importlib_aliases = importlib_aliases
        self._scope_stack: list[_StaticScope] = [analysis.root]
        self.evidence: list[DynamicImport] = []
        self.unbounded: list[str] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scope_stack.append(self._analysis.scope_for(node))
        self.generic_visit(node)
        self._scope_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._scope_stack.append(self._analysis.scope_for(node))
        self.generic_visit(node)
        self._scope_stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope_stack.append(self._analysis.scope_for(node))
        self.generic_visit(node)
        self._scope_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        if _import_module_call(node, self._import_aliases, self._importlib_aliases) and node.args:
            destination = node.args[0]
            scope = self._scope_stack[-1]
            values = _static_strings(destination, scope.merged_assignments, scope.merged_bindings)
            kind = "literal_or_static"
            if (
                values is None
                and isinstance(destination, ast.Name)
                and isinstance(scope.node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ):
                function = scope.node
                positional = list(function.args.posonlyargs) + list(function.args.args)
                try:
                    index = next(index for index, parameter in enumerate(positional) if parameter.arg == destination.id)
                except StopIteration:
                    index = -1
                if index >= 0:
                    values = self._parameter_bindings.get((id(function), index))
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
            self.evidence.append(
                DynamicImport(
                    self._module,
                    node.lineno,
                    kind,
                    count,
                    tuple(sorted(values)) if values is not None else None,
                )
            )
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
        analysis = _StaticScopeAnalysis(tree)
        parameter_bindings = _function_parameter_bindings(analysis)
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
            analysis,
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
        imports[name] = targets
    dynamic_evidence, _unbounded = dynamic_import_destinations(root)
    accepted_kinds = {"literal_or_static", "bounded_callsite"}
    for item in dynamic_evidence:
        if item.destination_kind not in accepted_kinds or item.destination_values is None:
            continue
        for destination in item.destination_values:
            if destination in modules:
                imports[item.module].add(destination)
                dynamic.append(f"{item.module}:{item.line}:{destination}")
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
