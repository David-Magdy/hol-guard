"""Static Python import analysis used by the capability cleanup gate."""

from __future__ import annotations

import ast
import re
from collections.abc import Mapping, Sequence
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
    bindings: Mapping[str, _StaticValue],
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
        "call_aliases",
        "call_bindings",
        "entry_bindings",
        "entry_function_bindings",
        "entry_import_aliases",
        "entry_importlib_aliases",
        "entry_module_bindings",
        "entry_recorded",
        "entry_sequences",
        "function_bindings",
        "loop_nodes",
        "merged_assignments",
        "merged_bindings",
        "merged_function_bindings",
        "merged_import_aliases",
        "merged_importlib_aliases",
        "merged_module_bindings",
        "merged_sequences",
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
        self.merged_bindings: dict[str, _StaticValue] = {}
        self.merged_function_bindings: dict[str, tuple[str, int] | None] = {}
        self.merged_import_aliases: frozenset[str] = frozenset()
        self.merged_importlib_aliases: frozenset[str] = frozenset()
        self.merged_module_bindings: dict[str, str | None] = {}
        self.merged_sequences: dict[str, tuple[object, ...] | None] = {}
        self.parameters: frozenset[str] = frozenset()
        self.function_bindings: dict[str, tuple[str, int] | None] = {}
        self.call_aliases: dict[int, tuple[frozenset[str], frozenset[str]]] = {}
        self.call_bindings: dict[int, dict[str, frozenset[str] | None]] = {}
        self.entry_bindings: dict[str, _StaticValue] = {}
        self.entry_sequences: dict[str, tuple[object, ...] | None] = {}
        self.entry_import_aliases: frozenset[str] = frozenset()
        self.entry_importlib_aliases: frozenset[str] = frozenset()
        self.entry_function_bindings: dict[str, tuple[str, int] | None] = {}
        self.entry_module_bindings: dict[str, str | None] = {}
        self.entry_recorded = False


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


_StaticValue = frozenset[str] | None
_FunctionIdentity = tuple[str, int]
_SequenceValue = tuple[object, ...] | None


def _merge_sequence_values(left: _SequenceValue, right: _SequenceValue) -> _SequenceValue:
    """Retain a sequence only when both control-flow paths agree exactly."""

    return left if left == right else None


def _merge_static_values(left: _StaticValue, right: _StaticValue) -> _StaticValue:
    if left is None or right is None:
        return None
    merged = left | right
    return merged if len(merged) <= 32 else None


def _merge_static_bindings(
    left: Mapping[str, _StaticValue],
    right: Mapping[str, _StaticValue],
) -> dict[str, _StaticValue]:
    return {name: _merge_static_values(left.get(name), right.get(name)) for name in left.keys() | right.keys()}


def _resolve_static_strings(
    node: ast.AST,
    bindings: Mapping[str, _StaticValue],
    seen: set[str] | None = None,
) -> frozenset[str] | None:
    """Resolve a string expression against values proven before one callsite."""

    seen = seen or set()
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return frozenset({node.value})
    if isinstance(node, ast.Name):
        if node.id in seen:
            return None
        value = bindings.get(node.id)
        return value if value is not None else None
    if isinstance(node, ast.IfExp):
        left = _resolve_static_strings(node.body, bindings, seen)
        right = _resolve_static_strings(node.orelse, bindings, seen)
        if left is None or right is None:
            return None
        return _merge_static_values(left, right)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve_static_strings(node.left, bindings, seen)
        right = _resolve_static_strings(node.right, bindings, seen)
        if left is None or right is None or len(left) * len(right) > 32:
            return None
        return frozenset("".join(parts) for parts in product(left, right))
    return None


def _resolve_static_sequence(
    node: ast.AST,
    bindings: Mapping[str, _SequenceValue],
    seen: set[str] | None = None,
) -> tuple[object, ...] | None:
    if isinstance(node, ast.Name):
        if node.id in (seen or set()):
            return None
        return bindings.get(node.id)
    if not isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return None
    values: list[object] = []
    for element in node.elts:
        if isinstance(element, ast.Constant) and isinstance(element.value, str):
            values.append(element.value)
            continue
        nested = _resolve_static_sequence(element, bindings, seen)
        if nested is None:
            return None
        values.append(nested)
    return tuple(values)


class _ScopeBindingFlow(ast.NodeVisitor):
    """Record lexical values and aliases at each callsite in one scope."""

    def __init__(
        self,
        analysis: _StaticScopeAnalysis,
        scope: _StaticScope,
        bindings: Mapping[str, _StaticValue],
        sequences: Mapping[str, _SequenceValue],
        import_aliases: set[str],
        importlib_aliases: set[str],
        function_bindings: Mapping[str, _FunctionIdentity | None],
        module_bindings: Mapping[str, str | None],
    ) -> None:
        self._analysis = analysis
        self._scope = scope
        self.bindings: dict[str, _StaticValue] = dict(bindings)
        self.sequences: dict[str, _SequenceValue] = dict(sequences)
        self.import_aliases = set(import_aliases)
        self.importlib_aliases = set(importlib_aliases)
        self.function_bindings: dict[str, _FunctionIdentity | None] = dict(function_bindings)
        self.module_bindings: dict[str, str | None] = dict(module_bindings)

    def _snapshot_call(self, node: ast.Call) -> None:
        self._analysis.call_bindings[id(node)] = dict(self.bindings)
        self._analysis.call_aliases[id(node)] = (
            frozenset(self.import_aliases),
            frozenset(self.importlib_aliases),
        )
        target = None
        if isinstance(node.func, ast.Name):
            target = self.function_bindings.get(node.func.id)
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            module = self.module_bindings.get(node.func.value.id)
            if module is not None:
                target = self._analysis.function_exports.get(module, {}).get(node.func.attr)
        self._analysis.call_targets[id(node)] = target

    def _forget_names(self, names: tuple[str, ...]) -> None:
        for name in names:
            self.bindings[name] = None
            self.sequences[name] = None
            self.import_aliases.discard(name)
            self.importlib_aliases.discard(name)
            self.function_bindings[name] = None
            self.module_bindings[name] = None

    def _state(
        self,
    ) -> tuple[
        dict[str, _StaticValue],
        dict[str, _SequenceValue],
        set[str],
        set[str],
        dict[str, _FunctionIdentity | None],
        dict[str, str | None],
    ]:
        return (
            dict(self.bindings),
            dict(self.sequences),
            set(self.import_aliases),
            set(self.importlib_aliases),
            dict(self.function_bindings),
            dict(self.module_bindings),
        )

    def _branch(
        self,
        statements: Sequence[ast.AST],
        base: tuple[
            dict[str, _StaticValue],
            dict[str, _SequenceValue],
            set[str],
            set[str],
            dict[str, _FunctionIdentity | None],
            dict[str, str | None],
        ],
    ) -> tuple[
        dict[str, _StaticValue],
        dict[str, _SequenceValue],
        set[str],
        set[str],
        dict[str, _FunctionIdentity | None],
        dict[str, str | None],
    ]:
        bindings, sequences, import_aliases, importlib_aliases, function_bindings, module_bindings = base
        self.bindings = dict(bindings)
        self.sequences = dict(sequences)
        self.import_aliases = set(import_aliases)
        self.importlib_aliases = set(importlib_aliases)
        self.function_bindings = dict(function_bindings)
        self.module_bindings = dict(module_bindings)
        for statement in statements:
            self.visit(statement)
        return self._state()

    @staticmethod
    def _merge_aliases(
        left: set[str],
        right: set[str],
    ) -> set[str]:
        return left & right

    def _merge_states(
        self,
        left: tuple[
            dict[str, _StaticValue],
            dict[str, _SequenceValue],
            set[str],
            set[str],
            dict[str, _FunctionIdentity | None],
            dict[str, str | None],
        ],
        right: tuple[
            dict[str, _StaticValue],
            dict[str, _SequenceValue],
            set[str],
            set[str],
            dict[str, _FunctionIdentity | None],
            dict[str, str | None],
        ],
    ) -> None:
        self.bindings = _merge_static_bindings(left[0], right[0])
        self.sequences = {
            name: _merge_sequence_values(left[1].get(name), right[1].get(name))
            for name in left[1].keys() | right[1].keys()
        }
        self.import_aliases = self._merge_aliases(left[2], right[2])
        self.importlib_aliases = self._merge_aliases(left[3], right[3])
        self.function_bindings = {
            name: left[4].get(name) if left[4].get(name) == right[4].get(name) else None
            for name in left[4].keys() | right[4].keys()
        }
        self.module_bindings = {
            name: left[5].get(name) if left[5].get(name) == right[5].get(name) else None
            for name in left[5].keys() | right[5].keys()
        }

    def visit_Call(self, node: ast.Call) -> None:
        self._snapshot_call(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        value = _resolve_static_strings(node.value, self.bindings)
        sequence = _resolve_static_sequence(node.value, self.sequences)
        function = self._resolve_function_value(node.value)
        names: list[str] = []
        for target in node.targets:
            names.extend(_assigned_names(target))
        self._forget_names(tuple(names))
        for name in names:
            self.bindings[name] = value
            self.sequences[name] = sequence
            self.function_bindings[name] = function

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            value = _resolve_static_strings(node.value, self.bindings)
            sequence = _resolve_static_sequence(node.value, self.sequences)
            function = self._resolve_function_value(node.value)
        else:
            value = None
            sequence = None
            function = None
        names = _assigned_names(node.target)
        self._forget_names(names)
        for name in names:
            self.bindings[name] = value
            self.sequences[name] = sequence
            self.function_bindings[name] = function

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        self._forget_names(_assigned_names(node.target))

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        value = _resolve_static_strings(node.value, self.bindings)
        sequence = _resolve_static_sequence(node.value, self.sequences)
        function = self._resolve_function_value(node.value)
        names = _assigned_names(node.target)
        self._forget_names(names)
        for name in names:
            self.bindings[name] = value
            self.sequences[name] = sequence
            self.function_bindings[name] = function

    def visit_Delete(self, node: ast.Delete) -> None:
        self.generic_visit(node)
        self._forget_names(tuple(name for target in node.targets for name in _assigned_names(target)))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            bound = alias.asname or alias.name.split(".", 1)[0]
            self._forget_names((bound,))
            if alias.name == "importlib":
                self.importlib_aliases.add(bound)
            else:
                self.module_bindings[bound] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        target_module = resolve_import(self._analysis.module, node.level, node.module)
        for alias in node.names:
            bound = alias.asname or alias.name
            self._forget_names((bound,))
            if node.module == "importlib":
                if alias.name == "import_module":
                    self.import_aliases.add(bound)
            else:
                function = self._analysis.function_exports.get(target_module, {}).get(alias.name)
                self.function_bindings[bound] = function

    def _resolve_function_value(self, node: ast.AST) -> _FunctionIdentity | None:
        if isinstance(node, ast.Name):
            return self.function_bindings.get(node.id)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            module = self.module_bindings.get(node.value.id)
            if module is not None:
                return self._analysis.function_exports.get(module, {}).get(node.attr)
        return None

    def _record_scope_entry(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        scope = self._analysis.scope_for(node)
        scope.entry_bindings = dict(self.bindings)
        scope.entry_sequences = dict(self.sequences)
        scope.entry_import_aliases = frozenset(self.import_aliases)
        scope.entry_importlib_aliases = frozenset(self.importlib_aliases)
        scope.entry_function_bindings = dict(self.function_bindings)
        scope.entry_module_bindings = dict(self.module_bindings)
        scope.entry_recorded = True

    def _visit_definition_header(self, node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) -> None:
        self._record_scope_entry(node)
        for decorator in getattr(node, "decorator_list", ()):
            self.visit(decorator)
        for default in (
            getattr(node.args, "defaults", ()) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else ()
        ):
            self.visit(default)
        for default in (
            getattr(node.args, "kw_defaults", ()) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) else ()
        ):
            if default is not None:
                self.visit(default)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None:
            self.visit(node.returns)
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                self.visit(base)
            for keyword in node.keywords:
                self.visit(keyword.value)
        self._forget_names((node.name,))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.function_bindings[node.name] = self._analysis.function_identity(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_definition_header(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_definition_header(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_definition_header(node)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        base = self._state()
        left = self._branch(node.body, base)
        right = self._branch(node.orelse, base) if node.orelse else base
        self._merge_states(left, right)

    def visit_For(self, node: ast.For | ast.AsyncFor) -> None:
        self.visit(node.iter)
        after_iter = self._state()
        # Resolve the source from bindings proven before this statement.  The
        # scope-wide assignment index also contains future assignments, which
        # must never make an earlier loop appear statically bounded.
        sequence = _resolve_static_sequence(node.iter, self.sequences)
        self._forget_names(_assigned_names(node.target))
        target_names = _assigned_names(node.target)
        if sequence is not None:
            values: dict[str, set[str]] = {}
            for item in sequence:
                for name, item_value in _assignment_targets(node.target, item).items():
                    if isinstance(item_value, str):
                        values.setdefault(name, set()).add(item_value)
            for name in target_names:
                self.bindings[name] = frozenset(values[name]) if name in values else None
        body = self._branch(node.body, self._state())
        loop_exit = self._branch(node.orelse, body) if node.orelse else body
        self._merge_states(after_iter, loop_exit)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self.visit_For(node)

    def visit_While(self, node: ast.While) -> None:
        self.visit(node.test)
        base = self._state()
        body = self._branch(node.body, base)
        loop_exit = self._branch(node.orelse, body) if node.orelse else body
        self._merge_states(base, loop_exit)

    def visit_Try(self, node: ast.Try) -> None:
        base = self._state()
        body = self._branch(node.body, base)
        exits = [body]
        for handler in node.handlers:
            exits.append(self._branch([handler], base))
        if node.orelse:
            exits = [self._branch(node.orelse, exit_state) for exit_state in exits]
        merged = exits[0]
        for exit_state in exits[1:]:
            merged = (
                _merge_static_bindings(merged[0], exit_state[0]),
                {
                    name: _merge_sequence_values(merged[1].get(name), exit_state[1].get(name))
                    for name in merged[1].keys() | exit_state[1].keys()
                },
                merged[2] & exit_state[2],
                merged[3] & exit_state[3],
                {
                    name: merged[4].get(name) if merged[4].get(name) == exit_state[4].get(name) else None
                    for name in merged[4].keys() | exit_state[4].keys()
                },
                {
                    name: merged[5].get(name) if merged[5].get(name) == exit_state[5].get(name) else None
                    for name in merged[5].keys() | exit_state[5].keys()
                },
            )
        self._merge_states(merged, self._branch(node.finalbody, merged) if node.finalbody else merged)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is not None:
            self.visit(node.type)
        if node.name is not None:
            self._forget_names((node.name,))
        for statement in node.body:
            self.visit(statement)

    def visit_With(self, node: ast.With | ast.AsyncWith) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                names = _assigned_names(item.optional_vars)
                self._forget_names(names)
        for statement in node.body:
            self.visit(statement)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        self.visit_With(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        # Lambda bodies have a separate lexical parameter environment.  Keep
        # outer proven aliases, but invalidate parameters and restore the
        # enclosing flow after visiting the body.
        outer = self._state()
        for parameter in _function_parameters(node):
            self._forget_names((parameter,))
        self.visit(node.body)
        (
            self.bindings,
            self.sequences,
            self.import_aliases,
            self.importlib_aliases,
            self.function_bindings,
            self.module_bindings,
        ) = outer


class _StaticScopeAnalysis:
    """Collect static bindings without allowing sibling lexical scopes to leak."""

    def __init__(self, tree: ast.Module, module: str = "") -> None:
        self.tree = tree
        self.module = module
        self.function_exports: dict[str, dict[str, _FunctionIdentity | None]] = {}
        self.root = _StaticScope(None, None)
        self.scopes: list[_StaticScope] = [self.root]
        self._node_scopes: dict[int, _StaticScope] = {}
        self.call_aliases: dict[int, tuple[frozenset[str], frozenset[str]]] = {}
        self.call_bindings: dict[int, dict[str, _StaticValue]] = {}
        self.call_targets: dict[int, _FunctionIdentity | None] = {}
        self._walk(tree, self.root)
        for scope in self.scopes:
            self._finalize(scope)
        self._compute_callsite_bindings()

    def function_identity(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> _FunctionIdentity:
        return self.module, id(node)

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

    def _compute_callsite_bindings(self) -> None:
        self.call_aliases.clear()
        self.call_bindings.clear()
        self.call_targets.clear()
        for scope in self.scopes:
            scope.entry_recorded = False
        for scope in self.scopes:
            parent = scope.parent
            if scope.entry_recorded:
                bindings = scope.entry_bindings
                sequences = scope.entry_sequences
                import_aliases = set(scope.entry_import_aliases)
                importlib_aliases = set(scope.entry_importlib_aliases)
                function_bindings = scope.entry_function_bindings
                module_bindings = scope.entry_module_bindings
            else:
                bindings = parent.merged_bindings if parent is not None else {}
                sequences = parent.merged_sequences if parent is not None else {}
                import_aliases = set(parent.merged_import_aliases) if parent is not None else set()
                importlib_aliases = set(parent.merged_importlib_aliases) if parent is not None else set()
                function_bindings = parent.merged_function_bindings if parent is not None else {}
                module_bindings = parent.merged_module_bindings if parent is not None else {}
            if isinstance(scope.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                parameters = _function_parameters(scope.node)
                for parameter in parameters:
                    bindings = {**bindings, parameter: None}
                    sequences = {**sequences, parameter: None}
                    import_aliases.discard(parameter)
                    importlib_aliases.discard(parameter)
                    function_bindings = {**function_bindings, parameter: None}
                    module_bindings = {**module_bindings, parameter: None}
            flow = _ScopeBindingFlow(
                self,
                scope,
                bindings,
                sequences,
                import_aliases,
                importlib_aliases,
                function_bindings,
                module_bindings,
            )
            if scope.node is None:
                statements = self.tree.body
            elif isinstance(scope.node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                statements = scope.node.body
            else:
                continue
            for statement in statements:
                flow.visit(statement)
            scope.merged_bindings = dict(flow.bindings)
            scope.merged_sequences = dict(flow.sequences)
            scope.merged_function_bindings = dict(flow.function_bindings)
            scope.merged_import_aliases = frozenset(flow.import_aliases)
            scope.merged_importlib_aliases = frozenset(flow.importlib_aliases)
            scope.merged_module_bindings = dict(flow.module_bindings)


def _static_assignments(tree: ast.Module) -> tuple[dict[str, ast.AST], dict[str, frozenset[str]]]:
    analysis = _StaticScopeAnalysis(tree)
    return analysis.root.assignments, analysis.root.bindings


def _function_parameter_bindings(
    analysis: _StaticScopeAnalysis,
    callsites: Mapping[_FunctionIdentity, list[tuple[ast.Call, _StaticScopeAnalysis]]] | None = None,
) -> dict[tuple[int, int], frozenset[str]]:
    """Prove helper parameters from every statically visible direct callsite."""

    functions = [
        scope.node for scope in analysis.scopes if isinstance(scope.node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    local_calls: dict[_FunctionIdentity, list[tuple[ast.Call, _StaticScopeAnalysis]]] = {}
    if callsites is None:
        for node in ast.walk(analysis.tree):
            if not isinstance(node, ast.Call):
                continue
            target = analysis.call_targets.get(id(node))
            if target is not None:
                local_calls.setdefault(target, []).append((node, analysis))
        callsites = local_calls
    result: dict[tuple[int, int], frozenset[str]] = {}
    for function in functions:
        function_calls = callsites.get(analysis.function_identity(function), [])
        if not function_calls:
            continue
        positional = [*function.args.posonlyargs, *function.args.args]
        for index, _parameter in enumerate(positional):
            values: set[str] = set()
            proven = True
            for call, caller_analysis in function_calls:
                if index >= len(call.args):
                    proven = False
                    break
                caller_bindings = caller_analysis.call_bindings.get(id(call), {})
                resolved = _resolve_static_strings(call.args[index], caller_bindings)
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
    ) -> None:
        self._module = module
        self._analysis = analysis
        self._parameter_bindings = parameter_bindings
        self.evidence: list[DynamicImport] = []
        self.unbounded: list[str] = []

    def visit_Call(self, node: ast.Call) -> None:
        import_aliases, importlib_aliases = self._analysis.call_aliases.get(id(node), (frozenset(), frozenset()))
        if _import_module_call(node, set(import_aliases), set(importlib_aliases)) and node.args:
            destination = node.args[0]
            bindings = self._analysis.call_bindings.get(id(node), {})
            values = _resolve_static_strings(destination, bindings)
            kind = "literal_or_static"
            if (
                values is None
                and isinstance(destination, ast.Name)
                and isinstance(self._analysis.scope_for(node).node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ):
                function = self._analysis.scope_for(node).node
                assert isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
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


def _module_analyses(root: Path) -> dict[str, tuple[Path, ast.Module, _StaticScopeAnalysis]]:
    analyses: dict[str, tuple[Path, ast.Module, _StaticScopeAnalysis]] = {}
    for path in (root / "src").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        module = module_name(root, path)
        analyses[module] = (path, tree, _StaticScopeAnalysis(tree, module))
    exports: dict[str, dict[str, _FunctionIdentity | None]] = {}
    for module, (_path, _tree, analysis) in analyses.items():
        module_exports: dict[str, _FunctionIdentity | None] = {}
        for scope in analysis.scopes:
            function = scope.node
            if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) or scope.parent is not analysis.root:
                continue
            identity = analysis.function_identity(function)
            module_exports[function.name] = identity if function.name not in module_exports else None
        exports[module] = module_exports
    for _module, (_path, _tree, analysis) in analyses.items():
        analysis.function_exports = exports
        analysis._compute_callsite_bindings()
    return analyses


def _all_function_calls(
    analyses: Mapping[str, tuple[Path, ast.Module, _StaticScopeAnalysis]],
) -> dict[_FunctionIdentity, list[tuple[ast.Call, _StaticScopeAnalysis]]]:
    calls: dict[_FunctionIdentity, list[tuple[ast.Call, _StaticScopeAnalysis]]] = {}
    for _path, tree, analysis in analyses.values():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                target = analysis.call_targets.get(id(node))
                if target is not None:
                    calls.setdefault(target, []).append((node, analysis))
    return calls


def _dynamic_import_analysis(
    analyses: Mapping[str, tuple[Path, ast.Module, _StaticScopeAnalysis]],
) -> tuple[list[DynamicImport], list[str]]:
    """Inspect dynamic imports after one parse of every source module."""

    evidence: list[DynamicImport] = []
    unbounded: list[str] = []
    callsites = _all_function_calls(analyses)
    for module, (_path, tree, analysis) in analyses.items():
        parameter_bindings = _function_parameter_bindings(analysis, callsites)
        visitor = _DynamicImportVisitor(module, analysis, parameter_bindings)
        visitor.visit(tree)
        evidence.extend(visitor.evidence)
        unbounded.extend(visitor.unbounded)
    return evidence, unbounded


def dynamic_import_destinations(root: Path) -> tuple[list[DynamicImport], list[str]]:
    """Inspect every importlib destination and reject unbounded provenance."""

    return _dynamic_import_analysis(_module_analyses(root))


def _module_imports_from_analyses(
    analyses: Mapping[str, tuple[Path, ast.Module, _StaticScopeAnalysis]],
    dynamic_evidence: list[DynamicImport],
) -> tuple[dict[str, set[str]], list[str]]:
    modules = {name: path for name, (path, _tree, _analysis) in analyses.items()}
    imports: dict[str, set[str]] = {}
    dynamic: list[str] = []
    for name, (_path, tree, _analysis) in analyses.items():
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
    accepted_kinds = {"literal_or_static", "bounded_callsite"}
    for item in dynamic_evidence:
        if item.destination_kind not in accepted_kinds or item.destination_values is None:
            continue
        for destination in item.destination_values:
            if destination in modules:
                imports[item.module].add(destination)
                dynamic.append(f"{item.module}:{item.line}:{destination}")
    return imports, dynamic


def module_imports(root: Path) -> tuple[dict[str, set[str]], list[str]]:
    """Build the static and dynamic import graph from one AST pass."""

    import_graph, dynamic, _evidence, _unbounded = _analyze_import_graph(root)
    return import_graph, dynamic


def _analyze_import_graph(root: Path) -> tuple[dict[str, set[str]], list[str], list[DynamicImport], list[str]]:
    analyses = _module_analyses(root)
    dynamic_evidence, dynamic_unbounded = _dynamic_import_analysis(analyses)
    import_graph, dynamic = _module_imports_from_analyses(analyses, dynamic_evidence)
    return import_graph, dynamic, dynamic_evidence, dynamic_unbounded


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
    import_graph, dynamic, _evidence, _unbounded = _analyze_import_graph(root)
    importers = sorted(module for module, targets in import_graph.items() if candidate_module in targets)
    importers.extend(item for item in dynamic if candidate_module in item)
    return importers
