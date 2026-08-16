"""AST metrics used by the repository code-quality audit."""

from __future__ import annotations

import ast
import copy
import hashlib
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FunctionMetric:
    path: str
    qualname: str
    line: int
    end_line: int
    lines: int
    complexity: int
    category: str
    digest: str

    @property
    def identity(self) -> str:
        return f"{self.path}::{self.qualname}"


@dataclass(frozen=True, slots=True)
class SilentHandler:
    path: str
    qualname: str
    line: int
    exception: str

    @property
    def identity(self) -> str:
        return f"{self.path}::{self.qualname}::{self.exception}"


class _ComplexityVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.value = 1
        self._root: ast.AST | None = None

    def calculate(self, node: ast.AST) -> int:
        self._root = node
        for child in ast.iter_child_nodes(node):
            self.visit(child)
        return self.value

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node is self._root:
            self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef

    def visit_If(self, node: ast.If) -> None:
        self.value += 1
        self.generic_visit(node)

    visit_For = visit_If
    visit_AsyncFor = visit_If
    visit_While = visit_If
    visit_IfExp = visit_If

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        self.value += max(0, len(node.values) - 1)
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try) -> None:
        self.value += len(node.handlers) + bool(node.orelse) + bool(node.finalbody)
        self.generic_visit(node)

    visit_TryStar = visit_Try

    def visit_Match(self, node: ast.Match) -> None:
        self.value += len(node.cases)
        self.generic_visit(node)

    def visit_comprehension(self, node: ast.comprehension) -> None:
        self.value += 1 + len(node.ifs)
        self.generic_visit(node)


class _SilentHandlerVisitor(ast.NodeVisitor):
    def __init__(self, root: ast.AST) -> None:
        self.root = root
        self.handlers: list[ast.ExceptHandler] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node is self.root:
            self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef
    visit_Lambda = visit_FunctionDef

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if _silent_handler(node):
            self.handlers.append(node)
        self.generic_visit(node)


class _FunctionCollector(ast.NodeVisitor):
    def __init__(self, *, path: str, category: str) -> None:
        self.path = path
        self.category = category
        self.stack: list[str] = []
        self.functions: list[FunctionMetric] = []
        self.handlers: list[SilentHandler] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.stack.append(node.name)
        qualname = ".".join(self.stack)
        end_line = int(node.end_lineno or node.lineno)
        normalized = copy.deepcopy(node)
        normalized.name = "_"
        normalized.decorator_list = []
        if (
            normalized.body
            and isinstance(normalized.body[0], ast.Expr)
            and isinstance(normalized.body[0].value, ast.Constant)
            and isinstance(normalized.body[0].value.value, str)
        ):
            normalized.body = normalized.body[1:]
        normalized_ast = repr(_canonical_ast(normalized)).encode("utf-8")
        digest = hashlib.sha256(normalized_ast).hexdigest()
        self.functions.append(
            FunctionMetric(
                path=self.path,
                qualname=qualname,
                line=node.lineno,
                end_line=end_line,
                lines=end_line - node.lineno + 1,
                complexity=_ComplexityVisitor().calculate(node),
                category=self.category,
                digest=digest,
            )
        )
        handler_visitor = _SilentHandlerVisitor(node)
        handler_visitor.visit(node)
        for handler in handler_visitor.handlers:
            exception = _exception_name(handler.type)
            if exception in {"bare", "BaseException", "Exception"}:
                self.handlers.append(SilentHandler(self.path, qualname, handler.lineno, exception))
        self.generic_visit(node)
        self.stack.pop()


def _canonical_ast(value: object) -> object:
    """Return a stable, version-independent representation of an AST value."""
    if isinstance(value, ast.AST):
        fields: list[tuple[str, object]] = []
        for name, child in ast.iter_fields(value):
            if child is None or child == []:
                continue
            fields.append((name, _canonical_ast(child)))
        return type(value).__name__, tuple(fields)
    if isinstance(value, list):
        return tuple(_canonical_ast(item) for item in value)
    return value


def collect_python_metrics(
    tree: ast.AST,
    *,
    path: str,
    category: str,
) -> tuple[list[FunctionMetric], list[SilentHandler]]:
    collector = _FunctionCollector(path=path, category=category)
    collector.visit(tree)
    return collector.functions, collector.handlers


def _silent_handler(handler: ast.ExceptHandler) -> bool:
    if not handler.body:
        return True
    for statement in handler.body:
        if isinstance(statement, (ast.Pass, ast.Continue, ast.Break)):
            continue
        if isinstance(statement, ast.Return) and (
            statement.value is None
            or isinstance(statement.value, ast.Constant)
            and statement.value.value is None
        ):
            continue
        return False
    return True


def _exception_name(node: ast.expr | None) -> str:
    if node is None:
        return "bare"
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Tuple):
        return ",".join(sorted(_exception_name(item) for item in node.elts))
    return type(node).__name__


__all__ = ["FunctionMetric", "SilentHandler", "collect_python_metrics"]
