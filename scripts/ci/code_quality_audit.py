#!/usr/bin/env python3
"""Inventory and ratchet structural code-quality debt without changing behavior."""

from __future__ import annotations

import argparse
import ast
import json
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from code_quality_ast import FunctionMetric, SilentHandler, collect_python_metrics
from code_quality_report import render_markdown

SCHEMA_VERSION = 1
OVERSIZED_FILE_LINES = 500
LONG_FUNCTION_LINES = 100
HIGH_COMPLEXITY = 30
DUPLICATE_FUNCTION_LINES = 8
CODE_ROOTS = (
    ".github/workflows",
    "action",
    "ci",
    "dashboard",
    "devcontainer-features",
    "distributions",
    "fuzzers",
    "guarded-repository",
    "integrations",
    "rust",
    "scripts",
    "src",
    "tests",
)
CODE_SUFFIXES = frozenset(
    {
        ".cjs",
        ".css",
        ".html",
        ".js",
        ".mjs",
        ".ps1",
        ".py",
        ".rs",
        ".sh",
        ".swift",
        ".toml",
        ".ts",
        ".tsx",
        ".wxs",
        ".yaml",
        ".yml",
    }
)
EXCLUDED_PARTS = frozenset(
    {
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
        "node_modules",
    }
)
GENERATED_PREFIXES = ("src/codex_plugin_scanner/guard/daemon/static/assets/",)
GENERATED_NAMES = frozenset({"pnpm-lock.yaml"})
FORBIDDEN_RESIDUE = (
    ".github/rust-required-gzip-b64",
    ".github/rust-required-patch",
    "scripts/ci/apply_daemon_edge_hardening.py",
)
FORBIDDEN_WORKFLOW_PREFIXES = ("tmp-",)
FORBIDDEN_WORKFLOW_FRAGMENTS = ("-cleanup-shepherd", "-final-tree-shepherd", "-source-fix-shepherd")


@dataclass(frozen=True, slots=True)
class FileMetric:
    path: str
    lines: int
    category: str
    generated: bool


def _code_files(root: Path) -> Iterable[Path]:
    seen: set[Path] = set()
    for relative_root in CODE_ROOTS:
        base = root / relative_root
        if not base.exists():
            continue
        candidates = (base,) if base.is_file() else base.rglob("*")
        for path in candidates:
            if not path.is_file() or path.suffix.lower() not in CODE_SUFFIXES:
                continue
            relative = path.relative_to(root)
            if any(part in EXCLUDED_PARTS for part in relative.parts) or relative in seen:
                continue
            seen.add(relative)
            yield path


def _category(path: str) -> str:
    name = Path(path).name
    if path.startswith("tests/") or ".test." in name or ".spec." in name:
        return "test"
    if path.startswith(".github/workflows/"):
        return "workflow"
    tooling_prefixes = (
        "action/",
        "ci/",
        "devcontainer-features/",
        "distributions/",
        "fuzzers/",
        "guarded-repository/",
        "integrations/",
        "scripts/",
    )
    if path.startswith(tooling_prefixes):
        return "tooling"
    return "production"


def _generated(path: str) -> bool:
    return path.startswith(GENERATED_PREFIXES) or Path(path).name in GENERATED_NAMES or ".generated." in path


def _line_count(path: Path) -> int:
    with path.open("rb") as handle:
        return sum(1 for _ in handle)


def _forbidden_residue(root: Path) -> list[str]:
    residue = [path for path in FORBIDDEN_RESIDUE if (root / path).exists()]
    workflows = root / ".github/workflows"
    if workflows.is_dir():
        for path in workflows.iterdir():
            if not path.is_file():
                continue
            if path.name.startswith(FORBIDDEN_WORKFLOW_PREFIXES) or any(
                fragment in path.name for fragment in FORBIDDEN_WORKFLOW_FRAGMENTS
            ):
                residue.append(str(path.relative_to(root)))
    return sorted(set(residue))


def audit_repository(root: Path) -> dict[str, Any]:
    files: list[FileMetric] = []
    functions: list[FunctionMetric] = []
    handlers: list[SilentHandler] = []
    parse_errors: list[dict[str, object]] = []
    for path in sorted(_code_files(root)):
        relative = path.relative_to(root).as_posix()
        category = _category(relative)
        generated = _generated(relative)
        files.append(FileMetric(relative, _line_count(path), category, generated))
        if path.suffix != ".py" or generated or category == "test":
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            parse_errors.append({"path": relative, "error": f"{type(exc).__name__}: {exc}"})
            continue
        file_functions, file_handlers = collect_python_metrics(
            tree,
            path=relative,
            category=category,
        )
        functions.extend(file_functions)
        handlers.extend(file_handlers)

    duplicate_candidates: dict[str, list[FunctionMetric]] = defaultdict(list)
    for function in functions:
        if function.lines >= DUPLICATE_FUNCTION_LINES:
            duplicate_candidates[function.digest].append(function)
    duplicate_groups = [
        {
            "digest": digest,
            "lines": max(item.lines for item in instances),
            "instances": [asdict(item) for item in sorted(instances, key=lambda item: (item.path, item.line))],
        }
        for digest, instances in duplicate_candidates.items()
        if len(instances) >= 2
    ]
    duplicate_groups.sort(
        key=lambda item: (int(item["lines"]), len(item["instances"]), str(item["digest"])),
        reverse=True,
    )

    oversized = [asdict(item) for item in files if item.lines > OVERSIZED_FILE_LINES]
    oversized.sort(key=lambda item: (int(item["lines"]), str(item["path"])), reverse=True)
    long_functions = [
        asdict(item) | {"identity": item.identity}
        for item in functions
        if item.lines >= LONG_FUNCTION_LINES
    ]
    long_functions.sort(key=lambda item: (int(item["lines"]), str(item["identity"])), reverse=True)
    complex_functions = [
        asdict(item) | {"identity": item.identity}
        for item in functions
        if item.complexity >= HIGH_COMPLEXITY
    ]
    complex_functions.sort(key=lambda item: (int(item["complexity"]), int(item["lines"])), reverse=True)
    silent_handlers = [asdict(item) | {"identity": item.identity} for item in handlers]
    silent_handlers.sort(key=lambda item: (str(item["path"]), int(item["line"])))
    categories = Counter(item.category for item in files)
    return {
        "schema_version": SCHEMA_VERSION,
        "thresholds": {
            "oversized_file_lines": OVERSIZED_FILE_LINES,
            "long_function_lines": LONG_FUNCTION_LINES,
            "high_complexity": HIGH_COMPLEXITY,
            "duplicate_function_lines": DUPLICATE_FUNCTION_LINES,
        },
        "summary": {
            "code_files": len(files),
            "categories": dict(sorted(categories.items())),
            "oversized_files": len(oversized),
            "oversized_handwritten_files": sum(not bool(item["generated"]) for item in oversized),
            "oversized_generated_files": sum(bool(item["generated"]) for item in oversized),
            "python_functions": len(functions),
            "long_python_functions": len(long_functions),
            "high_complexity_python_functions": len(complex_functions),
            "duplicate_function_groups": len(duplicate_groups),
            "duplicate_function_instances": sum(len(item["instances"]) for item in duplicate_groups),
            "silent_broad_exception_handlers": len(silent_handlers),
            "parse_errors": len(parse_errors),
            "forbidden_residue": len(_forbidden_residue(root)),
        },
        "oversized_files": oversized,
        "long_functions": long_functions,
        "complex_functions": complex_functions,
        "duplicate_function_groups": duplicate_groups,
        "silent_broad_exception_handlers": silent_handlers,
        "parse_errors": parse_errors,
        "forbidden_residue": _forbidden_residue(root),
    }


def baseline_from_report(report: dict[str, Any]) -> dict[str, Any]:
    oversized = {
        str(item["path"]): int(item["lines"])
        for item in report["oversized_files"]
        if not bool(item["generated"])
    }
    long_functions = {str(item["identity"]): int(item["lines"]) for item in report["long_functions"]}
    complex_functions = {str(item["identity"]): int(item["complexity"]) for item in report["complex_functions"]}
    duplicate_groups = {
        str(item["digest"]): len(item["instances"])
        for item in report["duplicate_function_groups"]
    }
    silent_handlers = Counter(str(item["identity"]) for item in report["silent_broad_exception_handlers"])
    return {
        "schema_version": SCHEMA_VERSION,
        "thresholds": report["thresholds"],
        "oversized_files": dict(sorted(oversized.items())),
        "long_functions": dict(sorted(long_functions.items())),
        "complex_functions": dict(sorted(complex_functions.items())),
        "duplicate_function_groups": dict(sorted(duplicate_groups.items())),
        "silent_broad_exception_handlers": dict(sorted(silent_handlers.items())),
    }


def check_against_baseline(report: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if report["parse_errors"]:
        failures.extend(f"Python parse failure: {item['path']}: {item['error']}" for item in report["parse_errors"])
    failures.extend(f"Forbidden one-shot delivery residue: {path}" for path in report["forbidden_residue"])
    comparisons: Sequence[tuple[str, str, str]] = (
        ("oversized_files", "lines", "Oversized file"),
        ("long_functions", "lines", "Long function"),
        ("complex_functions", "complexity", "Complex function"),
    )
    for key, value_key, label in comparisons:
        expected = {str(name): int(value) for name, value in baseline.get(key, {}).items()}
        identity_key = "path" if key == "oversized_files" else "identity"
        for item in report[key]:
            if key == "oversized_files" and bool(item["generated"]):
                continue
            identity = str(item[identity_key])
            value = int(item[value_key])
            if identity not in expected:
                failures.append(f"{label} introduced: {identity} ({value})")
            elif value > expected[identity]:
                failures.append(f"{label} grew: {identity} ({expected[identity]} -> {value})")
    expected_duplicates = {
        str(name): int(value) for name, value in baseline.get("duplicate_function_groups", {}).items()
    }
    for group in report["duplicate_function_groups"]:
        digest = str(group["digest"])
        count = len(group["instances"])
        if digest not in expected_duplicates:
            locations = ", ".join(f"{item['path']}:{item['line']}" for item in group["instances"])
            failures.append(f"Duplicate function group introduced ({count} instances): {locations}")
        elif count > expected_duplicates[digest]:
            failures.append(f"Duplicate function group grew: {digest} ({expected_duplicates[digest]} -> {count})")
    expected_handlers = Counter(
        {str(name): int(value) for name, value in baseline.get("silent_broad_exception_handlers", {}).items()}
    )
    current_handlers = Counter(str(item["identity"]) for item in report["silent_broad_exception_handlers"])
    for identity, count in current_handlers.items():
        if count > expected_handlers[identity]:
            failures.append(
                "Silent broad exception handler introduced: "
                f"{identity} ({expected_handlers[identity]} -> {count})"
            )
    return failures


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--write-baseline", action="store_true")
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--markdown-output", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    report = audit_repository(root)
    if args.json_output is not None:
        _write_json(args.json_output, report)
    if args.markdown_output is not None:
        output = args.markdown_output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render_markdown(report), encoding="utf-8")
    if args.write_baseline:
        if args.baseline is None:
            raise SystemExit("--write-baseline requires --baseline")
        _write_json(args.baseline, baseline_from_report(report))
        return 0
    if args.baseline is None:
        print(json.dumps(report["summary"], indent=2, sort_keys=True))
        return 0
    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    failures = check_against_baseline(report, baseline)
    if failures:
        print("Code-quality ratchet failed:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print(json.dumps(report["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
