from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest


def _audit_module() -> ModuleType:
    script_dir = Path(__file__).parents[1] / "scripts" / "ci"
    sys.path.insert(0, str(script_dir))
    try:
        spec = importlib.util.spec_from_file_location(
            "code_quality_audit",
            script_dir / "code_quality_audit.py",
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(script_dir))


def _function_source(name: str) -> str:
    return (
        f"def {name}(value: int) -> int:\n"
        "    total = 0\n"
        "    if value > 0:\n"
        "        total += value\n"
        "    for item in range(3):\n"
        "        total += item\n"
        "    if total > 10:\n"
        "        total -= 1\n"
        "    return total\n"
    )


def test_duplicate_digest_ignores_function_name_and_ast_field_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit = _audit_module()
    ast_support = sys.modules["code_quality_ast"]
    tree = ast.parse(_function_source("first"))
    expected_canonical = ast_support._canonical_ast(tree)
    original_iter_fields = ast.iter_fields

    def reversed_iter_fields(node: ast.AST):
        return iter(reversed(list(original_iter_fields(node))))

    monkeypatch.setattr(ast, "iter_fields", reversed_iter_fields)
    assert ast_support._canonical_ast(tree) == expected_canonical

    first, _ = audit.collect_python_metrics(
        ast.parse(_function_source("first")),
        path="first.py",
        category="production",
    )
    second, _ = audit.collect_python_metrics(
        ast.parse(_function_source("second")),
        path="second.py",
        category="production",
    )
    assert first[0].digest == second[0].digest


def test_audit_inventories_oversized_and_duplicate_functions(tmp_path: Path) -> None:
    audit = _audit_module()
    package = tmp_path / "src" / "sample"
    package.mkdir(parents=True)
    (package / "first.py").write_text(
        _function_source("first") + "# filler\n" * 500,
        encoding="utf-8",
    )
    (package / "second.py").write_text(
        _function_source("second"),
        encoding="utf-8",
    )

    report = audit.audit_repository(tmp_path)

    assert report["summary"]["code_files"] == 2
    assert report["summary"]["oversized_handwritten_files"] == 1
    assert report["summary"]["duplicate_function_groups"] == 1
    assert report["forbidden_residue"] == []


def test_audit_counts_lambdas_and_qualified_broad_exceptions() -> None:
    audit = _audit_module()
    source = """
handler = lambda value: value if value else 0

def guarded() -> None:
    try:
        raise RuntimeError
    except (builtins.Exception, package.ValueError):
        pass
"""
    functions, handlers = audit.collect_python_metrics(
        ast.parse(source),
        path="sample.py",
        category="production",
    )

    assert any(item.qualname.startswith("<lambda>@") for item in functions)
    assert [item.exception for item in handlers] == ["builtins.Exception,package.ValueError"]


def test_audit_excludes_plain_venv_and_detects_nonstandard_tests(
    tmp_path: Path,
) -> None:
    audit = _audit_module()
    test_file = tmp_path / "src" / "sample" / "specs" / "check.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text("value = 1\n", encoding="utf-8")
    ignored = tmp_path / "src" / "sample" / "venv" / "ignored.py"
    ignored.parent.mkdir(parents=True)
    ignored.write_text("raise RuntimeError\n", encoding="utf-8")

    report = audit.audit_repository(tmp_path)

    assert report["summary"]["code_files"] == 1
    assert report["summary"]["categories"] == {"test": 1}


def test_ratchet_rejects_growth_and_new_duplicate_group(tmp_path: Path) -> None:
    audit = _audit_module()
    package = tmp_path / "src" / "sample"
    package.mkdir(parents=True)
    first = package / "first.py"
    first.write_text(
        "# line\n" * 501 + _function_source("first"),
        encoding="utf-8",
    )
    baseline_report = audit.audit_repository(tmp_path)
    baseline = audit.baseline_from_report(baseline_report)

    first.write_text(
        "# line\n" * 502 + _function_source("first"),
        encoding="utf-8",
    )
    (package / "second.py").write_text(
        _function_source("second"),
        encoding="utf-8",
    )
    failures = audit.check_against_baseline(
        audit.audit_repository(tmp_path),
        baseline,
    )

    assert any("Oversized file grew" in failure for failure in failures)
    assert any("Duplicate function group introduced or changed" in failure for failure in failures)


def test_duplicate_group_reintroduction_requires_a_new_baseline(
    tmp_path: Path,
) -> None:
    audit = _audit_module()
    package = tmp_path / "src" / "sample"
    package.mkdir(parents=True)
    first = package / "first.py"
    second = package / "second.py"
    first.write_text(_function_source("first"), encoding="utf-8")
    second.write_text(_function_source("second"), encoding="utf-8")
    original_baseline = audit.baseline_from_report(audit.audit_repository(tmp_path))

    second.unlink()
    reduced_report = audit.audit_repository(tmp_path)
    assert any(
        "baseline is stale after debt reduction" in failure
        for failure in audit.check_against_baseline(
            reduced_report,
            original_baseline,
        )
    )
    reduced_baseline = audit.baseline_from_report(reduced_report)

    second.write_text(_function_source("second"), encoding="utf-8")
    assert any(
        "Duplicate function group introduced or changed" in failure
        for failure in audit.check_against_baseline(
            audit.audit_repository(tmp_path),
            reduced_baseline,
        )
    )


def test_silent_handler_reintroduction_requires_a_new_baseline(
    tmp_path: Path,
) -> None:
    audit = _audit_module()
    package = tmp_path / "src" / "sample"
    package.mkdir(parents=True)
    first = package / "first.py"
    second = package / "second.py"
    handler = "def {name}() -> None:\n    try:\n        raise RuntimeError\n    except Exception:\n        pass\n"
    first.write_text(handler.format(name="first"), encoding="utf-8")
    second.write_text(handler.format(name="second"), encoding="utf-8")

    second.unlink()
    reduced_report = audit.audit_repository(tmp_path)
    reduced_baseline = audit.baseline_from_report(reduced_report)
    second.write_text(handler.format(name="second"), encoding="utf-8")

    assert any(
        "Silent broad exception handler introduced" in failure
        for failure in audit.check_against_baseline(
            audit.audit_repository(tmp_path),
            reduced_baseline,
        )
    )


def test_ratchet_rejects_one_shot_delivery_residue(tmp_path: Path) -> None:
    audit = _audit_module()
    workflow = tmp_path / ".github" / "workflows" / "tmp-push-fix.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "permissions:\n  contents: write\n",
        encoding="utf-8",
    )

    report = audit.audit_repository(tmp_path)
    failures = audit.check_against_baseline(
        report,
        audit.baseline_from_report(report),
    )

    assert report["forbidden_residue"] == [".github/workflows/tmp-push-fix.yml"]
    assert failures == ["Forbidden one-shot delivery residue: .github/workflows/tmp-push-fix.yml"]
