from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path
from types import ModuleType


def _audit_module() -> ModuleType:
    script_dir = Path(__file__).parents[1] / "scripts" / "ci"
    sys.path.insert(0, str(script_dir))
    try:
        spec = importlib.util.spec_from_file_location("code_quality_audit", script_dir / "code_quality_audit.py")
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


def test_duplicate_digest_is_stable_across_python_ast_versions() -> None:
    audit = _audit_module()
    functions, _handlers = audit.collect_python_metrics(
        ast.parse(_function_source("first")),
        path="sample.py",
        category="production",
    )

    assert functions[0].digest == "4ed5cd437cc2fba317ec97936d684e7c37d3c7516cf89f5e48b6badf2cb02431"


def test_audit_inventories_oversized_and_duplicate_functions(tmp_path: Path) -> None:
    audit = _audit_module()
    package = tmp_path / "src" / "sample"
    package.mkdir(parents=True)
    (package / "first.py").write_text(_function_source("first") + "# filler\n" * 500, encoding="utf-8")
    (package / "second.py").write_text(_function_source("second"), encoding="utf-8")

    report = audit.audit_repository(tmp_path)

    assert report["summary"]["code_files"] == 2
    assert report["summary"]["oversized_handwritten_files"] == 1
    assert report["summary"]["duplicate_function_groups"] == 1
    assert report["forbidden_residue"] == []


def test_ratchet_rejects_growth_and_new_duplicate_group(tmp_path: Path) -> None:
    audit = _audit_module()
    package = tmp_path / "src" / "sample"
    package.mkdir(parents=True)
    first = package / "first.py"
    first.write_text("# line\n" * 501 + _function_source("first"), encoding="utf-8")
    baseline_report = audit.audit_repository(tmp_path)
    baseline = audit.baseline_from_report(baseline_report)

    first.write_text("# line\n" * 502 + _function_source("first"), encoding="utf-8")
    (package / "second.py").write_text(_function_source("second"), encoding="utf-8")
    failures = audit.check_against_baseline(audit.audit_repository(tmp_path), baseline)

    assert any("Oversized file grew" in failure for failure in failures)
    assert any("Duplicate function group introduced" in failure for failure in failures)


def test_ratchet_rejects_one_shot_delivery_residue(tmp_path: Path) -> None:
    audit = _audit_module()
    workflow = tmp_path / ".github" / "workflows" / "tmp-push-fix.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("permissions:\n  contents: write\n", encoding="utf-8")

    report = audit.audit_repository(tmp_path)
    failures = audit.check_against_baseline(report, audit.baseline_from_report(report))

    assert report["forbidden_residue"] == [".github/workflows/tmp-push-fix.yml"]
    assert failures == ["Forbidden one-shot delivery residue: .github/workflows/tmp-push-fix.yml"]
