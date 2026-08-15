from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
AUDIT_PATH = ROOT / "ci/rust_migration_regression_audit.py"


def _load_audit() -> ModuleType:
    spec = importlib.util.spec_from_file_location("rust_migration_regression_audit", AUDIT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


AUDIT = _load_audit()


def _minimal_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".github/workflows").mkdir(parents=True)
    (root / "docs/guard/contracts").mkdir(parents=True)
    (root / "rust/crate/src").mkdir(parents=True)
    (root / "src/codex_plugin_scanner/guard/runtime").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "pyproject.toml").write_text("[project]\nname='fixture'\nversion='0.0.0'\n", encoding="utf-8")
    (root / ".github/workflows/rust.yml").write_text("name: rust native wheel security codeql fuzz publish\n", encoding="utf-8")
    (root / "rust/crate/src/lib.rs").write_text("#![forbid(unsafe_code)]\npub fn ok() {}\n", encoding="utf-8")
    (root / "src/codex_plugin_scanner/guard/runtime/command_fixture.py").write_text("def adapt():\n    return 1\n", encoding="utf-8")
    (root / "tests/test_command_fixture.py").write_text("def test_command_fixture():\n    assert True\n", encoding="utf-8")
    (root / "docs/guard/contracts/rust-fixture-ownership.json").write_text(
        json.dumps({"schema_version": 1, "python_symbols_removed": ["src/retired.py::evaluate"]}),
        encoding="utf-8",
    )
    return root


def test_current_release_tree_satisfies_regression_contract() -> None:
    baseline = json.loads((ROOT / "ci/rust-migration-regression-baseline.json").read_text(encoding="utf-8"))
    assert AUDIT.audit(ROOT, baseline).blocking == ()


def test_temporary_transfer_asset_is_blocking(tmp_path: Path) -> None:
    root = _minimal_repo(tmp_path)
    transfer = root / ".github/rust-required-patch/part-00"
    transfer.parent.mkdir()
    transfer.write_text("synthetic", encoding="utf-8")
    assert any(item.code == "RUST-REG-001" for item in AUDIT.audit(root).blocking)


def test_retired_python_symbol_is_blocking(tmp_path: Path) -> None:
    root = _minimal_repo(tmp_path)
    retired = root / "src/retired.py"
    retired.parent.mkdir(exist_ok=True)
    retired.write_text("def evaluate():\n    return 'duplicate'\n", encoding="utf-8")
    assert any(item.code == "RUST-REG-004" for item in AUDIT.audit(root).blocking)


def test_first_party_unsafe_rust_is_blocking(tmp_path: Path) -> None:
    root = _minimal_repo(tmp_path)
    (root / "rust/crate/src/lib.rs").write_text(
        "pub fn broken() { unsafe { core::hint::unreachable_unchecked() } }\n",
        encoding="utf-8",
    )
    assert any(item.code == "RUST-REG-006" for item in AUDIT.audit(root).blocking)


def test_test_inventory_floor_catches_removed_coverage(tmp_path: Path) -> None:
    root = _minimal_repo(tmp_path)
    result = AUDIT.audit(root, {"minimum_test_counts": {"command_extensions": 2}})
    assert any(item.code == "RUST-REG-011" for item in result.blocking)


def test_report_is_repository_relative_and_content_free(tmp_path: Path) -> None:
    root = _minimal_repo(tmp_path)
    secret_like = "ghp_" + "A" * 36
    transfer = root / ".github/rust-required-patch/part-00"
    transfer.parent.mkdir()
    transfer.write_text(secret_like, encoding="utf-8")
    serialized = json.dumps(AUDIT.audit(root).jsonable())
    assert str(root) not in serialized
    assert secret_like not in serialized


def test_cli_rechecks_fixture(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _minimal_repo(tmp_path)
    baseline = root / "ci/baseline.json"
    baseline.parent.mkdir(exist_ok=True)
    baseline.write_text(json.dumps({"minimum_test_counts": {"command_extensions": 1}}), encoding="utf-8")
    assert AUDIT.main(["--root", str(root), "--baseline", str(baseline)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["blocking_count"] == 0
