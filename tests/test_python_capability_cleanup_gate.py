from __future__ import annotations

import importlib.util
import tarfile
from pathlib import Path
from zipfile import ZipFile

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci" / "python_capability_cleanup_gate.py"
SPEC = importlib.util.spec_from_file_location("python_capability_cleanup_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def test_cleanup_contract_covers_every_scoped_hook_capability() -> None:
    payload = GATE.run(ROOT)

    assert payload["schema"] == "hol-guard.python-capability-cleanup.v1"
    assert payload["status"] == "passed"
    assert payload["scope_files"] == 84
    assert payload["capabilities"]["legacy_python_resident_transport"] == 1
    assert payload["candidate_evidence"] == [
        {
            "path": "src/codex_plugin_scanner/guard/native_runtime_resident.py",
            "module": "codex_plugin_scanner.guard.native_runtime_resident",
            "loc": 569,
            "source_importers": [],
            "package_excluded": True,
        }
    ]
    assert payload["dynamic_import_destinations_checked"] is True
    assert payload["dynamic_import_unbounded"] == []
    assert payload["dynamic_import_count"] == len(payload["dynamic_import_evidence"])


def test_dynamic_import_gate_rejects_unbounded_destination(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "example.py").write_text(
        "import importlib\ndef load(destination: str):\n    return importlib.import_module(destination)\n",
        encoding="utf-8",
    )

    _evidence, unbounded = GATE._dynamic_import_destinations(tmp_path)

    assert unbounded == ["example:3"]


def test_dynamic_import_gate_does_not_leak_sibling_function_bindings(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "example.py").write_text(
        "import importlib\n"
        "def unrelated():\n"
        "    destination = 'example.allowed'\n"
        "    return destination\n"
        "def load(destination: str):\n"
        "    return importlib.import_module(destination)\n",
        encoding="utf-8",
    )

    _evidence, unbounded = GATE._dynamic_import_destinations(tmp_path)

    assert unbounded == ["example:6"]


def test_dynamic_import_gate_preserves_function_local_static_bindings(tmp_path: Path) -> None:
    source = tmp_path / "src"
    source.mkdir()
    (source / "example.py").write_text(
        "import importlib\n"
        "def load():\n"
        "    destination = 'example.allowed'\n"
        "    return importlib.import_module(destination)\n",
        encoding="utf-8",
    )

    evidence, unbounded = GATE._dynamic_import_destinations(tmp_path)

    assert unbounded == []
    assert evidence[0].destination_values == ("example.allowed",)


def test_dynamic_import_graph_records_alias_and_static_expression(tmp_path: Path) -> None:
    package = tmp_path / "src" / "codex_plugin_scanner" / "guard"
    package.mkdir(parents=True)
    (package / "native_runtime_resident.py").write_text("", encoding="utf-8")
    (package / "loader.py").write_text(
        "from importlib import import_module as load\n"
        "prefix = 'codex_plugin_scanner.guard.'\n"
        "destination = prefix + 'native_runtime_resident'\n"
        "load(destination)\n",
        encoding="utf-8",
    )

    importers = GATE._production_importers(tmp_path, "codex_plugin_scanner.guard.native_runtime_resident")

    assert any(item.startswith("codex_plugin_scanner.guard.loader:") for item in importers)


def test_cleanup_contract_rejects_empty_excluded_candidate_list() -> None:
    contract = GATE._read_json(ROOT / GATE.CONTRACT)
    contract["package_excluded_candidates"] = []

    with pytest.raises(RuntimeError, match="non-empty list"):
        GATE._run_inputs(ROOT, contract)


def test_retained_python_oracle_is_loaded_only_by_explicit_test_surface(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOL_GUARD_NATIVE", "off")
    monkeypatch.setenv("HOL_GUARD_TEST_MODE", "1")
    monkeypatch.setenv("HOL_GUARD_PYTHON_ORACLE", "1")

    from codex_plugin_scanner.guard.cli.commands_hook_compat_loader import load_hook_compatibility_surface

    surface = load_hook_compatibility_surface()
    assert surface is not None
    assert callable(surface["_run_hook_generic_payload"])
    assert callable(surface["hydrate_hook_payload_reference"])


def test_excluded_dead_module_cannot_enter_a_package_artifact(tmp_path: Path) -> None:
    wheel = tmp_path / "fixture.whl"
    with ZipFile(wheel, "w") as archive:
        archive.writestr("codex_plugin_scanner/guard/native_runtime_resident.py", b"retained source")
    with pytest.raises(RuntimeError, match="package artifact contains excluded dead module"):
        GATE.run(ROOT, wheel)

    sdist = tmp_path / "fixture.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        source = tmp_path / "native_runtime_resident.py"
        source.write_bytes(b"retained source")
        archive.add(source, arcname="hol_guard-3.0.1/src/codex_plugin_scanner/guard/native_runtime_resident.py")
    with pytest.raises(RuntimeError, match="package artifact contains excluded dead module"):
        GATE.run(ROOT, sdist)


def test_cleanup_candidate_requires_dead_duplicate_class() -> None:
    candidate = "src/codex_plugin_scanner/guard/native_runtime_resident.py"

    with pytest.raises(RuntimeError, match="not classified as dead_duplicate"):
        GATE._candidate_evidence(
            ROOT,
            candidate,
            {candidate: "hook_control_and_transport"},
            {"hook_control_and_transport": "required_control_plane"},
            [candidate],
        )


def test_parity_fixture_stays_language_neutral() -> None:
    fixture = GATE._validate_fixture(ROOT, "tests/fixtures/native-hook-parity/cases.v1.json")

    assert fixture["case_count"] == 6
