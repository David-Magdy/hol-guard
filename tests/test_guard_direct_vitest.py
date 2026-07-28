"""Regression coverage for verified direct local Vitest execution."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact
from codex_plugin_scanner.guard.runtime.secret_file_requests import (
    extract_sensitive_tool_action_request,
    is_explicitly_benign_tool_action_request,
)


@pytest.fixture(autouse=True)
def _exclude_workspace_virtualenv_from_path(  # pyright: ignore[reportUnusedFunction]
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workspace = Path().resolve()
    entries: list[str] = []
    for raw_entry in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(raw_entry or ".").expanduser()
        if not candidate.is_absolute():
            candidate = workspace / candidate
        try:
            _ = candidate.resolve().relative_to(workspace)
        except (OSError, RuntimeError):
            continue
        except ValueError:
            entries.append(raw_entry)
    monkeypatch.setenv("PATH", os.pathsep.join(entries))


def _write_package(root: Path, *, include_lock: bool = True, declares_vitest: bool = True) -> None:
    root.mkdir(parents=True, exist_ok=True)
    dependencies = {"vitest": "^4.1.8"} if declares_vitest else {}
    _ = (root / "package.json").write_text(
        json.dumps({"name": "fixture", "devDependencies": dependencies}),
        encoding="utf-8",
    )
    if include_lock:
        _ = (root / "bun.lock").write_text(
            json.dumps({"packages": {"vitest": ["vitest@4.1.8"]}}),
            encoding="utf-8",
        )


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    home = tmp_path / "home"
    caller = home / "caller"
    workspace = tmp_path / "subject"
    runner_project = home / "runner-project"
    _write_package(workspace)
    _write_package(runner_project)
    caller.mkdir(parents=True)
    test_file = workspace / "tests" / "unit.test.ts"
    test_file.parent.mkdir()
    _ = test_file.write_text("export {};\n", encoding="utf-8")
    package_dir = runner_project / "node_modules" / "vitest"
    package_dir.mkdir(parents=True)
    _ = (package_dir / "package.json").write_text(
        json.dumps({"name": "vitest", "version": "4.1.8"}),
        encoding="utf-8",
    )
    runner = package_dir / "vitest.mjs"
    _ = runner.write_text("#!/usr/bin/env node\n", encoding="utf-8")
    runner.chmod(0o755)
    return home, caller, workspace, runner


def _command(workspace: Path, runner: Path, *, suffix: str = "--no-coverage 2>&1 | tail -40") -> str:
    return f"cd {workspace} && {runner} run tests/unit.test.ts {suffix}"


def test_verified_direct_vitest_run_is_explicitly_benign(tmp_path: Path) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    command = _command(workspace, runner)

    assert (
        extract_sensitive_tool_action_request(
            "bash",
            {"command": command},
            cwd=caller,
            home_dir=home,
        )
        is None
    )
    assert is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )
    assert (
        _hook_runtime_artifact(
            harness="pi",
            payload={
                "hook_event_name": "PreToolUse",
                "tool_name": "bash",
                "tool_input": {"command": command},
            },
            action_envelope=None,
            home_dir=home,
            guard_home=home / ".guard",
            workspace=caller,
        )
        is None
    )


@pytest.mark.parametrize(
    "suffix",
    (
        "--config attacker.ts --no-coverage 2>&1 | tail -40",
        "--no-coverage > result.txt",
        "--no-coverage",
        "--no-coverage | tail -40",
        "--no-coverage 2>&1 | tee result.txt",
        "--no-coverage 2>&1 | tail -1001",
        "--no-coverage $(touch marker)",
    ),
)
def test_direct_vitest_rejects_unsafe_options_and_shell_behavior(tmp_path: Path, suffix: str) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _command(workspace, runner, suffix=suffix)},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize("missing", ("workspace-package", "workspace-lock", "runner-package", "runner-lock"))
def test_direct_vitest_requires_manifest_and_lock_evidence(tmp_path: Path, missing: str) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    runner_project = runner.parents[2]
    target = {
        "workspace-package": workspace / "package.json",
        "workspace-lock": workspace / "bun.lock",
        "runner-package": runner_project / "package.json",
        "runner-lock": runner_project / "bun.lock",
    }[missing]
    target.unlink()

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _command(workspace, runner)},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize("evidence", ("workspace-lock", "runner-lock"))
@pytest.mark.parametrize(
    "lock_payload",
    (
        {},
        {"packages": {"vitest": ["vitest@5.0.0"]}},
    ),
)
def test_direct_vitest_requires_bound_lock_version(
    tmp_path: Path,
    evidence: str,
    lock_payload: dict[str, object],
) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    runner_project = runner.parents[2]
    lockfile = workspace / "bun.lock" if evidence == "workspace-lock" else runner_project / "bun.lock"
    _ = lockfile.write_text(json.dumps(lock_payload), encoding="utf-8")

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _command(workspace, runner)},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize(
    "evidence",
    ("workspace-package", "workspace-lock", "runner-package", "runner-lock", "installed-package"),
)
def test_direct_vitest_rejects_symlinked_evidence(tmp_path: Path, evidence: str) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    runner_project = runner.parents[2]
    target = {
        "workspace-package": workspace / "package.json",
        "workspace-lock": workspace / "bun.lock",
        "runner-package": runner_project / "package.json",
        "runner-lock": runner_project / "bun.lock",
        "installed-package": runner.parent / "package.json",
    }[evidence]
    real = target.with_name(f"{target.name}.real")
    _ = target.rename(real)
    _ = target.symlink_to(real)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _command(workspace, runner)},
        cwd=caller,
        home_dir=home,
    )


def test_direct_vitest_rejects_retargeted_runner_package(tmp_path: Path) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    _ = (runner.parent / "package.json").write_text(
        json.dumps({"name": "lookalike", "version": "4.1.8"}),
        encoding="utf-8",
    )

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _command(workspace, runner)},
        cwd=caller,
        home_dir=home,
    )


def test_direct_vitest_rejects_symlinked_runner(tmp_path: Path) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    actual = runner.with_name("actual.mjs")
    _ = runner.rename(actual)
    _ = runner.symlink_to(actual)

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _command(workspace, runner)},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize("target", ("tests/missing.test.ts", "../outside.test.ts", "tests/helper.ts"))
def test_direct_vitest_rejects_missing_escaping_and_non_test_targets(tmp_path: Path, target: str) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    outside = workspace.parent / "outside.test.ts"
    _ = outside.write_text("export {};\n", encoding="utf-8")
    _ = (workspace / "tests" / "helper.ts").write_text("export {};\n", encoding="utf-8")
    command = f"cd {workspace} && {runner} run {target} --no-coverage 2>&1 | head -20"

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=caller,
        home_dir=home,
    )


def test_direct_vitest_rejects_arbitrary_javascript_runner(tmp_path: Path) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    arbitrary = runner.parents[2] / "scripts" / "vitest.mjs"
    arbitrary.parent.mkdir()
    _ = arbitrary.write_text("#!/usr/bin/env node\n", encoding="utf-8")

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _command(workspace, arbitrary)},
        cwd=caller,
        home_dir=home,
    )


@pytest.mark.parametrize("shadowed_command", ("node", "head", "tail"))
def test_direct_vitest_rejects_shadowed_runtime_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    shadowed_command: str,
) -> None:
    home, caller, workspace, runner = _fixture(tmp_path)
    shadow_bin = workspace / "bin"
    shadow_bin.mkdir()
    shadow = shadow_bin / shadowed_command
    _ = shadow.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    shadow.chmod(0o755)
    monkeypatch.setenv("PATH", f"{shadow_bin}{os.pathsep}{os.environ.get('PATH', '')}")
    suffix = "--no-coverage 2>&1 | head -40" if shadowed_command == "head" else "--no-coverage 2>&1 | tail -40"

    assert not is_explicitly_benign_tool_action_request(
        "bash",
        {"command": _command(workspace, runner, suffix=suffix)},
        cwd=caller,
        home_dir=home,
    )
