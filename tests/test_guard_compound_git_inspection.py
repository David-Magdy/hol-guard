from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _hook_runtime_artifact
from codex_plugin_scanner.guard.models import GuardArtifact


def _artifact(command: str, *, home: Path) -> GuardArtifact | None:
    return _hook_runtime_artifact(
        harness="pi",
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        },
        action_envelope=None,
        home_dir=home,
        guard_home=home / ".guard",
        workspace=None,
    )


def _init_repository(path: Path) -> None:
    _ = subprocess.run(
        ["git", "init", "--quiet", str(path)],
        check=True,
        capture_output=True,
        text=True,
    )


def test_compound_git_refresh_and_inspection_is_evaluated_as_one_unit(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    repository = workspace / "repository"
    repository.mkdir(parents=True)
    _init_repository(repository)
    _ = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "remote",
            "add",
            "origin",
            "https://github.com/example/project.git",
        ],
        check=True,
    )

    command = " ".join(
        (
            f"cd {workspace} && git -C repository fetch origin main 2>&1 | tail -5",
            '&& echo "---ORIGIN---" && git -C repository log origin/main -1 --oneline',
            '&& echo "---STATUS---" && git -C repository status --short | head -20',
        )
    )
    artifact = _artifact(command, home=home)

    assert artifact is None


@pytest.mark.parametrize(
    "log_args",
    ("-5 --oneline", "--oneline -20 origin/main", "origin/main -1 --oneline"),
)
def test_compound_git_inspection_accepts_bounded_log_forms(tmp_path: Path, log_args: str) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)

    assert _artifact(f"cd {workspace} && git log {log_args}", home=home) is None


@pytest.mark.parametrize(
    "inspection",
    (
        "git show origin/main:public/example.txt | head -20",
        "git diff origin/main -- public/example.txt | head -20",
    ),
)
def test_compound_git_inspection_accepts_safe_revision_paths(tmp_path: Path, inspection: str) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    (workspace / "public").mkdir(parents=True)

    assert _artifact(f"cd {workspace} && {inspection}", home=home) is None


@pytest.mark.parametrize("harness", ("pi", "codex", "claude-code", "gemini", "cursor"))
def test_cross_workspace_git_show_accepts_bounded_revision_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    harness: str,
) -> None:
    for key in ("GIT_EXTERNAL_DIFF", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"):
        monkeypatch.delenv(key, raising=False)
    home = tmp_path / "home"
    active_workspace = home / "projects" / "active"
    inspected_workspace = home / "projects" / "inspected"
    active_workspace.mkdir(parents=True)
    _init_repository(inspected_workspace)
    (inspected_workspace / "workers" / "services").mkdir(parents=True)

    artifact = _hook_runtime_artifact(
        harness=harness,
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": (f"cd {inspected_workspace} && git show b56514561 -- workers/services/ 2>&1 | head -60")
            },
        },
        action_envelope=None,
        home_dir=home,
        guard_home=home / ".guard",
        workspace=active_workspace,
    )

    assert artifact is None


@pytest.mark.parametrize(
    "inspection",
    (
        "git show b56514561 -- ../outside | head -60",
        "git show b56514561 -- .env | head -60",
        "git show $REVISION -- workers/services/ | head -60",
        "git show b56514561 --ext-diff -- workers/services/ | head -60",
        "git show b56514561 --textconv -- workers/services/ | head -60",
        "git show b56514561 -- workers/services/ | sh",
        "git show b56514561 -- workers/services/ > report.txt",
    ),
)
def test_cross_workspace_git_show_keeps_unsafe_variants_guarded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    inspection: str,
) -> None:
    for key in ("GIT_EXTERNAL_DIFF", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"):
        monkeypatch.delenv(key, raising=False)
    home = tmp_path / "home"
    active_workspace = home / "projects" / "active"
    inspected_workspace = home / "projects" / "inspected"
    active_workspace.mkdir(parents=True)
    _init_repository(inspected_workspace)
    (inspected_workspace / "workers" / "services").mkdir(parents=True)

    artifact = _hook_runtime_artifact(
        harness="pi",
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": f"cd {inspected_workspace} && {inspection}"},
        },
        action_envelope=None,
        home_dir=home,
        guard_home=home / ".guard",
        workspace=active_workspace,
    )

    assert artifact is not None


@pytest.mark.parametrize(
    "inspection",
    (
        "git show HEAD",
        "git show b56514561 -- workers/services/ 2>&1 | head -60",
    ),
)
def test_cross_workspace_git_show_rejects_configured_textconv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    inspection: str,
) -> None:
    for key in ("GIT_EXTERNAL_DIFF", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"):
        monkeypatch.delenv(key, raising=False)
    home = tmp_path / "home"
    active_workspace = home / "projects" / "active"
    inspected_workspace = home / "projects" / "inspected"
    active_workspace.mkdir(parents=True)
    _init_repository(inspected_workspace)
    _ = (inspected_workspace / ".git" / "config").write_text(
        '[diff "guard"]\n    textconv = helper\n',
        encoding="utf-8",
    )
    (inspected_workspace / "workers" / "services").mkdir(parents=True)

    artifact = _hook_runtime_artifact(
        harness="pi",
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": f"cd {inspected_workspace} && {inspection}"},
        },
        action_envelope=None,
        home_dir=home,
        guard_home=home / ".guard",
        workspace=active_workspace,
    )

    assert artifact is not None


def test_cross_workspace_git_show_rejects_textconv_in_git_c_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in ("GIT_EXTERNAL_DIFF", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS"):
        monkeypatch.delenv(key, raising=False)
    home = tmp_path / "home"
    active_workspace = home / "projects" / "active"
    repositories = home / "projects" / "repositories"
    inspected_workspace = repositories / "inspected"
    active_workspace.mkdir(parents=True)
    _init_repository(inspected_workspace)
    _ = (inspected_workspace / ".git" / "config").write_text(
        '[diff "guard"]\n    textconv = helper\n',
        encoding="utf-8",
    )
    (inspected_workspace / "workers" / "services").mkdir(parents=True)

    artifact = _hook_runtime_artifact(
        harness="pi",
        payload={
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": (
                    f"cd {repositories} && git -C inspected show b56514561 -- workers/services/ 2>&1 | head -60"
                )
            },
        },
        action_envelope=None,
        home_dir=home,
        guard_home=home / ".guard",
        workspace=active_workspace,
    )

    assert artifact is not None


@pytest.mark.parametrize(
    "inspection",
    (
        "git status --short",
        "git log -1 --oneline",
        "git show HEAD",
    ),
)
def test_compound_git_inspection_rejects_path_shadowed_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    inspection: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    _init_repository(workspace)
    shadow_bin = workspace / "bin"
    shadow_bin.mkdir()
    shadow_git = shadow_bin / "git"
    shadow_git.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    shadow_git.chmod(0o755)
    monkeypatch.setenv("PATH", f"{shadow_bin}:{os.environ.get('PATH', '')}")

    assert _artifact(f"cd {workspace} && {inspection}", home=home) is not None


@pytest.mark.parametrize(
    "key",
    (
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
    ),
)
def test_compound_git_inspection_rejects_config_routing_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    key: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    _init_repository(workspace)
    monkeypatch.setenv(key, "1")

    assert _artifact(f"cd {workspace} && git show HEAD", home=home) is not None


def test_compound_git_c_status_checks_target_repository_fsmonitor(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    repository = workspace / "repository"
    _init_repository(repository)
    subprocess.run(
        ["git", "-C", str(repository), "config", "core.fsmonitor", "./payload"],
        check=True,
        capture_output=True,
    )

    assert _artifact(f"cd {workspace} && git -C repository status --short", home=home) is not None


@pytest.mark.parametrize(
    "inspection",
    (
        "git show origin/main:../settings.txt",
        "git show origin/main:/settings.txt",
        "git diff origin/main -- ../settings.txt",
        "git diff origin/main -- /settings.txt",
    ),
)
def test_compound_git_inspection_rejects_escaping_revision_paths(tmp_path: Path, inspection: str) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    workspace.mkdir(parents=True)

    assert _artifact(f"cd {workspace} && {inspection}", home=home) is not None


@pytest.mark.parametrize("repository", ("projects/repository", "./projects/repository", "."))
def test_compound_git_inspection_accepts_bounded_relative_repository_paths(
    tmp_path: Path,
    repository: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "workspace"
    (workspace / "projects" / "repository").mkdir(parents=True)

    assert _artifact(f"cd {workspace} && git -C {repository} status --short | head -20", home=home) is None


@pytest.mark.parametrize(
    "suffix",
    (
        "git -C repository push origin main",
        "git -C repository reset --hard origin/main",
        "git -C repository fetch origin main:refs/heads/main",
        "git -C ../outside fetch origin main",
        "git -C projects/../../outside status --short",
        "git -C /outside status --short",
        "git -C ~/outside status --short",
        "git -C projects/$TARGET status --short",
        "git -C repository status --short | sh",
        "git -C repository status --short > report.txt",
        "git log -101 --oneline",
        "git log --all --oneline -5",
    ),
)
def test_compound_git_recovery_keeps_ambiguous_or_mutating_commands_guarded(
    tmp_path: Path,
    suffix: str,
) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "repository").mkdir(parents=True)

    assert _artifact(f"cd {workspace} && {suffix}", home=home) is not None


def test_compound_git_recovery_rejects_dynamic_or_preceding_execution(tmp_path: Path) -> None:
    home = tmp_path / "home"
    workspace = home / "projects" / "workspace"
    (workspace / "repository").mkdir(parents=True)

    assert _artifact("cd $TARGET && git -C repository fetch origin main", home=home) is not None
    assert (
        _artifact(
            f"printf ready && cd {workspace} && git -C repository status --short",
            home=home,
        )
        is not None
    )
