from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.secrets.doctor import (
    _platform_name,
    _safe_label,
    doctor_json,
    render_doctor_text,
    run_secrets_doctor,
)
from codex_plugin_scanner.guard.secrets.git_safe import run_git, safe_git_environment


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def _repository(tmp_path: Path, name: str = "repository with spaces") -> Path:
    root = tmp_path / name
    root.mkdir()
    assert _git(root, "init").returncode == 0
    assert _git(root, "config", "user.email", "doctor@example.test").returncode == 0
    assert _git(root, "config", "user.name", "Doctor Test").returncode == 0
    return root


def test_safe_git_environment_drops_redirection_and_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    synthetic = "".join(("sk", "-", "test", "_not", "_real"))
    monkeypatch.setenv("GIT_DIR", "/redirected")
    monkeypatch.setenv("GIT_INDEX_FILE", "/redirected-index")
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", "/redirected-objects")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", synthetic)
    monkeypatch.setenv("DATABASE_URL", f"postgres://user:{synthetic}@example.test/db")

    environment = safe_git_environment()

    assert "GIT_DIR" not in environment
    assert "GIT_INDEX_FILE" not in environment
    assert "GIT_OBJECT_DIRECTORY" not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert "DATABASE_URL" not in environment
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert environment["GCM_INTERACTIVE"] == "Never"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"


def test_safe_git_environment_uses_only_fixed_config_overrides() -> None:
    environment = safe_git_environment({"PATH": os.environ.get("PATH", ""), "GIT_CONFIG_COUNT": "999"})

    assert environment["GIT_CONFIG_COUNT"] == "4"
    keys = {environment[f"GIT_CONFIG_KEY_{index}"] for index in range(4)}
    assert keys == {"credential.helper", "core.askPass", "core.sshCommand", "protocol.file.allow"}


def test_run_git_ignores_ambient_git_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    expected = _repository(tmp_path, "expected")
    redirected = _repository(tmp_path, "redirected")
    monkeypatch.setenv("GIT_DIR", str(redirected / ".git"))

    completed = run_git(expected, ["rev-parse", "--show-toplevel"])

    assert completed.returncode == 0
    assert Path(completed.stdout.decode().strip()).resolve() == expected.resolve()


def test_run_git_is_noninteractive_when_askpass_is_hostile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    monkeypatch.setenv("GIT_ASKPASS", str(tmp_path / "hostile-askpass"))
    monkeypatch.setenv("SSH_ASKPASS", str(tmp_path / "hostile-ssh-askpass"))

    completed = run_git(root, ["status", "--porcelain=v1"])

    assert completed.returncode == 0


def test_run_git_returns_bounded_failure_for_missing_executable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.setenv("PATH", "")

    completed = run_git(root, ["status"])

    assert completed.returncode == 124
    assert len(completed.stderr) < 100


def test_doctor_fails_honestly_for_missing_explicit_target(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"

    report = run_secrets_doctor(missing)

    assert report.status == "fail"
    assert report.target_kind == "missing"
    assert report.repository_detected is False
    assert "current" not in json.dumps(report.to_public_dict()).lower()


def test_doctor_warns_for_existing_non_repository(tmp_path: Path) -> None:
    target = tmp_path / "plain directory"
    target.mkdir()

    report = run_secrets_doctor(target)

    assert report.repository_detected is False
    assert any(check.check_id == "repository" and check.status == "warn" for check in report.checks)


def test_doctor_passes_core_repository_checks_without_mutating_hooks(tmp_path: Path) -> None:
    root = _repository(tmp_path, "unicode-δ repository")
    hooks = root / ".git" / "hooks"
    before = set(hooks.iterdir()) if hooks.exists() else set()

    report = run_secrets_doctor(root)

    after = set(hooks.iterdir()) if hooks.exists() else set()
    assert report.repository_detected is True
    assert any(check.check_id == "repository" and check.status == "pass" for check in report.checks)
    assert before == after


def test_doctor_warns_without_overwriting_custom_hooks_path(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    assert _git(root, "config", "core.hooksPath", ".custom-hooks").returncode == 0

    report = run_secrets_doctor(root)

    check = next(check for check in report.checks if check.check_id == "hooks_path")
    assert check.status == "warn"
    assert "will not overwrite" in check.summary
    assert not (root / ".custom-hooks").exists()


def test_doctor_marks_shallow_history_as_incomplete(tmp_path: Path) -> None:
    source = _repository(tmp_path, "source")
    (source / "README.md").write_text("hello\n", encoding="utf-8")
    assert _git(source, "add", "README.md").returncode == 0
    assert _git(source, "commit", "-m", "initial").returncode == 0
    clone = tmp_path / "shallow"
    completed = subprocess.run(
        ["git", "clone", "--depth", "1", f"file://{source}", str(clone)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0

    report = run_secrets_doctor(clone)

    check = next(check for check in report.checks if check.check_id == "history_depth")
    assert check.status == "warn"
    assert "shallow" in check.summary.lower()


def test_doctor_marks_partial_clone_promisor_as_incomplete(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    assert _git(root, "config", "remote.origin.promisor", "true").returncode == 0

    report = run_secrets_doctor(root)

    check = next(check for check in report.checks if check.check_id == "partial_clone")
    assert check.status == "warn"


def test_doctor_json_excludes_paths_environment_and_credentials(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _repository(tmp_path, "private customer repository")
    synthetic = "".join(("gh", "p_", "not", "a", "real", "credential"))
    monkeypatch.setenv("PRIVATE_TOKEN", synthetic)

    payload = doctor_json(run_secrets_doctor(root))

    assert str(root) not in payload
    assert "PRIVATE_TOKEN" not in payload
    assert synthetic not in payload
    parsed = json.loads(payload)
    assert parsed["privacy"]["absolute_paths_included"] is False
    assert parsed["privacy"]["credentials_included"] is False


def test_doctor_text_contains_actionable_checks_without_absolute_paths(tmp_path: Path) -> None:
    root = _repository(tmp_path)

    rendered = render_doctor_text(run_secrets_doctor(root))

    assert "HOL Guard Secrets doctor" in rendered
    assert "No credentials" in rendered
    assert str(root) not in rendered


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("git version 2.50.0\x1b[31m", "git version 2.50.0 [31m"),
        ("  windows\r\nserver  ", "windows server"),
        ("", "unknown"),
    ],
)
def test_safe_label_strips_terminal_control_characters(raw: str, expected: str) -> None:
    assert _safe_label(raw) == expected


def test_platform_name_prefers_wsl_boundary() -> None:
    assert _platform_name({"WSL_DISTRO_NAME": "Ubuntu"}) == "wsl"


def test_doctor_is_deterministic_for_the_same_repository(tmp_path: Path) -> None:
    root = _repository(tmp_path)

    first = run_secrets_doctor(root).to_public_dict()
    second = run_secrets_doctor(root).to_public_dict()

    assert first == second
