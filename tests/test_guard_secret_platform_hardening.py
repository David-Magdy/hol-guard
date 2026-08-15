from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.secrets import cli
from codex_plugin_scanner.guard.secrets.git_subprocess import run_git, secure_git_environment
from codex_plugin_scanner.guard.secrets.precommit import install_precommit_hook, uninstall_precommit_hook
from codex_plugin_scanner.guard.secrets.secret_repository_scanner import scan_repository_secrets
from codex_plugin_scanner.guard.secrets.secret_staged_scanner import scan_staged_secrets
from codex_plugin_scanner.guard.secrets.setup_diagnostics import inspect_secrets_setup


def _provider_token() -> str:
    return "".join(("gh", "p_", "Ab3d", "Ef5h", "Ij7l", "Mn9p", "Qr2t", "Uv4x", "Yz6B", "cd8F"))


def _git(root: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "project with spaces Ω"
    root.mkdir()
    assert _git(root, "init").returncode == 0
    assert _git(root, "config", "user.email", "guard-test@example.invalid").returncode == 0
    assert _git(root, "config", "user.name", "Guard Test").returncode == 0
    return root


@pytest.mark.parametrize(
    "name",
    [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG_COUNT",
        "GIT_SSH_COMMAND",
        "GIT_ASKPASS",
    ],
)
def test_secure_git_environment_drops_ambient_git_overrides(name: str) -> None:
    environment = secure_git_environment({
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        name: "untrusted-value",
        "AWS_SECRET_ACCESS_KEY": "untrusted-value",
    })

    assert name not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GCM_INTERACTIVE"] == "Never"


def test_run_git_ignores_redirected_repository_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _repository(tmp_path)
    decoy = tmp_path / "decoy"
    decoy.mkdir()
    assert _git(decoy, "init").returncode == 0
    monkeypatch.setenv("GIT_DIR", str(decoy / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(decoy))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.pager")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "false")

    result = run_git(root, ["rev-parse", "--show-toplevel"])

    assert result.returncode == 0
    assert Path(os.fsdecode(result.stdout).strip()).resolve() == root.resolve()


def test_doctor_missing_target_never_falls_back_to_current_directory(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"

    report = inspect_secrets_setup(missing)
    payload = report.to_public_dict()

    assert report.ready is False
    assert any(check.code == "target_directory_missing" for check in report.checks)
    serialized = json.dumps(payload)
    assert str(tmp_path) not in serialized
    assert "does-not-exist" not in serialized


def test_doctor_payload_is_privacy_safe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _repository(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", _provider_token())
    monkeypatch.setenv("DATABASE_URL", "postgres://user:password@example.invalid/database")

    payload = inspect_secrets_setup(root).to_public_dict()
    serialized = json.dumps(payload)

    assert payload["schema"] == "guard-secrets-setup-doctor.v1"
    assert payload["privacy"] == {
        "environment_values_included": False,
        "absolute_paths_included": False,
        "repository_identity_included": False,
        "secret_values_included": False,
    }
    assert str(root) not in serialized
    assert _provider_token() not in serialized
    assert "postgres://" not in serialized


def test_cli_doctor_json_is_machine_readable(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = _repository(tmp_path)

    status = cli.main(["doctor", str(root), "--json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert status == 0
    assert payload["ready"] is True
    assert payload["schema"] == "guard-secrets-setup-doctor.v1"
    assert captured.err == ""


def test_working_tree_scan_supports_utf8_bom_crlf_and_unicode_paths(tmp_path: Path) -> None:
    root = tmp_path / "workspace Ω"
    root.mkdir()
    token = _provider_token()
    path = root / "credentials Ω.env"
    path.write_bytes(b"\xef\xbb\xbf" + f"GITHUB_TOKEN={token}\r\n".encode())

    result = scan_repository_secrets(root)

    assert result.truncated is False
    assert [finding.rule_id for finding in result.findings] == ["github-token"]
    assert result.findings[0].path == "credentials Ω.env"
    assert token not in json.dumps(result.to_public_dict())


def test_staged_scan_reads_index_not_unstaged_worktree(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    path = root / "config.env"
    token = _provider_token()
    path.write_text(f"GITHUB_TOKEN={token}\n", encoding="utf-8")
    assert _git(root, "add", "config.env").returncode == 0
    path.write_text("GITHUB_TOKEN=not-a-secret\n", encoding="utf-8")

    result = scan_staged_secrets(root)

    assert [finding.rule_id for finding in result.findings] == ["github-token"]
    assert token not in json.dumps(result.to_public_dict())


def test_oversized_working_file_makes_coverage_partial(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "large.env").write_text("A" * 512, encoding="utf-8")

    result = scan_repository_secrets(root, max_file_bytes=64)

    assert result.truncated is True
    assert "max_file_bytes" in result.truncation_reasons


def test_oversized_staged_blob_makes_coverage_partial(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "large.env").write_text("A" * 512, encoding="utf-8")
    assert _git(root, "add", "large.env").returncode == 0

    result = scan_staged_secrets(root, max_file_bytes=64)

    assert result.truncated is True
    assert "max_file_bytes" in result.truncation_reasons


def test_custom_hooks_path_refusal_has_no_side_effects(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    custom = tmp_path / "shared-hooks"
    assert _git(root, "config", "core.hooksPath", str(custom)).returncode == 0

    with pytest.raises(ValueError, match="custom core.hooksPath"):
        install_precommit_hook(root)

    assert not custom.exists()
    assert not (root / ".git" / "hooks" / "pre-commit").exists()
    assert not (root / ".git" / "hooks" / "pre-commit.hol-guard-user").exists()


def test_existing_hook_is_preserved_and_restored_byte_for_byte(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    hook = root / ".git" / "hooks" / "pre-commit"
    original = b"#!/bin/sh\r\nprintf 'existing hook\\n'\r\n"
    hook.write_bytes(original)
    hook.chmod(0o755)

    installed = install_precommit_hook(root)
    managed = hook.read_text(encoding="utf-8")
    assert installed.chained_existing is True
    assert "HOL_GUARD_SECRETS_PRE_COMMIT_V1" in managed
    assert "command -v hol-guard" in managed
    assert "scan --staged --fail-on-findings" in managed

    removed = uninstall_precommit_hook(root)

    assert removed.status == "restored"
    assert hook.read_bytes() == original
    assert not (hook.parent / "pre-commit.hol-guard-user").exists()


@pytest.mark.skipif(os.name == "nt", reason="symlink permissions vary on Windows runners")
def test_symlinked_hooks_directory_is_refused(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    actual = tmp_path / "outside-hooks"
    actual.mkdir()
    hooks = root / ".git" / "hooks"
    for child in hooks.iterdir():
        child.unlink()
    hooks.rmdir()
    hooks.symlink_to(actual, target_is_directory=True)

    with pytest.raises(ValueError, match="symlinked Git hooks"):
        install_precommit_hook(root)

    assert list(actual.iterdir()) == []


def test_managed_hook_fails_closed_when_cli_is_missing(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    install_precommit_hook(root)
    hook = root / ".git" / "hooks" / "pre-commit"
    environment = {"PATH": str(tmp_path / "empty-path")}

    result = subprocess.run(
        ["sh", str(hook)],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )

    assert result.returncode == 2
    assert "could not find the hol-guard executable" in result.stderr
    assert _provider_token() not in result.stderr


def test_scan_subprocess_never_uses_shell(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = _repository(tmp_path)
    observed: dict[str, object] = {}
    original = subprocess.run

    def recording_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        observed.update(kwargs)
        return original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr("codex_plugin_scanner.guard.secrets.git_subprocess.subprocess.run", recording_run)

    result = run_git(root, ["status", "--porcelain"])

    assert result.returncode == 0
    assert observed["shell"] is False
    assert observed["stdin"] is subprocess.DEVNULL
    environment = observed["env"]
    assert isinstance(environment, dict)
    assert not any(key.startswith("GIT_CONFIG_") for key in environment)
