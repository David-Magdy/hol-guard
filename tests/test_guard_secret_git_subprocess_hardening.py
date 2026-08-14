from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.secrets.git_subprocess import run_git, secure_git_environment


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    assert _git(root, "init").returncode == 0
    assert _git(root, "config", "user.email", "guard-test@example.invalid").returncode == 0
    assert _git(root, "config", "user.name", "Guard Test").returncode == 0
    (root / "README.md").write_text("safe\n", encoding="utf-8")
    assert _git(root, "add", "README.md").returncode == 0
    assert _git(root, "commit", "-m", "baseline").returncode == 0
    return root


def test_secure_environment_disables_global_system_and_external_helpers() -> None:
    environment = secure_git_environment(
        {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", ""),
            "GIT_CONFIG_GLOBAL": "/tmp/untrusted-global-config",
            "GIT_EXTERNAL_DIFF": "/tmp/untrusted-diff",
            "GIT_ASKPASS": "/tmp/untrusted-askpass",
            "SSH_ASKPASS": "/tmp/untrusted-ssh-askpass",
        }
    )

    assert environment["GIT_CONFIG_GLOBAL"] == os.devnull
    assert environment["GIT_CONFIG_NOSYSTEM"] == "1"
    assert environment["GIT_ATTR_NOSYSTEM"] == "1"
    assert environment["GIT_EXTERNAL_DIFF"] == ""
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert "GIT_ASKPASS" not in environment
    assert "SSH_ASKPASS" not in environment


@pytest.mark.skipif(os.name == "nt", reason="shell-hook execution differs under Git for Windows")
def test_repository_local_fsmonitor_hook_is_not_executed(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    marker = tmp_path / "fsmonitor-executed"
    hook = tmp_path / "fsmonitor-hook.sh"
    hook.write_text(
        "#!/bin/sh\nprintf executed > \"$1\"\nexit 0\n",
        encoding="utf-8",
    )
    hook.chmod(0o755)
    wrapper = tmp_path / "fsmonitor-wrapper.sh"
    wrapper.write_text(
        f"#!/bin/sh\nexec '{hook}' '{marker}' \"$@\"\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    assert _git(root, "config", "core.fsmonitor", str(wrapper)).returncode == 0

    result = run_git(root, ["status", "--porcelain"])

    assert result.returncode == 0
    assert not marker.exists()


@pytest.mark.skipif(os.name == "nt", reason="shell diff drivers differ under Git for Windows")
def test_repository_local_external_diff_is_not_executed(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    marker = tmp_path / "diff-executed"
    helper = tmp_path / "diff-helper.sh"
    helper.write_text(
        f"#!/bin/sh\nprintf executed > '{marker}'\nexit 0\n",
        encoding="utf-8",
    )
    helper.chmod(0o755)
    assert _git(root, "config", "diff.external", str(helper)).returncode == 0
    (root / "README.md").write_text("changed\n", encoding="utf-8")

    result = run_git(root, ["diff", "--", "README.md"])

    assert result.returncode == 0
    assert not marker.exists()
