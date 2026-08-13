from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.secrets.git_safe import (
    _run_bounded_command,
    run_git,
    safe_git_environment,
)


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
    return root


def test_repository_local_git_executable_cannot_hijack_scanner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    marker = tmp_path / "hijacked"
    executable = root / ("git.bat" if os.name == "nt" else "git")
    if os.name == "nt":
        executable.write_text(f"@echo off\r\necho hijacked>{marker}\r\nexit /b 0\r\n", encoding="utf-8")
    else:
        executable.write_text(f"#!/bin/sh\nprintf hijacked > '{marker}'\nexit 0\n", encoding="utf-8")
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", os.pathsep.join((str(root), os.environ.get("PATH", ""))))

    completed = run_git(root, ["rev-parse", "--show-toplevel"])

    assert completed.returncode == 0
    assert marker.exists() is False
    assert Path(completed.stdout.decode().strip()).resolve() == root.resolve()


def test_relative_path_entry_is_removed_from_git_environment() -> None:
    environment = safe_git_environment({"PATH": f".{os.pathsep}relative-bin"})

    assert "." not in environment.get("PATH", "").split(os.pathsep)
    assert "relative-bin" not in environment.get("PATH", "").split(os.pathsep)


def test_bounded_process_stops_stdout_output_bomb() -> None:
    completed = _run_bounded_command(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 1048576)"],
        environment=dict(os.environ),
        timeout_seconds=10.0,
        input_bytes=None,
        max_output_bytes=1024,
    )

    assert completed.returncode == 125
    assert completed.stderr == b"git_output_limit_exceeded"
    assert len(completed.stdout) <= 1024


def test_bounded_process_stops_stderr_output_bomb() -> None:
    completed = _run_bounded_command(
        [sys.executable, "-c", "import sys; sys.stderr.buffer.write(b'x' * 1048576)"],
        environment=dict(os.environ),
        timeout_seconds=10.0,
        input_bytes=None,
        max_output_bytes=1024,
    )

    assert completed.returncode == 125
    assert completed.stderr == b"git_output_limit_exceeded"


def test_bounded_process_enforces_timeout_without_returning_command_content() -> None:
    completed = _run_bounded_command(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        environment=dict(os.environ),
        timeout_seconds=0.1,
        input_bytes=None,
        max_output_bytes=1024,
    )

    assert completed.returncode == 124
    assert completed.stderr == b"git_timeout"


def test_run_git_rejects_oversized_input_before_starting_process(tmp_path: Path) -> None:
    root = _repository(tmp_path)

    completed = run_git(
        root,
        ["hash-object", "--stdin"],
        input_bytes=b"x" * 2048,
        max_output_bytes=1024,
    )

    assert completed.returncode == 126
    assert completed.stderr == b"git_input_limit_exceeded"


def test_missing_trusted_git_returns_stable_path_free_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    monkeypatch.setenv("PATH", str(root))

    completed = run_git(root, ["status"])

    assert completed.returncode == 124
    assert completed.stderr == b"git_executable_unavailable"
    assert str(root).encode() not in completed.stderr
