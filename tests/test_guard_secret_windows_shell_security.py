from __future__ import annotations

import os
import stat
from pathlib import Path

from codex_plugin_scanner.guard.secrets.git_safe import trusted_windows_hook_shell


def _make_executable(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def test_repository_local_shell_cannot_satisfy_windows_hook_diagnostic(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    shell = root / "sh.exe"
    _make_executable(shell)

    available = trusted_windows_hook_shell(root, {"PATH": str(root)})

    assert available is False


def test_relative_program_files_value_cannot_redirect_shell_probe(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    relative = root / "Git" / "bin" / "sh.exe"
    _make_executable(relative)

    available = trusted_windows_hook_shell(
        root,
        {
            "PATH": "",
            "PROGRAMFILES": "",
            "PROGRAMFILES(X86)": "Git",
        },
    )

    assert available is False


def test_absolute_non_repository_shell_can_satisfy_probe(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    tools = tmp_path / "trusted-tools"
    shell = tools / "sh.exe"
    _make_executable(shell)

    available = trusted_windows_hook_shell(root, {"PATH": str(tools)})

    assert available is True


def test_world_writable_shell_directory_is_rejected_on_posix(tmp_path: Path) -> None:
    if os.name == "nt":
        return
    root = tmp_path / "repository"
    root.mkdir()
    tools = tmp_path / "untrusted-tools"
    shell = tools / "sh.exe"
    _make_executable(shell)
    tools.chmod(tools.stat().st_mode | stat.S_IWOTH)

    available = trusted_windows_hook_shell(root, {"PATH": str(tools)})

    assert available is False
