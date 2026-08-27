"""Focused regressions for routine source and Git inspections."""

from __future__ import annotations

import subprocess
from pathlib import Path

from codex_plugin_scanner.guard.runtime.secret_file_requests import is_explicitly_benign_tool_action_request


def _repository(tmp_path: Path) -> tuple[Path, Path]:
    home_dir = tmp_path / "home"
    repository = home_dir / "projects" / "example"
    repository.mkdir(parents=True)
    (repository / "ui.tsx").write_text("export {};\n", encoding="utf-8")
    (repository / "health.py").write_text("pass\n", encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
    return home_dir, repository


def _is_benign(command: str, *, home_dir: Path, repository: Path) -> bool:
    return is_explicitly_benign_tool_action_request(
        "bash",
        {"command": command},
        cwd=repository,
        home_dir=home_dir,
    )


def _create_local_branch(repository: Path, branch: str) -> None:
    commit = subprocess.run(
        ["git", "-C", str(repository), "hash-object", "-t", "commit", "-w", "--stdin"],
        input=(
            "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n"
            "author Guard Test <guard@example.invalid> 0 +0000\n"
            "committer Guard Test <guard@example.invalid> 0 +0000\n\ninitial\n"
        ),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    subprocess.run(["git", "-C", str(repository), "update-ref", f"refs/heads/{branch}", commit], check=True)


def test_read_only_source_inspection_accepts_no_match_fallback_and_multiple_reads(tmp_path: Path) -> None:
    home_dir, repository = _repository(tmp_path)
    command = "sed -n '1,20p' ui.tsx 2>/dev/null || true; sed -n '1,20p' health.py; rg -n export ui.tsx | head -10"

    assert _is_benign(command, home_dir=home_dir, repository=repository)


def test_bounded_decorated_git_logs_are_explicitly_benign(tmp_path: Path) -> None:
    home_dir, repository = _repository(tmp_path)
    _create_local_branch(repository, "release/3.0")

    assert _is_benign(
        "git log --oneline --decorate -12 release/3.0; git log --oneline --decorate -8 main",
        home_dir=home_dir,
        repository=repository,
    )


def test_git_status_filter_and_excluded_diff_stat_are_explicitly_benign(tmp_path: Path) -> None:
    home_dir, repository = _repository(tmp_path)

    assert _is_benign(
        "git status --short | rg example || true; git diff --stat -- . ':!node_modules' | tail -30",
        home_dir=home_dir,
        repository=repository,
    )
