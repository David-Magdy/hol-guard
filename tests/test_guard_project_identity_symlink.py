from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.project_identity import resolve_portable_project_identity


def test_gitdir_directory_symlink_cannot_claim_external_repository_identity(tmp_path: Path) -> None:
    remote = "https://github.com/example/trusted-repository.git"
    external_git = tmp_path / "external-git"
    (external_git / "logs").mkdir(parents=True)
    (external_git / "config").write_text(
        f'[remote "origin"]\n\turl = {remote}\n',
        encoding="utf-8",
    )
    (external_git / "logs" / "HEAD").write_text(
        f'{"0" * 40} {"1" * 40} Guard Test <guard@example.invalid> 0 +0000\tclone: from {remote}\n',
        encoding="utf-8",
    )

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".git").symlink_to(external_git, target_is_directory=True)

    assert resolve_portable_project_identity(workspace) is None
