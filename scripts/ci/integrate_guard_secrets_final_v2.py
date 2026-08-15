#!/usr/bin/env python3
"""Materialize the reviewed HOL Guard Secrets hardening sources on release/3.0."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def run(*args: str, capture: bool = False) -> str:
    completed = subprocess.run(
        args,
        cwd=ROOT,
        check=True,
        capture_output=capture,
        text=True,
    )
    return completed.stdout if capture else ""


def show(revision: str, path: str) -> str:
    return run("git", "show", f"{revision}:{path}", capture=True)


def apply_diff(base: str, head: str, paths: tuple[str, ...], destination: Path) -> None:
    with destination.open("w", encoding="utf-8") as output:
        subprocess.run(
            ["git", "diff", "--binary", "--full-index", base, head, "--", *paths],
            cwd=ROOT,
            check=True,
            stdout=output,
            text=True,
        )
    if destination.stat().st_size == 0:
        raise SystemExit(f"empty reviewed patch: {destination.name}")
    run("git", "apply", "--3way", "--index", str(destination))


def unindent_heredoc(lines: list[str]) -> str:
    first = next((line for line in lines if line.strip()), "")
    prefix = len(first) - len(first.lstrip(" "))
    return "\n".join(
        line[prefix:] if line.startswith(" " * prefix) else line for line in lines
    ).rstrip() + "\n"


def heredoc_body(body: str, marker: str) -> str:
    lines = body.splitlines()
    for index, line in enumerate(lines):
        if marker not in line or "<<'PY'" not in line:
            continue
        collected: list[str] = []
        for candidate in lines[index + 1 :]:
            if candidate.strip() == "PY":
                return unindent_heredoc(collected)
            collected.append(candidate)
    raise SystemExit(f"heredoc not found: {marker}")


def execute_python_block(revision: str, workflow: str, required: tuple[str, ...]) -> None:
    lines = show(revision, workflow).splitlines()
    for index, line in enumerate(lines):
        if line.strip() not in {"python - <<'PY'", "python3 - <<'PY'"}:
            continue
        collected: list[str] = []
        for candidate in lines[index + 1 :]:
            if candidate.strip() == "PY":
                script = unindent_heredoc(collected)
                if all(value in script for value in required):
                    exec(compile(script, f"{revision}:{workflow}", "exec"), {})
                    return
                break
            collected.append(candidate)
    raise SystemExit(f"reviewed patch block not found: {workflow}")


PRECOMMIT_SOURCE = r'''"""Non-destructive Git pre-commit integration for HOL Guard Secrets."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .git_subprocess import run_git

_MANAGED_MARKER = "# HOL_GUARD_SECRETS_PRE_COMMIT_V1"
_BACKUP_NAME = "pre-commit.hol-guard-user"


def _shell_path(path: Path) -> str:
    return path.resolve().as_posix()


def _guard_launch() -> tuple[Path, tuple[str, ...]]:
    command = shutil.which("hol-guard")
    if command:
        executable = Path(command).resolve()
        return executable, ("secrets", "scan", "--staged", "--fail-on-findings")
    executable = Path(sys.executable).resolve()
    return executable, (
        "-m",
        "codex_plugin_scanner.guard.secrets.cli",
        "scan",
        "--staged",
        "--fail-on-findings",
    )


def _managed_hook_source() -> str:
    executable, arguments = _guard_launch()
    executable_text = _shell_path(executable)
    command = " ".join((shlex.quote(executable_text), *(shlex.quote(value) for value in arguments)))
    return f"""#!/bin/sh
{_MANAGED_MARKER}
# Managed by `hol-guard secrets install-hook`. Do not place secrets in this file.
hook_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
legacy="$hook_dir/{_BACKUP_NAME}"
if [ -x "$legacy" ]; then
  "$legacy" "$@"
  status=$?
  if [ "$status" -ne 0 ]; then
    exit "$status"
  fi
fi
guard_executable={shlex.quote(executable_text)}
if [ ! -x "$guard_executable" ]; then
  echo "HOL Guard Secrets pinned Guard executable is unavailable. Reinstall HOL Guard with pipx, then run hol-guard secrets install-hook again." >&2
  exit 2
fi
exec {command}
"""


_MANAGED_HOOK = _managed_hook_source()


@dataclass(frozen=True, slots=True)
class SecretsHookResult:
    status: str
    hook: str
    chained_existing: bool

    def to_public_dict(self) -> dict[str, object]:
        return {
            "schema": "guard-secrets-hook.v1",
            "status": self.status,
            "hook": self.hook,
            "chained_existing": self.chained_existing,
        }


def _resolved_git_path(root: Path, value: bytes) -> Path:
    raw = os.fsdecode(value).strip()
    if not raw:
        raise ValueError("Git metadata directory could not be resolved")
    path = Path(raw)
    return (path if path.is_absolute() else root / path).resolve()


def _git_common_dir(root: Path) -> Path:
    resolved = root.expanduser().resolve()
    if not resolved.exists() or not resolved.is_dir():
        raise ValueError("hook target must be an existing Git worktree directory")
    try:
        bare = run_git(resolved, ["rev-parse", "--is-bare-repository"])
        inside = run_git(resolved, ["rev-parse", "--is-inside-work-tree"])
        custom_hooks = run_git(resolved, ["config", "--get", "core.hooksPath"])
        git_dir = run_git(resolved, ["rev-parse", "--git-dir"])
        common = run_git(resolved, ["rev-parse", "--git-common-dir"])
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("hook target is not a usable Git worktree") from error
    if bare.returncode == 0 and bare.stdout.strip() == b"true":
        raise ValueError("bare repository has no pre-commit worktree")
    if inside.returncode != 0 or inside.stdout.strip() != b"true":
        raise ValueError("hook target is not a usable Git worktree")
    if custom_hooks.returncode == 0 and custom_hooks.stdout.strip():
        raise ValueError(
            "custom core.hooksPath is configured; HOL Guard will not modify a shared or custom hook directory automatically"
        )
    if git_dir.returncode != 0 or common.returncode != 0:
        raise ValueError("Git hook directory could not be resolved")
    git_dir_path = _resolved_git_path(resolved, git_dir.stdout)
    common_dir = _resolved_git_path(resolved, common.stdout)
    if git_dir_path != common_dir:
        raise ValueError("linked worktree uses a shared Git hooks directory; compose the staged scan manually")
    if not common_dir.exists() or not common_dir.is_dir():
        raise ValueError("Git common directory could not be verified")
    return common_dir


def _hook_paths(root: Path) -> tuple[Path, Path, str]:
    hooks_dir = _git_common_dir(root) / "hooks"
    if hooks_dir.is_symlink():
        raise ValueError("refusing to modify a symlinked Git hooks directory")
    return hooks_dir / "pre-commit", hooks_dir / _BACKUP_NAME, "git-hooks/pre-commit"


def _is_managed_hook(path: Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    try:
        prefix = path.read_text(encoding="utf-8", errors="replace")[:512]
    except OSError:
        return False
    return _MANAGED_MARKER in prefix


def _write_managed_hook(hook: Path) -> None:
    temp = hook.with_name(f".{hook.name}.hol-guard-{os.getpid()}.tmp")
    try:
        temp.write_text(_MANAGED_HOOK, encoding="utf-8", newline="\n")
        temp.chmod(0o755)
        os.replace(temp, hook)
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def install_precommit_hook(root: Path) -> SecretsHookResult:
    """Install the managed hook while preserving any existing user hook."""

    hook, backup, display = _hook_paths(root)
    if _is_managed_hook(hook):
        try:
            current = hook.read_text(encoding="utf-8", errors="strict")
        except OSError as error:
            raise ValueError("could not inspect HOL Guard Secrets pre-commit hook") from error
        if current == _MANAGED_HOOK:
            return SecretsHookResult("already_installed", display, backup.exists())
        try:
            _write_managed_hook(hook)
        except OSError as error:
            raise ValueError("could not update HOL Guard Secrets pre-commit hook") from error
        return SecretsHookResult("updated", display, backup.exists())
    if hook.exists() and backup.exists():
        raise ValueError("refusing to replace pre-commit hook because the HOL Guard backup path already exists")

    hook.parent.mkdir(parents=True, exist_ok=True)
    moved_existing = False
    try:
        if hook.exists() or hook.is_symlink():
            os.replace(hook, backup)
            moved_existing = True
        _write_managed_hook(hook)
    except OSError as error:
        try:
            if moved_existing and backup.exists() and not hook.exists():
                os.replace(backup, hook)
        except OSError:
            pass
        raise ValueError("could not install HOL Guard Secrets pre-commit hook") from error
    return SecretsHookResult("installed", display, backup.exists())


def uninstall_precommit_hook(root: Path) -> SecretsHookResult:
    """Remove only the managed hook and restore a chained user hook exactly."""

    hook, backup, display = _hook_paths(root)
    if not hook.exists():
        if backup.exists():
            try:
                os.replace(backup, hook)
            except OSError as error:
                raise ValueError("could not restore the preserved pre-commit hook") from error
            return SecretsHookResult("restored", display, True)
        return SecretsHookResult("not_installed", display, False)
    if not _is_managed_hook(hook):
        if backup.exists():
            raise ValueError("refusing to overwrite a non-HOL-Guard pre-commit hook while a preserved backup exists")
        return SecretsHookResult("not_installed", display, False)
    if not backup.exists():
        try:
            hook.unlink()
        except OSError as error:
            raise ValueError("could not uninstall HOL Guard Secrets pre-commit hook") from error
        return SecretsHookResult("uninstalled", display, False)

    retired = hook.with_name(f".{hook.name}.hol-guard-retired-{os.getpid()}.tmp")
    try:
        os.replace(hook, retired)
        os.replace(backup, hook)
        retired.unlink(missing_ok=True)
    except OSError as error:
        try:
            if retired.exists() and not hook.exists():
                os.replace(retired, hook)
        except OSError:
            pass
        raise ValueError("could not restore the preserved pre-commit hook") from error
    return SecretsHookResult("restored", display, True)


__all__ = ["SecretsHookResult", "install_precommit_hook", "uninstall_precommit_hook"]
'''


DIAGNOSTIC_BLOCK = '''            inside = repository is not None and repository.returncode == 0 and repository.stdout.strip() == b"true"
            try:
                bare_result = run_secure_git(git, root, ["rev-parse", "--is-bare-repository"])
            except (OSError, subprocess.SubprocessError):
                bare_result = None
            bare = bare_result is not None and bare_result.returncode == 0 and bare_result.stdout.strip() == b"true"
            checks.append(
                SetupCheck(
                    code="git_repository",
                    status="pass" if inside else "warn",
                    summary=(
                        "The requested directory is a Git worktree."
                        if inside
                        else "The requested directory is not a Git worktree; working-tree scans still work, but staged and pre-commit scans do not."
                    ),
                    action=None if inside else "Run inside a Git worktree to use staged and pre-commit protection.",
                )
            )
            if bare:
                checks.append(
                    SetupCheck(
                        code="git_bare_repository",
                        status="warn",
                        summary="The requested repository is bare; bounded history scans work, but no working tree or managed hook exists.",
                        action="Use a non-bare worktree for current-tree, staged, and pre-commit protection.",
                    )
                )
            if inside:
                try:
                    hook_config = run_secure_git(git, root, ["config", "--get", "core.hooksPath"])
                    git_dir_result = run_secure_git(git, root, ["rev-parse", "--git-dir"])
                    common_dir_result = run_secure_git(git, root, ["rev-parse", "--git-common-dir"])
                except (OSError, subprocess.SubprocessError):
                    hook_config = None
                    git_dir_result = None
                    common_dir_result = None
                custom_hooks = hook_config is not None and hook_config.returncode == 0 and bool(hook_config.stdout.strip())
                checks.append(
                    SetupCheck(
                        code="standard_hooks_path",
                        status="warn" if custom_hooks else "pass",
                        summary=(
                            "A custom Git hooks path is configured; HOL Guard will not modify it automatically."
                            if custom_hooks
                            else "The repository uses the standard Git hooks directory."
                        ),
                        action=(
                            "Keep the custom hook manager authoritative and invoke `hol-guard secrets scan --staged --fail-on-findings` from it."
                            if custom_hooks
                            else None
                        ),
                    )
                )
                linked = False
                common_dir = None
                if git_dir_result is not None and common_dir_result is not None and git_dir_result.returncode == 0 and common_dir_result.returncode == 0:
                    raw_git_dir = os.fsdecode(git_dir_result.stdout).strip()
                    raw_common = os.fsdecode(common_dir_result.stdout).strip()
                    if raw_git_dir and raw_common:
                        git_dir_path = Path(raw_git_dir)
                        common_path = Path(raw_common)
                        git_dir_path = (git_dir_path if git_dir_path.is_absolute() else root / git_dir_path).resolve()
                        common_dir = (common_path if common_path.is_absolute() else root / common_path).resolve()
                        linked = git_dir_path != common_dir
                checks.append(
                    SetupCheck(
                        code="linked_worktree_shared_hooks",
                        status="warn" if linked else "pass",
                        summary=(
                            "This linked worktree shares hooks with another worktree; HOL Guard will not modify them automatically."
                            if linked
                            else "This worktree has an independently managed Git hook directory."
                        ),
                        action=(
                            "Invoke `hol-guard secrets scan --staged --fail-on-findings` from the existing shared hook manager."
                            if linked
                            else None
                        ),
                    )
                )
                metadata_writable = bool(common_dir is not None and os.access(common_dir, os.W_OK) and not linked and not custom_hooks)
                checks.append(
                    SetupCheck(
                        code="git_metadata_writable",
                        status="pass" if metadata_writable else "warn",
                        summary=(
                            "Git metadata is writable for managed hook installation."
                            if metadata_writable
                            else "Managed hook installation is unavailable for this repository layout or permission set."
                        ),
                        action=None if metadata_writable else "Use direct scans or compose the staged scan in the existing hook manager.",
                    )
                )
                shell_ready = _git_shell_available(git)
                checks.append(
                    SetupCheck(
                        code="hook_shell_available",
                        status="pass" if shell_ready else "warn",
                        summary=(
                            "A POSIX-compatible shell is available for the managed Git hook."
                            if shell_ready
                            else "The Git hook shell could not be verified."
                        ),
                        action=None if shell_ready else "Install Git for Windows with its shell, or invoke the staged scan from your existing hook manager.",
                    )
                )
'''


def main() -> None:
    run(
        "git",
        "fetch",
        "--no-tags",
        "origin",
        "fix/secrets-complete-hardening-final-v1",
        "fix/secrets-e2e-platform-hardening-v2",
        "fix/secrets-git-process-hardening-v2",
        "fix/secrets-git-object-edge-hardening",
        "fix/secrets-hook-identity-final-v2",
        "fix/secrets-coverage-edge-cases-v2",
    )
    apply_diff(
        "92d0767cbea98e9fbce14f8eaacc3d32131b9864",
        "d7255d314533c3d06fbf1a212141527724fcfadf",
        (
            "docs/guard/contracts",
            "scripts/ci/guard_secrets_release_claim_gate.py",
            "scripts/write_release_toolchain_sbom.py",
            "src/codex_plugin_scanner/guard/secrets/contracts_v2.py",
            "tests/test_guard_secret_contracts_v2.py",
            "tests/test_guard_secret_release_claim_gate.py",
            "tests/test_release_toolchain_sbom.py",
        ),
        Path("/tmp/contracts-v2.patch"),
    )
    apply_diff(
        "38ebf3fddbb038a30b30c8a82bbb377183c3912d",
        "1143f6e3eb355e6de1e434083ff2c974efd78708",
        (
            ".github/workflows/secrets-platform-e2e.yml",
            "docs/guard/secrets-platform-hardening.md",
            "scripts/ci/run_guard_secrets_platform_smoke_v2.py",
            "src/codex_plugin_scanner/guard/secrets/cli.py",
            "src/codex_plugin_scanner/guard/secrets/git_subprocess.py",
            "src/codex_plugin_scanner/guard/secrets/precommit.py",
            "src/codex_plugin_scanner/guard/secrets/secret_staged_scanner.py",
            "src/codex_plugin_scanner/guard/secrets/setup_diagnostics.py",
            "tests/test_guard_secret_doctor.py",
            "tests/test_guard_secret_git_subprocess_hardening.py",
            "tests/test_guard_secret_hook_configuration_hardening.py",
            "tests/test_guard_secret_input_coverage_hardening.py",
            "tests/test_guard_secret_platform_hardening.py",
        ),
        Path("/tmp/platform-v2.patch"),
    )
    copies = {
        "tests/test_guard_secret_git_process_security.py": ("5f5befcf2aa847d2813d40e8bf47f4ce4f5a95d2", "tests/test_guard_secret_git_process_security.py"),
        "tests/test_guard_secret_git_repository_edges.py": ("1de19656af287ced5a8cac17b2986053c125afca", "tests/test_guard_secret_git_repository_edges.py"),
        "scripts/ci/run_guard_secrets_pipx_smoke.py": ("1de19656af287ced5a8cac17b2986053c125afca", "scripts/ci/run_guard_secrets_pipx_smoke.py"),
        "tests/test_guard_secret_hook_identity_worktree.py": ("8efba21c24afc54677899d3e8b5619d1c252598f", "tests/test_guard_secret_hook_identity_worktree.py"),
        "tests/test_guard_secret_sparse_bare_repository.py": ("8efba21c24afc54677899d3e8b5619d1c252598f", "tests/test_guard_secret_sparse_bare_repository.py"),
        "src/codex_plugin_scanner/guard/secrets/coverage.py": ("3e2328a76c506c78df2f571af15d248aa3589ea0", "src/codex_plugin_scanner/guard/secrets/coverage.py"),
        "tests/test_guard_secret_coverage_edges.py": ("8960c9dd8205849f2efbe3e2f5cf752e941e61f9", "tests/test_guard_secret_coverage_edges.py"),
    }
    for destination, (revision, source) in copies.items():
        (ROOT / destination).write_text(show(revision, source), encoding="utf-8")

    git_safe_workflow = show(
        "5f5befcf2aa847d2813d40e8bf47f4ce4f5a95d2",
        ".github/workflows/secrets-git-process-bootstrap.yml",
    )
    (ROOT / "src/codex_plugin_scanner/guard/secrets/git_safe.py").write_text(
        heredoc_body(git_safe_workflow, "guard/secrets/git_safe.py"),
        encoding="utf-8",
    )
    execute_python_block(
        "1de19656af287ced5a8cac17b2986053c125afca",
        ".github/workflows/secrets-git-object-integration.yml",
        ("git_lfs_pointer_content_unavailable", "secret_repository_scanner.py"),
    )
    execute_python_block(
        "8efba21c24afc54677899d3e8b5619d1c252598f",
        ".github/workflows/secrets-hook-worktree-integration.yml",
        ("git_sparse_checkout_partial", "bare_repository_working_tree_unavailable"),
    )

    (ROOT / "src/codex_plugin_scanner/guard/secrets/precommit.py").write_text(
        PRECOMMIT_SOURCE,
        encoding="utf-8",
    )
    diagnostics = ROOT / "src/codex_plugin_scanner/guard/secrets/setup_diagnostics.py"
    diagnostic_text = diagnostics.read_text(encoding="utf-8")
    start = diagnostic_text.index("            inside = repository is not None")
    end = diagnostic_text.index("\n    writable = os.access(root, os.W_OK)", start)
    diagnostics.write_text(diagnostic_text[:start] + DIAGNOSTIC_BLOCK + diagnostic_text[end:], encoding="utf-8")

    platform_test = ROOT / "tests/test_guard_secret_platform_hardening.py"
    test_text = platform_test.read_text(encoding="utf-8")
    test_text = test_text.replace(
        '    assert "command -v hol-guard" in managed\n',
        '    assert "command -v hol-guard" not in managed\n    assert "pinned Guard executable is unavailable" in managed\n',
    )
    test_text = test_text.replace(
        '    assert "could not find the hol-guard executable" in result.stderr\n',
        '    assert "pinned Guard executable is unavailable" in result.stderr\n',
    )
    platform_test.write_text(test_text, encoding="utf-8")
    run("git", "add", "-A")


if __name__ == "__main__":
    main()
