"""Bounded execution-context recovery for verified local Vitest runs."""

from __future__ import annotations

import json
import os
import re
import shutil
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from .git_execution_safety import git_binary_path_is_trusted
from .jsonc import loads_jsonc
from .shell_execution_context import ShellExecutionContext, model_shell_execution_context

_LOCKFILE_NAMES = ("bun.lock", "package-lock.json")
_DEPENDENCY_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
_MAX_METADATA_BYTES = 16 * 1024 * 1024


def direct_local_vitest_execution_context(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path,
) -> ShellExecutionContext | None:
    """Recover one literal workspace switch followed by a verified Vitest run."""

    initial_root = cwd or home_dir
    context = model_shell_execution_context(
        command_text,
        cwd=initial_root,
        workspace_root=initial_root,
        home_dir=home_dir,
    )
    workspace = _literal_leading_cd_target(context, initial_root=initial_root, home_dir=home_dir)
    if workspace is None:
        return None
    context = model_shell_execution_context(
        command_text,
        cwd=workspace,
        workspace_root=workspace,
        home_dir=home_dir,
    )
    if not context.complete or len(context.segments) != 3:
        return None
    directory, runner = context.segments[:2]
    if (
        directory.directory_operation != "cd"
        or directory.control_before
        or runner.control_before != ("&&",)
        or runner.effective_cwd != workspace
    ):
        return None
    runner_tokens = list(runner.tokens)
    if runner_tokens[-1:] != ["2>&1"]:
        return None
    _ = runner_tokens.pop()
    if len(runner_tokens) < 4 or any(_has_shell_dynamics(token) for token in runner_tokens):
        return None
    runner_path = Path(runner_tokens[0])
    if not runner_path.is_absolute():
        return None
    installed_version = _verified_vitest_runner(
        runner_path,
        cwd=workspace,
        home_dir=home_dir,
    )
    if installed_version is None or not _workspace_vitest_version_is_bound(
        workspace,
        installed_version=installed_version,
    ):
        return None
    args = runner_tokens[1:]
    if args[0] != "run" or args.count("--no-coverage") != 1:
        return None
    targets = [arg for arg in args[1:] if arg != "--no-coverage"]
    if not targets or any(arg.startswith("-") for arg in targets):
        return None
    if not all(_contained_test_target(target, workspace=workspace) for target in targets):
        return None
    if not _bounded_output_filter(
        context.segments[2].tokens,
        context.segments[2].control_before,
        cwd=workspace,
        home_dir=home_dir,
    ):
        return None
    return context


def _literal_leading_cd_target(
    context: ShellExecutionContext,
    *,
    initial_root: Path,
    home_dir: Path,
) -> Path | None:
    if not context.segments:
        return None
    segment = context.segments[0]
    if segment.control_before or segment.directory_operation != "cd" or len(segment.tokens) != 2:
        return None
    if segment.tokens[0].strip("\"'").casefold() != "cd":
        return None
    operand = segment.tokens[1]
    if _has_shell_dynamics(operand) or (operand.startswith("~") and not operand.startswith("~/")):
        return None
    candidate = home_dir / operand[2:] if operand.startswith("~/") else Path(operand)
    if not candidate.is_absolute():
        candidate = initial_root / candidate
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    return resolved if resolved.is_dir() else None


def _verified_vitest_runner(runner: Path, *, cwd: Path, home_dir: Path) -> str | None:
    package_dir = runner.parent
    node_modules = package_dir.parent
    project = node_modules.parent
    try:
        resolved_home = home_dir.resolve(strict=True)
        resolved_runner = runner.resolve(strict=True)
        _ = resolved_runner.relative_to(resolved_home)
    except (OSError, RuntimeError, ValueError):
        return None
    if (
        runner.name != "vitest.mjs"
        or package_dir.name != "vitest"
        or node_modules.name != "node_modules"
        or runner.is_symlink()
        or package_dir.is_symlink()
        or node_modules.is_symlink()
        or resolved_runner != runner.absolute()
        or not resolved_runner.is_file()
        or not os.access(resolved_runner, os.X_OK)
        or not _trusted_env_node_runtime(resolved_runner, cwd=cwd, home_dir=home_dir)
    ):
        return None
    package = _read_package_json(package_dir / "package.json")
    installed_version = package.get("version") if package is not None and package.get("name") == "vitest" else None
    if not isinstance(installed_version, str):
        return None
    return (
        installed_version if _workspace_vitest_version_is_bound(project, installed_version=installed_version) else None
    )


def _declared_vitest_version(workspace: Path) -> str | None:
    package = _read_package_json(workspace / "package.json")
    if package is None:
        return None
    for section in _DEPENDENCY_SECTIONS:
        dependencies = package.get(section)
        if not isinstance(dependencies, Mapping):
            continue
        typed_dependencies = cast(Mapping[object, object], dependencies)
        declared = typed_dependencies.get("vitest")
        if isinstance(declared, str):
            return declared
    return None


def _workspace_vitest_version_is_bound(workspace: Path, *, installed_version: str) -> bool:
    declared_version = _declared_vitest_version(workspace)
    lockfiles = [workspace / name for name in _LOCKFILE_NAMES if (workspace / name).exists()]
    if declared_version is None or len(lockfiles) != 1:
        return False
    locked_version = _locked_vitest_version(lockfiles[0])
    return locked_version == installed_version and _semver_spec_matches(declared_version, installed_version)


def _read_package_json(path: Path) -> dict[str, object] | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_METADATA_BYTES:
            return None
        payload = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    typed_payload = cast(dict[object, object], payload)
    if not all(isinstance(key, str) for key in typed_payload):
        return None
    return {key: value for key, value in typed_payload.items() if isinstance(key, str)}


def _locked_vitest_version(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_METADATA_BYTES:
            return None
        lock_text = path.read_text(encoding="utf-8")
        lock = cast(
            object,
            loads_jsonc(lock_text) if path.name == "bun.lock" else json.loads(lock_text),
        )
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(lock, dict):
        return None
    typed_lock = cast(dict[object, object], lock)
    packages = typed_lock.get("packages")
    if not isinstance(packages, dict):
        return None
    typed_packages = cast(dict[object, object], packages)
    entry = typed_packages.get("vitest") if path.name == "bun.lock" else typed_packages.get("node_modules/vitest")
    if path.name == "bun.lock":
        if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
            return None
        prefix = "vitest@"
        return entry[0][len(prefix) :] if entry[0].startswith(prefix) else None
    if not isinstance(entry, dict):
        return None
    typed_entry = cast(dict[object, object], entry)
    version = typed_entry.get("version")
    return version if isinstance(version, str) else None


def _semver_spec_matches(specifier: str, version: str) -> bool:
    match = re.fullmatch(r"([~^]?)(\d+)\.(\d+)\.(\d+)", specifier)
    installed = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
    if match is None or installed is None:
        return False
    operator, major, minor, patch = match.groups()
    requested = (int(major), int(minor), int(patch))
    actual = tuple(int(value) for value in installed.groups())
    if actual < requested:
        return False
    if operator == "^":
        if requested[0] > 0:
            return actual[0] == requested[0]
        if requested[1] > 0:
            return actual[:2] == requested[:2]
        return actual == requested
    if operator == "~":
        return actual[:2] == requested[:2]
    return actual == requested


def _contained_test_target(target: str, *, workspace: Path) -> bool:
    if _has_shell_dynamics(target) or target.startswith(("/", "~")):
        return False
    candidate = workspace / target
    try:
        absolute = candidate.absolute()
        resolved = candidate.resolve(strict=True)
        _ = resolved.relative_to(workspace)
    except (OSError, RuntimeError, ValueError):
        return False
    if absolute != resolved or not resolved.is_file():
        return False
    name = resolved.name.casefold()
    return ".test." in name or ".spec." in name


def _bounded_output_filter(
    tokens: tuple[str, ...],
    control_before: tuple[str, ...],
    *,
    cwd: Path,
    home_dir: Path,
) -> bool:
    if control_before != ("|",) or len(tokens) != 2 or tokens[0] not in {"head", "tail"}:
        return False
    if not _trusted_path_command(tokens[0], cwd=cwd, home_dir=home_dir):
        return False
    count = tokens[1]
    return count.startswith("-") and count[1:].isdigit() and 1 <= int(count[1:]) <= 1000


def _trusted_env_node_runtime(runner: Path, *, cwd: Path, home_dir: Path) -> bool:
    try:
        with runner.open("rb") as handle:
            shebang = handle.readline(64)
    except OSError:
        return False
    return shebang == b"#!/usr/bin/env node\n" and _trusted_path_command("node", cwd=cwd, home_dir=home_dir)


def _trusted_path_command(command: str, *, cwd: Path, home_dir: Path) -> bool:
    path_entries: list[str] = []
    for entry in os.environ.get("PATH", os.defpath).split(os.pathsep):
        candidate = Path(entry or ".").expanduser()
        if not candidate.is_absolute():
            candidate = cwd / candidate
        path_entries.append(str(candidate))
    path = shutil.which(command, path=os.pathsep.join(path_entries))
    if path is None:
        return False
    try:
        resolved = Path(path).resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    del home_dir
    return git_binary_path_is_trusted(resolved, cwd=cwd)


def _has_shell_dynamics(token: str) -> bool:
    return any(marker in token for marker in ("$", "`", "\x00", ">", "<"))
