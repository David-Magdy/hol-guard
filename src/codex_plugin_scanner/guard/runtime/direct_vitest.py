"""Bounded execution-context recovery for verified local JavaScript tools."""

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
    runner_path, args, require_no_coverage = _vitest_runner_invocation(
        runner_tokens,
        workspace=workspace,
        home_dir=home_dir,
    )
    if runner_path is None:
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
    no_coverage_count = args.count("--no-coverage")
    if not args or args[0] != "run" or no_coverage_count > 1 or (require_no_coverage and no_coverage_count != 1):
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


def direct_local_typescript_execution_context(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path,
) -> ShellExecutionContext | None:
    """Recover a locked local TypeScript no-emit validation pipeline."""

    initial_root = cwd or home_dir
    initial_context = model_shell_execution_context(
        command_text,
        cwd=initial_root,
        workspace_root=initial_root,
        home_dir=home_dir,
    )
    workspace = _literal_leading_cd_target(initial_context, initial_root=initial_root, home_dir=home_dir)
    if workspace is None:
        return None
    context = model_shell_execution_context(
        command_text,
        cwd=workspace,
        workspace_root=workspace,
        home_dir=home_dir,
    )
    if not context.complete or len(context.segments) != 5:
        return None
    directory, compiler, grep, count, marker = context.segments
    if (
        directory.directory_operation != "cd"
        or directory.control_before
        or compiler.control_before != ("&&",)
        or compiler.effective_cwd != workspace
        or grep.control_before != ("|",)
        or count.control_before != ("|",)
        or marker.control_before != (";",)
    ):
        return None
    compiler_tokens = list(compiler.tokens)
    if compiler_tokens[-1:] != ["2>&1"]:
        return None
    _ = compiler_tokens.pop()
    if (
        len(compiler_tokens) != 5
        or not _safe_node_heap_assignment(compiler_tokens[0])
        or compiler_tokens[1:] != ["bun", "--smol", "./node_modules/typescript/bin/tsc", "--noEmit"]
        or not _trusted_path_command("bun", cwd=workspace, home_dir=home_dir)
        or _bun_runtime_config_exists(workspace=workspace, home_dir=home_dir)
        or not _workspace_typescript_is_bound(workspace)
    ):
        return None
    if (
        grep.tokens != ("grep", "error TS")
        or count.tokens != ("wc", "-l")
        or not _trusted_path_command("grep", cwd=workspace, home_dir=home_dir)
        or not _trusted_path_command("wc", cwd=workspace, home_dir=home_dir)
    ):
        return None
    if marker.tokens != ("echo", "MY_TSC_ERRORS_COUNT_DONE"):
        return None
    return context


def _safe_node_heap_assignment(token: str) -> bool:
    match = re.fullmatch(r"NODE_OPTIONS=--max-old-space-size=([1-9][0-9]{2,4})", token)
    return match is not None and 256 <= int(match.group(1)) <= 32768


def _bun_runtime_config_exists(*, workspace: Path, home_dir: Path) -> bool:
    """Reject implicit Bun config that can preload executable workspace code."""

    if os.environ.get("BUN_OPTIONS", "").strip():
        return True
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME", "").strip()
    candidates = [workspace / "bunfig.toml", home_dir / ".bunfig.toml"]
    if xdg_config_home:
        candidates.append(Path(xdg_config_home) / ".bunfig.toml")
    return any(candidate.exists() for candidate in candidates)


def _workspace_typescript_is_bound(workspace: Path) -> bool:
    package_dir = workspace / "node_modules" / "typescript"
    compiler = package_dir / "bin" / "tsc"
    package = _read_package_json(package_dir / "package.json")
    if package is None or package.get("name") != "typescript":
        return False
    installed_version = package.get("version")
    package_bin = package.get("bin")
    if (
        not isinstance(installed_version, str)
        or not isinstance(package_bin, Mapping)
        or cast(Mapping[object, object], package_bin).get("tsc") not in {"bin/tsc", "./bin/tsc"}
    ):
        return False
    try:
        resolved_compiler = compiler.resolve(strict=True)
        _ = resolved_compiler.relative_to(workspace.resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return False
    if compiler.is_symlink() or resolved_compiler != compiler.absolute() or not resolved_compiler.is_file():
        return False
    declared_version = _declared_dependency_version(workspace, "typescript")
    lockfiles = [workspace / name for name in _LOCKFILE_NAMES if (workspace / name).exists()]
    if declared_version is None or len(lockfiles) != 1:
        return False
    locked_version = _locked_package_version(lockfiles[0], "typescript")
    return locked_version == installed_version and _semver_spec_matches(declared_version, installed_version)


def _declared_dependency_version(workspace: Path, package_name: str) -> str | None:
    package = _read_package_json(workspace / "package.json")
    if package is None:
        return None
    for section in _DEPENDENCY_SECTIONS:
        dependencies = package.get(section)
        if not isinstance(dependencies, Mapping):
            continue
        declared = cast(Mapping[object, object], dependencies).get(package_name)
        if isinstance(declared, str):
            return declared
    return None


def _vitest_runner_invocation(
    runner_tokens: list[str],
    *,
    workspace: Path,
    home_dir: Path,
) -> tuple[Path | None, list[str], bool]:
    executable = runner_tokens[0]
    runner_path = Path(executable)
    if runner_path.is_absolute():
        return runner_path, runner_tokens[1:], True
    if executable != "npx" or not _trusted_path_command("npx", cwd=workspace, home_dir=home_dir):
        return None, [], False
    index = 1
    while index < len(runner_tokens) and runner_tokens[index] in {"--no", "--no-install"}:
        index += 1
    if index >= len(runner_tokens) or runner_tokens[index] != "vitest":
        return None, [], False
    bin_entry = workspace / "node_modules" / ".bin" / "vitest"
    package_runner = workspace / "node_modules" / "vitest" / "vitest.mjs"
    try:
        local_runner = package_runner.resolve(strict=True)
        resolved_bin_entry = bin_entry.resolve(strict=True)
    except (OSError, RuntimeError):
        return None, [], False
    if not bin_entry.is_symlink() or resolved_bin_entry != local_runner:
        return None, [], False
    args = runner_tokens[index + 1 :]
    if not args:
        return None, [], False
    return local_runner, args, False


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
    package_bin = package.get("bin") if package is not None else None
    if not isinstance(package_bin, Mapping) or cast(Mapping[object, object], package_bin).get("vitest") not in {
        "vitest.mjs",
        "./vitest.mjs",
    }:
        return None
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
    return _locked_package_version(path, "vitest")


def _locked_package_version(path: Path, package_name: str) -> str | None:
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
    entry = (
        typed_packages.get(package_name)
        if path.name == "bun.lock"
        else typed_packages.get(f"node_modules/{package_name}")
    )
    if path.name == "bun.lock":
        if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
            return None
        prefix = f"{package_name}@"
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
