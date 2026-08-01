"""Interpreter launch candidate modeling."""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from ..approval_context import build_runtime_executable_identity
from ..env_wrapper import parse_env_wrapper
from .constants_patterns import _SHELL_ASSIGNMENT_PATTERN, _SHELL_COMMAND_WRAPPERS
from .interpreter_trust import _interpreter_token_has_path, _python_interpreter_trust
from .request_artifacts import _normalized_shell_command_name
from .shell_static_safety import _is_python_interpreter_command
from .shell_tokenization import (
    _leading_shell_redirection_tokens_consumed,
    _shell_command_token_without_attached_redirection,
    _wrapper_option_tokens_consumed,
)


@dataclass(frozen=True, slots=True)
class _ShellLaunchCandidate:
    tokens: tuple[str, ...]
    command_index: int
    effective_cwd: Path
    environment: dict[str, str]
    resolution_reason: str | None = None


def _normalized_interpreter_cwd(cwd: Path | None) -> Path:
    candidate = cwd or Path.cwd()
    try:
        return candidate.expanduser().resolve(strict=False)
    except (OSError, RuntimeError):
        return candidate.expanduser().absolute()


def _shell_launch_candidate(
    tokens: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    depth: int = 0,
    resolution_reason: str | None = None,
) -> _ShellLaunchCandidate | None:
    if depth > 8:
        return None
    working = list(tokens)
    effective_environment = dict(environment)
    effective_cwd = cwd
    index = 0
    while index < len(working):
        redirected = _leading_shell_redirection_tokens_consumed(working, index)
        if redirected:
            index += redirected
            continue
        token = _shell_command_token_without_attached_redirection(working[index]).strip()
        if _SHELL_ASSIGNMENT_PATTERN.match(token):
            name, _, value = token.partition("=")
            if name.endswith("+"):
                name = name[:-1]
                value = f"{effective_environment.get(name, '')}{value}"
            effective_environment[name] = value
            index += 1
            continue
        command_name = _normalized_shell_command_name(token)
        if command_name == "env":
            parsed = parse_env_wrapper(
                working[index + 1 :],
                inherited_environment=effective_environment,
                cwd=effective_cwd,
            )
            if not parsed.complete or not parsed.executable_argv:
                return None
            parsed_environment = parsed.environment_dict()
            if parsed_environment is None or parsed.effective_cwd is None:
                return None
            path_value = parsed_environment.get("PATH")
            env_reason = resolution_reason
            if path_value is not None and ("$" in path_value or "`" in path_value):
                env_reason = "path_expression_unresolved"
            return _shell_launch_candidate(
                list(parsed.executable_argv),
                cwd=parsed.effective_cwd,
                environment=parsed_environment,
                depth=depth + 1,
                resolution_reason=env_reason,
            )
        if command_name not in _SHELL_COMMAND_WRAPPERS:
            path_value = effective_environment.get("PATH")
            final_reason = resolution_reason
            if path_value is not None and ("$" in path_value or "`" in path_value):
                final_reason = "path_expression_unresolved"
            return _ShellLaunchCandidate(
                tokens=tuple(working),
                command_index=index,
                effective_cwd=effective_cwd,
                environment=effective_environment,
                resolution_reason=final_reason,
            )
        if command_name == "sudo":
            index, effective_cwd, sudo_reason = _consume_sudo_wrapper_for_interpreter(
                working,
                index + 1,
                cwd=effective_cwd,
            )
            resolution_reason = resolution_reason or sudo_reason
            continue
        index += 1
        while index < len(working) and working[index].startswith("-"):
            wrapper_token = working[index]
            if command_name == "command" and "p" in wrapper_token.lstrip("-"):
                effective_environment["PATH"] = os.defpath
            index += _wrapper_option_tokens_consumed(command_name, wrapper_token)
    return None


def _consume_sudo_wrapper_for_interpreter(
    tokens: list[str],
    index: int,
    *,
    cwd: Path,
) -> tuple[int, Path, str | None]:
    chdir_value: str | None = None
    reason: str | None = "sudo_path_resolution_unproven"
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            return index + 1, cwd, reason
        if not token.startswith("-"):
            break
        if token in {"-R", "--chroot"} or token.startswith(("-R", "--chroot=")):
            reason = "sudo_chroot_unresolved"
        if token in {"-D", "--chdir"}:
            if index + 1 >= len(tokens):
                return len(tokens), cwd, "sudo_chdir_missing"
            chdir_value = tokens[index + 1]
        elif token.startswith("--chdir="):
            chdir_value = token.split("=", 1)[1]
        elif token.startswith("-D") and token != "-D":
            chdir_value = token[2:]
        index += _wrapper_option_tokens_consumed("sudo", token)
    if chdir_value is not None:
        if not chdir_value or any(marker in chdir_value for marker in ("$", "`", "\x00")):
            return index, cwd, "sudo_chdir_unresolved"
        candidate = Path(chdir_value).expanduser()
        if not candidate.is_absolute():
            candidate = cwd / candidate
        try:
            resolved_cwd = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            return index, cwd, "sudo_chdir_unresolved"
        if not resolved_cwd.is_dir():
            return index, cwd, "sudo_chdir_unresolved"
        cwd = resolved_cwd
    return index, cwd, reason


def _ambiguous_python_evidence_from_tokens(
    tokens: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    workspace_root: Path,
    home_dir: Path | None,
    reason: str,
) -> tuple[dict[str, object], ...]:
    evidence: list[dict[str, object]] = []
    for token in tokens:
        raw_token = _shell_command_token_without_attached_redirection(token).strip()
        if not _is_python_interpreter_command(raw_token):
            continue
        evidence.append(
            _python_interpreter_executable_identity(
                raw_token,
                cwd=cwd,
                environment=environment,
                workspace_root=workspace_root,
                home_dir=home_dir,
                resolution_reason=reason,
            )
        )
    return tuple(evidence)


def _python_interpreter_executable_identity(
    raw_token: str,
    *,
    cwd: Path,
    environment: dict[str, str],
    workspace_root: Path,
    home_dir: Path | None,
    resolution_reason: str | None,
) -> dict[str, object]:
    search_path = environment.get("PATH")
    identity = build_runtime_executable_identity(raw_token, search_path=search_path, cwd=cwd)
    if resolution_reason is not None and not _interpreter_token_has_path(raw_token):
        identity = {**identity, "resolution_reason": resolution_reason, "reuse_nonce": secrets.token_hex(16)}
    trust = _python_interpreter_trust(
        raw_token,
        identity=identity,
        workspace_root=workspace_root,
        home_dir=home_dir,
        resolution_reason=resolution_reason,
    )
    return {
        "effective_cwd": str(cwd),
        "executable": identity,
        "normalized_name": _normalized_shell_command_name(raw_token),
        "raw_token": raw_token,
        "search_path_sha256": hashlib.sha256((search_path or "").encode("utf-8")).hexdigest(),
        "trust": trust,
    }


def _without_interpreter_reuse_nonces(value: object) -> object:
    if isinstance(value, dict):
        return {
            str(key): _without_interpreter_reuse_nonces(item) for key, item in value.items() if key != "reuse_nonce"
        }
    if isinstance(value, (list, tuple)):
        return [_without_interpreter_reuse_nonces(item) for item in value]
    return value


__all__ = [
    "_ShellLaunchCandidate",
    "_ambiguous_python_evidence_from_tokens",
    "_consume_sudo_wrapper_for_interpreter",
    "_normalized_interpreter_cwd",
    "_python_interpreter_executable_identity",
    "_shell_launch_candidate",
    "_without_interpreter_reuse_nonces",
]
