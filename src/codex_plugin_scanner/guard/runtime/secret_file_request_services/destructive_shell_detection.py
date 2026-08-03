"""Destructive shell, Git, and redirection detection."""

from __future__ import annotations

import re
from pathlib import Path

from .constants_core import _DESTRUCTIVE_SHELL_COMMANDS, _SAFE_SHELL_REDIRECT_TARGETS
from .constants_patterns import (
    _DESTRUCTIVE_GIT_SUBCOMMANDS,
    _GIT_GLOBAL_OPTIONS_WITH_VALUE,
    _SINGLE_INTERPRETER_HEREDOC_PATTERN,
)
from .credential_exfiltration import _local_shell_script_payloads, _shell_segments_contain_credential_exfiltration
from .github_pr_body_safety import _shell_heredoc_payloads, _text_contains_credential_exfiltration
from .github_shell_capabilities import (
    _env_split_string_payloads,
    _shell_command_scripts,
    _shell_command_substitution_payloads,
)
from .pytest_target_detection import _segment_targets_pytest
from .read_only_filters import _split_attached_redirection_token
from .request_artifacts import _normalized_shell_command_name
from .sensitive_read_pipeline import _shell_pipeline_reads_sensitive_path_to_network
from .shell_tokenization import _iter_shell_command_segments, _shell_segment_primary_command, _split_shell_parts


def _contains_shell_credential_exfiltration(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
    depth: int = 0,
    visited_script_paths: frozenset[str] = frozenset(),
) -> bool:
    if depth > 4:
        return False
    normalized = command_text.strip()
    if not normalized:
        return False
    parts = _split_shell_parts(normalized)
    if not parts:
        return False
    if _shell_pipeline_reads_sensitive_path_to_network(parts, cwd=cwd, home_dir=home_dir):
        return True
    if _shell_segments_contain_credential_exfiltration(parts):
        return True
    for heredoc_payload in _shell_heredoc_payloads(normalized):
        if _text_contains_credential_exfiltration(heredoc_payload):
            return True
    for env_split_string in _env_split_string_payloads(parts):
        if _contains_shell_credential_exfiltration(
            env_split_string,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for substitution_payload in _shell_command_substitution_payloads(normalized):
        if _contains_shell_credential_exfiltration(
            substitution_payload,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for shell_script in _shell_command_scripts(parts):
        if _contains_shell_credential_exfiltration(
            shell_script,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for script_text, script_cwd, script_path in _local_shell_script_payloads(
        parts,
        cwd=cwd,
        home_dir=home_dir,
        allowed_roots=allowed_roots,
        visited_script_paths=visited_script_paths,
    ):
        if _contains_shell_credential_exfiltration(
            script_text,
            cwd=script_cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths | frozenset({script_path}),
        ):
            return True
    return False


def _find_command_uses_delete(parts: list[str]) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name != "find" or command_index is None:
            continue
        if _find_segment_uses_delete(segment[command_index + 1 :]):
            return True
    return False


def _find_segment_uses_delete(segment_args: list[str]) -> bool:
    value_taking_predicates = {
        "-name",
        "-iname",
        "-path",
        "-ipath",
        "-wholename",
        "-iwholename",
        "-regex",
        "-iregex",
        "-lname",
        "-ilname",
    }
    index = 0
    while index < len(segment_args):
        token = segment_args[index]
        if token in {"-exec", "-execdir", "-ok", "-okdir"}:
            index += 1
            if index < len(segment_args):
                command_name = _normalized_shell_command_name(segment_args[index])
                if command_name in _DESTRUCTIVE_SHELL_COMMANDS:
                    return True
            while index < len(segment_args) and segment_args[index] not in {";", "+"}:
                index += 1
            if index < len(segment_args):
                index += 1
            continue
        if token in value_taking_predicates and index + 1 < len(segment_args):
            index += 2
            continue
        if token == "-delete":
            return True
        index += 1
    return False


def _contains_destructive_git_command(parts: list[str]) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name != "git" or command_index is None:
            continue
        if _segment_uses_destructive_git_command(segment[command_index + 1 :]):
            return True
    return False


def _segment_uses_destructive_git_command(segment_args: list[str]) -> bool:
    subcommand_index = 0
    while subcommand_index < len(segment_args):
        token = segment_args[subcommand_index]
        if token == "--":
            subcommand_index += 1
            continue
        if token in {"-h", "--help", "--version"}:
            return False
        if token in _GIT_GLOBAL_OPTIONS_WITH_VALUE and subcommand_index + 1 < len(segment_args):
            subcommand_index += 2
            continue
        if any(token.startswith(f"{option}=") for option in _GIT_GLOBAL_OPTIONS_WITH_VALUE if option.startswith("--")):
            subcommand_index += 1
            continue
        if token.startswith("-"):
            subcommand_index += 1
            continue
        normalized_token = token.strip().lower()
        if normalized_token == "help":
            return False
        if normalized_token == "clean":
            clean_arguments = segment_args[subcommand_index + 1 :]
            return not _git_clean_is_preview(clean_arguments)
        return normalized_token in _DESTRUCTIVE_GIT_SUBCOMMANDS
    return False


def _git_clean_is_preview(arguments: list[str]) -> bool:
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        normalized = argument.strip().lower()
        option_name = normalized.split("=", 1)[0]
        if option_name in {"-e", "--exclude"} and "=" not in normalized:
            index += 2
            continue
        if normalized == "--dry-run":
            return True
        if normalized.startswith("-") and not normalized.startswith("--"):
            for flag in normalized[1:]:
                if flag == "e":
                    break
                if flag == "n":
                    return True
        index += 1
    return False


def _contains_mutating_shell_redirection(parts: list[str]) -> bool:
    index = 0
    while index < len(parts):
        token = parts[index].strip()
        if not token:
            index += 1
            continue
        fd = ""
        target: str | None = None
        if token in {">", ">>", ">|", "1>", "1>>", "1>|", "2>", "2>>", "2>|"}:
            if token[0].isdigit():
                fd = token[0]
            if token.endswith(">") and index + 2 < len(parts) and parts[index + 1] == "|":
                target = parts[index + 2]
                index += 3
            elif index + 1 < len(parts):
                target = parts[index + 1]
                index += 2
            else:
                index += 1
        else:
            redirection = _split_attached_redirection_token(token)
            if redirection is None:
                index += 1
                continue
            prefix, fd, _op, target = redirection
            if prefix.endswith("="):
                index += 1
                continue
            if target:
                index += 1
            elif index + 1 < len(parts):
                target = parts[index + 1]
                index += 2
            else:
                index += 1
        if target is None:
            continue
        normalized_target = _normalized_redirect_target(target).lower()
        if fd == "2" and normalized_target in _SAFE_SHELL_REDIRECT_TARGETS:
            continue
        if normalized_target in _SAFE_SHELL_REDIRECT_TARGETS or normalized_target.startswith("&"):
            continue
        return True
    return False


def _normalized_redirect_target(target: str) -> str:
    return target.strip().strip(");,").strip("'\"")


def _shell_command_names(command_text: str) -> tuple[str, ...]:
    return _shell_command_names_from_parts(_split_shell_parts(command_text))


def _redacted_shell_text_for_command_names(command_text: str) -> str:
    return re.sub(r"'[^']*'|\"[^\"]*\"", "Q", command_text)


def _shell_text_for_redirection_scan(command_text: str) -> str:
    """Hide quoted arguments while retaining quoted redirect targets."""

    result: list[str] = []
    index = 0
    while index < len(command_text):
        quote = command_text[index]
        if quote not in {"'", '"'}:
            result.append(quote)
            index += 1
            continue
        previous_index = index - 1
        while previous_index >= 0 and command_text[previous_index].isspace():
            previous_index -= 1
        preserve = previous_index >= 0 and command_text[previous_index] == ">"
        result.append(quote if preserve else "Q")
        index += 1
        while index < len(command_text):
            character = command_text[index]
            if quote == '"' and character == "\\" and index + 1 < len(command_text):
                if preserve:
                    result.extend((character, command_text[index + 1]))
                index += 2
                continue
            if character == quote:
                if preserve:
                    result.append(character)
                index += 1
                break
            if preserve:
                result.append(character)
            index += 1
    return "".join(result)


def _shell_command_names_from_parts(parts: list[str]) -> tuple[str, ...]:
    command_names: list[str] = []
    for segment in _iter_shell_command_segments(parts):
        command_name, _command_index = _shell_segment_primary_command(segment)
        if command_name is not None:
            command_names.append(command_name)
    return tuple(command_names)


def _shell_script_targets_pytest(script_text: str) -> bool:
    for segment in _iter_shell_command_segments(_split_shell_parts(script_text)):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            continue
        if _segment_targets_pytest(segment, command_name, command_index):
            return True
    return False


def _single_interpreter_heredoc_script(command_text: str) -> str | None:
    match = _SINGLE_INTERPRETER_HEREDOC_PATTERN.fullmatch(command_text.strip())
    if match is None:
        return None
    script_text = match.group("body").strip()
    return script_text or None


__all__ = [
    "_contains_destructive_git_command",
    "_contains_mutating_shell_redirection",
    "_contains_shell_credential_exfiltration",
    "_find_command_uses_delete",
    "_find_segment_uses_delete",
    "_git_clean_is_preview",
    "_normalized_redirect_target",
    "_redacted_shell_text_for_command_names",
    "_segment_uses_destructive_git_command",
    "_shell_command_names",
    "_shell_command_names_from_parts",
    "_shell_script_targets_pytest",
    "_shell_text_for_redirection_scan",
    "_single_interpreter_heredoc_script",
]
