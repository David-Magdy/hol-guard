"""Credential exfiltration and local script inspection."""

from __future__ import annotations

import contextlib
import os
import stat
from pathlib import Path

from .constants_core import _SHELL_SCRIPT_INTERPRETER_COMMANDS
from .constants_patterns import (
    _BROAD_CREDENTIAL_EXFILTRATION_SKIP_COMMANDS,
    _CURL_AT_FILE_FLAGS_WITH_VALUE,
    _CURL_CONFIG_FLAGS_WITH_VALUE,
    _CURL_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE,
    _CURL_DATA_URLENCODE_FLAGS_WITH_VALUE,
    _CURL_DIRECT_FILE_FLAGS_WITH_VALUE,
    _CURL_FORM_FLAGS_WITH_VALUE,
    _CURL_SHORT_FLAGS_WITH_VALUES,
    _CURL_VARIABLE_FLAGS_WITH_VALUE,
    _SHELL_ASSIGNMENT_PATTERN,
    _WGET_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE,
)
from .github_pr_body_safety import _text_contains_credential_exfiltration
from .request_models import _MAX_DECODED_PAYLOAD_BYTES, _SECRET_EXFILTRATION_DESTINATION_PATTERN
from .sensitive_read_pipeline import (
    _resolved_runtime_path,
    _runtime_file_entry_under_root,
    _runtime_read_root_texts,
    _runtime_read_roots,
)
from .shell_static_safety import _path_text_is_within_root_text
from .shell_tokenization import (
    _iter_shell_command_segments,
    _shell_command_token_without_attached_redirection,
    _shell_segment_primary_command,
)


def _shell_segments_contain_credential_exfiltration(parts: list[str]) -> bool:
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None or command_index is None:
            continue
        if command_name in _BROAD_CREDENTIAL_EXFILTRATION_SKIP_COMMANDS and command_name not in {"curl", "wget"}:
            continue
        segment_text = _shell_segment_credential_exfiltration_text(
            segment,
            command_name=command_name,
            command_index=command_index,
        )
        if segment_text and _text_contains_credential_exfiltration(segment_text):
            return True
    return False


def _shell_segment_credential_exfiltration_text(
    segment: list[str],
    *,
    command_name: str,
    command_index: int,
) -> str:
    if command_name == "curl":
        return _curl_segment_credential_exfiltration_text(segment, command_index=command_index)
    if command_name == "wget":
        return _wget_segment_credential_exfiltration_text(segment, command_index=command_index)
    return " ".join(segment[command_index:])


def _curl_segment_credential_exfiltration_text(segment: list[str], *, command_index: int) -> str:
    surface_tokens = [
        token
        for token in segment[:command_index]
        if _SHELL_ASSIGNMENT_PATTERN.match(_shell_command_token_without_attached_redirection(token))
    ]
    surface_tokens.append(segment[command_index])
    index = command_index + 1
    while index < len(segment):
        token = segment[index]
        if token == "--":
            surface_tokens.extend(_network_destination_tokens(segment[index + 1 :]))
            break
        clustered_tokens_consumed = _curl_clustered_short_flag_tokens_consumed(segment, index)
        if clustered_tokens_consumed > 1:
            surface_tokens.append(token)
            surface_tokens.append(segment[index + 1])
            index += clustered_tokens_consumed
            continue
        if len(token) == 2 and token[0] == "-" and token[1] in _CURL_SHORT_FLAGS_WITH_VALUES:
            surface_tokens.append(token)
            if index + 1 < len(segment):
                surface_tokens.append(segment[index + 1])
            index += 2
            continue
        if token.startswith("--") and "=" in token:
            surface_tokens.append(token)
            index += 1
            continue
        if token in _CURL_CONFIG_FLAGS_WITH_VALUE or token in _CURL_AT_FILE_FLAGS_WITH_VALUE:
            surface_tokens.append(token)
            if index + 1 < len(segment):
                surface_tokens.append(segment[index + 1])
            index += 2
            continue
        if token in _CURL_DATA_URLENCODE_FLAGS_WITH_VALUE or token in _CURL_FORM_FLAGS_WITH_VALUE:
            surface_tokens.append(token)
            if index + 1 < len(segment):
                surface_tokens.append(segment[index + 1])
            index += 2
            continue
        if token in _CURL_DIRECT_FILE_FLAGS_WITH_VALUE or token in _CURL_VARIABLE_FLAGS_WITH_VALUE:
            surface_tokens.append(token)
            if index + 1 < len(segment):
                surface_tokens.append(segment[index + 1])
            index += 2
            continue
        if token in _CURL_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE or token in {"-H", "-X"}:
            surface_tokens.append(token)
            if index + 1 < len(segment):
                surface_tokens.append(segment[index + 1])
            index += 2
            continue
        if not token.startswith("-"):
            if _SECRET_EXFILTRATION_DESTINATION_PATTERN.search(token):
                surface_tokens.append(token)
            index += 1
            continue
        surface_tokens.append(token)
        index += 1
    return " ".join(surface_tokens)


def _wget_segment_credential_exfiltration_text(segment: list[str], *, command_index: int) -> str:
    surface_tokens = [
        token
        for token in segment[:command_index]
        if _SHELL_ASSIGNMENT_PATTERN.match(_shell_command_token_without_attached_redirection(token))
    ]
    surface_tokens.append(segment[command_index])
    index = command_index + 1
    while index < len(segment):
        token = segment[index]
        if token == "--":
            surface_tokens.extend(_network_destination_tokens(segment[index + 1 :]))
            break
        if token in _WGET_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE:
            surface_tokens.append(token)
            if index + 1 < len(segment):
                surface_tokens.append(segment[index + 1])
            index += 2
            continue
        if any(
            token.startswith(f"{flag}=")
            for flag in _WGET_CREDENTIAL_EXFILTRATION_FLAGS_WITH_VALUE
            if flag.startswith("--")
        ):
            surface_tokens.append(token)
            index += 1
            continue
        if not token.startswith("-"):
            if _SECRET_EXFILTRATION_DESTINATION_PATTERN.search(token):
                surface_tokens.append(token)
            index += 1
            continue
        surface_tokens.append(token)
        index += 1
    return " ".join(surface_tokens)


def _network_destination_tokens(tokens: list[str]) -> list[str]:
    return [token for token in tokens if _SECRET_EXFILTRATION_DESTINATION_PATTERN.search(token)]


def _curl_clustered_short_flag_tokens_consumed(segment_args: list[str], index: int) -> int:
    token = segment_args[index]
    if not token.startswith("-") or token.startswith("--") or len(token) <= 2:
        return 1
    cluster = token[1:]
    for flag_index, cluster_flag in enumerate(cluster):
        if cluster_flag not in _CURL_SHORT_FLAGS_WITH_VALUES:
            continue
        attached_value = cluster[flag_index + 1 :]
        if attached_value:
            return 1
        return 2 if index + 1 < len(segment_args) else 1
    return 1


def _local_shell_script_payloads(
    parts: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
    visited_script_paths: frozenset[str],
) -> tuple[tuple[str, Path | None, str], ...]:
    payloads: list[tuple[str, Path | None, str]] = []
    read_roots = allowed_roots or _runtime_read_roots(cwd, home_dir)
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_index is None:
            continue
        script_path = _shell_script_path_for_segment(segment, command_name=command_name, command_index=command_index)
        if script_path is None:
            continue
        script_file = _resolved_runtime_path(script_path, cwd=cwd, home_dir=home_dir, allowed_roots=read_roots)
        if script_file is None:
            continue
        normalized_script_path = str(script_file)
        if normalized_script_path in visited_script_paths:
            continue
        script_text = _read_small_runtime_text_file(
            script_file,
            allowed_roots=read_roots,
        )
        if script_text is None:
            continue
        payloads.append((script_text, script_file.parent, normalized_script_path))
    return tuple(payloads)


def _shell_script_path_for_segment(
    segment: list[str],
    *,
    command_name: str | None,
    command_index: int,
) -> str | None:
    if command_name in _SHELL_SCRIPT_INTERPRETER_COMMANDS:
        return _shell_script_path_from_segment(segment[command_index + 1 :])
    command_token = segment[command_index].strip()
    if not command_token or command_token.startswith("-") or _SHELL_ASSIGNMENT_PATTERN.match(command_token):
        return None
    if not _is_explicit_shell_script_path_token(command_token):
        return None
    return command_token


def _shell_script_path_from_segment(segment_args: list[str]) -> str | None:
    index = 0
    while index < len(segment_args):
        token = segment_args[index].strip()
        if not token:
            index += 1
            continue
        if token == "--":
            index += 1
            break
        if _SHELL_ASSIGNMENT_PATTERN.match(token):
            index += 1
            continue
        if token == "-s":
            return None
        if token.startswith("-") and not token.startswith("--") and "c" in token[1:]:
            return None
        if not token.startswith("-") and not token.startswith("+"):
            return token
        if token in {"-c", "--command"} or token.startswith(("-c", "--command=")):
            return None
        if token in {"-O", "-o", "+O", "+o", "--rcfile", "--init-file"}:
            index += 2
            continue
        if token.startswith(("--rcfile=", "--init-file=")):
            index += 1
            continue
        index += 1
    while index < len(segment_args):
        token = segment_args[index].strip()
        if token:
            return token
        index += 1
    return None


def _is_explicit_shell_script_path_token(token: str) -> bool:
    normalized_token = token.strip()
    if not normalized_token:
        return False
    return (
        normalized_token.startswith((".", "/", "~"))
        or normalized_token.startswith("../")
        or normalized_token.startswith("./")
        or "/" in normalized_token
    )


def _read_small_runtime_text_file(path: Path, *, allowed_roots: tuple[Path, ...]) -> str | None:
    path_text = os.path.realpath(os.fspath(path))
    root_texts = _runtime_read_root_texts(allowed_roots)
    if not any(_path_text_is_within_root_text(path_text, root_text) for root_text in root_texts):
        return None
    runtime_entry = next(
        (
            entry
            for root_text in root_texts
            if _path_text_is_within_root_text(path_text, root_text)
            for entry in (_runtime_file_entry_under_root(path_text, root_text),)
            if entry is not None
        ),
        None,
    )
    if runtime_entry is None:
        return None
    open_flags = os.O_RDONLY
    nofollow_flag = getattr(os, "O_NOFOLLOW", 0)
    if isinstance(nofollow_flag, int):
        open_flags |= nofollow_flag
    try:
        entry_stat = runtime_entry.stat(follow_symlinks=False)
    except OSError:
        return None
    if not stat.S_ISREG(entry_stat.st_mode) or entry_stat.st_size > _MAX_DECODED_PAYLOAD_BYTES:
        return None
    try:
        descriptor = os.open(runtime_entry.path, open_flags)
    except OSError:
        return None
    try:
        stat_result = os.fstat(descriptor)
        if not stat.S_ISREG(stat_result.st_mode) or stat_result.st_size > _MAX_DECODED_PAYLOAD_BYTES:
            os.close(descriptor)
            return None
        runtime_file = os.fdopen(descriptor, encoding="utf-8")
    except OSError:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        return None
    with runtime_file:
        try:
            content = runtime_file.read(_MAX_DECODED_PAYLOAD_BYTES + 1)
        except (OSError, UnicodeDecodeError):
            return None
    return content if len(content) <= _MAX_DECODED_PAYLOAD_BYTES else None


__all__ = [
    "_curl_clustered_short_flag_tokens_consumed",
    "_curl_segment_credential_exfiltration_text",
    "_is_explicit_shell_script_path_token",
    "_local_shell_script_payloads",
    "_network_destination_tokens",
    "_read_small_runtime_text_file",
    "_shell_script_path_for_segment",
    "_shell_script_path_from_segment",
    "_shell_segment_credential_exfiltration_text",
    "_shell_segments_contain_credential_exfiltration",
    "_wget_segment_credential_exfiltration_text",
]
