"""Network upload and stdin source detection."""

from __future__ import annotations

from pathlib import Path

from .constants_core import _SAFE_SHELL_REDIRECT_TARGETS
from .constants_patterns import (
    _CURL_AT_FILE_FLAGS_WITH_VALUE,
    _CURL_CONFIG_FLAGS_WITH_VALUE,
    _CURL_DATA_URLENCODE_FLAGS_WITH_VALUE,
    _CURL_DIRECT_FILE_FLAGS_WITH_VALUE,
    _CURL_EXPAND_FLAGS_WITH_VALUE,
    _CURL_FORM_FLAGS_WITH_VALUE,
    _CURL_VARIABLE_FLAGS_WITH_VALUE,
)
from .credential_exfiltration import _curl_clustered_short_flag_tokens_consumed, _read_small_runtime_text_file
from .request_models import _MAX_DECODED_PAYLOAD_BYTES
from .sensitive_read_pipeline import _resolved_runtime_path, _runtime_read_roots, _strip_cli_value
from .shell_tokenization import (
    _iter_shell_command_segments,
    _shell_command_token_without_attached_redirection,
    _shell_segment_primary_command,
    _split_shell_parts,
    _token_is_heredoc_operator,
)
from .upload_arguments import (
    _curl_clustered_short_flag_value,
    _curl_config_arguments,
    _curl_upload_value_uses_local_file,
    _curl_variable_value_uses_local_file,
    _wget_segment_uses_file_upload,
)


def _segment_uses_network_file_upload(
    segment: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
    stdin_uses_local_file: bool = False,
) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return False
    segment_args = segment[command_index + 1 :]
    if command_name == "curl":
        return _curl_segment_uses_file_upload(
            segment_args,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            stdin_uses_local_file=stdin_uses_local_file,
        )
    if command_name == "wget":
        return _wget_segment_uses_file_upload(segment_args, stdin_uses_local_file=stdin_uses_local_file)
    return False


def _curl_segment_uses_file_upload(
    segment_args: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
    visited_config_paths: frozenset[str] = frozenset(),
    stdin_config_payloads: tuple[tuple[str, Path | None], ...] = (),
    stdin_uses_local_file: bool = False,
) -> bool:
    index = 0
    saw_variable_file_input = False
    saw_variable_expansion = False
    while index < len(segment_args):
        token = segment_args[index]
        if token == "--":
            break
        if token in _CURL_CONFIG_FLAGS_WITH_VALUE:
            value = segment_args[index + 1] if index + 1 < len(segment_args) else ""
            if _curl_config_uses_file_upload(
                value,
                cwd=cwd,
                home_dir=home_dir,
                allowed_roots=allowed_roots,
                visited_config_paths=visited_config_paths,
                stdin_config_payloads=stdin_config_payloads,
            ):
                return True
            index += 2
            continue
        if (
            token in _CURL_AT_FILE_FLAGS_WITH_VALUE
            or token in _CURL_DATA_URLENCODE_FLAGS_WITH_VALUE
            or token in _CURL_FORM_FLAGS_WITH_VALUE
            or token in _CURL_DIRECT_FILE_FLAGS_WITH_VALUE
        ):
            value = segment_args[index + 1] if index + 1 < len(segment_args) else ""
            if _curl_upload_value_uses_local_file(token, value, stdin_uses_local_file=stdin_uses_local_file):
                return True
            index += 2
            continue
        if token in _CURL_VARIABLE_FLAGS_WITH_VALUE:
            value = segment_args[index + 1] if index + 1 < len(segment_args) else ""
            saw_variable_file_input = saw_variable_file_input or _curl_variable_value_uses_local_file(value)
            index += 2
            continue
        if token in _CURL_EXPAND_FLAGS_WITH_VALUE:
            saw_variable_expansion = True
            index += 2
            continue
        if token.startswith("--config=") and _curl_config_uses_file_upload(
            token.split("=", 1)[1],
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            visited_config_paths=visited_config_paths,
            stdin_config_payloads=stdin_config_payloads,
        ):
            return True
        if token.startswith("--data=") and _curl_upload_value_uses_local_file(
            "--data",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--data-ascii=") and _curl_upload_value_uses_local_file(
            "--data-ascii",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--data-binary=") and _curl_upload_value_uses_local_file(
            "--data-binary",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--json=") and _curl_upload_value_uses_local_file(
            "--json",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--url-query=") and _curl_upload_value_uses_local_file(
            "--url-query",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--data-urlencode=") and _curl_upload_value_uses_local_file(
            "--data-urlencode",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--data-raw=") and _curl_upload_value_uses_local_file(
            "--data-raw",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--form=") and _curl_upload_value_uses_local_file(
            "--form",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--upload-file=") and _curl_upload_value_uses_local_file(
            "--upload-file",
            token.split("=", 1)[1],
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        if token.startswith("--variable="):
            saw_variable_file_input = saw_variable_file_input or _curl_variable_value_uses_local_file(
                token.split("=", 1)[1]
            )
            index += 1
            continue
        if token.startswith("--expand-"):
            saw_variable_expansion = True
            index += 1
            continue
        clustered_tokens_consumed = _curl_clustered_short_flag_tokens_consumed(segment_args, index)
        clustered_upload_value = _curl_clustered_short_flag_value(segment_args, index, "T")
        if clustered_upload_value is not None and _curl_upload_value_uses_local_file(
            "-T",
            clustered_upload_value,
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        clustered_config_value = _curl_clustered_short_flag_value(segment_args, index, "K")
        if clustered_config_value is not None and _curl_config_uses_file_upload(
            clustered_config_value,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            visited_config_paths=visited_config_paths,
            stdin_config_payloads=stdin_config_payloads,
        ):
            return True
        clustered_form_value = _curl_clustered_short_flag_value(segment_args, index, "F")
        if clustered_form_value is not None and _curl_upload_value_uses_local_file("-F", clustered_form_value):
            return True
        clustered_data_value = _curl_clustered_short_flag_value(segment_args, index, "d")
        if clustered_data_value is not None and _curl_upload_value_uses_local_file(
            "-d",
            clustered_data_value,
            stdin_uses_local_file=stdin_uses_local_file,
        ):
            return True
        index += clustered_tokens_consumed
    return saw_variable_file_input and saw_variable_expansion


def _curl_segment_reads_config_from_stdin(segment_args: list[str]) -> bool:
    index = 0
    while index < len(segment_args):
        token = segment_args[index]
        if token == "--":
            return False
        if token in _CURL_CONFIG_FLAGS_WITH_VALUE:
            value = segment_args[index + 1] if index + 1 < len(segment_args) else ""
            if _strip_cli_value(_shell_command_token_without_attached_redirection(value)) == "-":
                return True
            index += 2
            continue
        if (
            token.startswith("--config=")
            and _strip_cli_value(_shell_command_token_without_attached_redirection(token.split("=", 1)[1])) == "-"
        ):
            return True
        clustered_config_value = _curl_clustered_short_flag_value(segment_args, index, "K")
        if (
            clustered_config_value is not None
            and _strip_cli_value(_shell_command_token_without_attached_redirection(clustered_config_value)) == "-"
        ):
            return True
        index += 1
    return False


def _curl_inline_config_text_uses_file_upload(config_text: str, *, cwd: Path | None, home_dir: Path | None) -> bool:
    if not config_text or len(config_text.encode("utf-8", errors="ignore")) > _MAX_DECODED_PAYLOAD_BYTES:
        return False
    config_args = _curl_config_arguments(config_text)
    if not config_args:
        return False
    return _curl_segment_uses_file_upload(config_args, cwd=cwd, home_dir=home_dir)


def _stdin_redirect_uses_local_file(
    target: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    return _looks_like_local_stdin_source(target)


def _looks_like_local_stdin_source(value: str) -> bool:
    stripped_value = _strip_cli_value(value).lower()
    return bool(
        stripped_value
        and stripped_value not in {"-", "@-"}
        and stripped_value not in _SAFE_SHELL_REDIRECT_TARGETS
        and not stripped_value.startswith("&")
    )


def _curl_config_uses_file_upload(
    value: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
    visited_config_paths: frozenset[str],
    stdin_config_payloads: tuple[tuple[str, Path | None], ...] = (),
) -> bool:
    normalized_value = _shell_command_token_without_attached_redirection(value)
    stripped_value = _strip_cli_value(normalized_value)
    if stripped_value == "-":
        return any(
            _curl_inline_config_text_uses_file_upload(payload_text, cwd=payload_cwd, home_dir=home_dir)
            for payload_text, payload_cwd in stdin_config_payloads
        )
    read_roots = allowed_roots or _runtime_read_roots(cwd, home_dir)
    config_file = _resolved_runtime_path(normalized_value, cwd=cwd, home_dir=home_dir, allowed_roots=read_roots)
    if config_file is None:
        return False
    normalized_config_path = str(config_file)
    if normalized_config_path in visited_config_paths:
        return False
    config_text = _read_small_runtime_text_file(
        config_file,
        allowed_roots=read_roots,
    )
    if config_text is None:
        return False
    config_args = _curl_config_arguments(config_text)
    if not config_args:
        return False
    return _curl_segment_uses_file_upload(
        config_args,
        cwd=config_file.parent,
        home_dir=home_dir,
        allowed_roots=read_roots,
        visited_config_paths=visited_config_paths | frozenset({normalized_config_path}),
        stdin_config_payloads=stdin_config_payloads,
    )


def _command_uses_curl_stdin_heredoc(command_text: str) -> bool:
    parts = _split_shell_parts(command_text)
    for segment in _iter_shell_command_segments(parts):
        if not any(_token_is_heredoc_operator(token) for token in segment):
            continue
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name != "curl" or command_index is None:
            continue
        if _curl_segment_reads_config_from_stdin(segment[command_index + 1 :]):
            return True
    return False


__all__ = [
    "_command_uses_curl_stdin_heredoc",
    "_curl_config_uses_file_upload",
    "_curl_inline_config_text_uses_file_upload",
    "_curl_segment_reads_config_from_stdin",
    "_curl_segment_uses_file_upload",
    "_looks_like_local_stdin_source",
    "_segment_uses_network_file_upload",
    "_stdin_redirect_uses_local_file",
]
