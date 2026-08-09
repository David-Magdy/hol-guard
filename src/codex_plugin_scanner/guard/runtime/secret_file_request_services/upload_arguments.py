"""Network upload argument classification."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

from .constants_patterns import (
    _CURL_DATA_URLENCODE_FLAGS_WITH_VALUE,
    _CURL_DIRECT_FILE_FLAGS_WITH_VALUE,
    _CURL_FORM_FLAGS_WITH_VALUE,
    _CURL_SHORT_FLAGS_WITH_VALUES,
    _WGET_UPLOAD_FLAGS_WITH_VALUE,
)
from .credential_exfiltration import _local_shell_script_payloads
from .encoded_payloads import (
    _contains_command_substitution_decode_exec,
    _decode_base64_literal,
    _decode_hex_literal,
    _looks_destructive_shell_command,
    _shell_text_without_quoted_literals,
)
from .github_shell_capabilities import _env_split_string_payloads, _shell_command_scripts
from .request_models import (
    _BASE64_LITERAL_PATTERN,
    _ENCODED_EXECUTION_PATTERNS,
    _HEX_LITERAL_PATTERN,
    _SENSITIVE_DECODED_PAYLOAD_TOKENS,
)
from .sensitive_read_pipeline import _strip_cli_value
from .shell_tokenization import _split_shell_parts


def _contains_encoded_or_encrypted_shell_command(
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
    executable_surface = _shell_text_without_quoted_literals(normalized)
    if any(pattern.search(executable_surface) for pattern in _ENCODED_EXECUTION_PATTERNS):
        return True
    if _contains_command_substitution_decode_exec(normalized):
        return True
    parts = _split_shell_parts(normalized)
    if not parts:
        return False
    for payload in _decoded_shell_payloads(executable_surface):
        if _decoded_payload_looks_sensitive(
            payload,
            cwd=cwd,
            home_dir=home_dir,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for env_split_string in _env_split_string_payloads(parts):
        if _contains_encoded_or_encrypted_shell_command(
            env_split_string,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths,
        ):
            return True
    for shell_script in _shell_command_scripts(parts):
        if _contains_encoded_or_encrypted_shell_command(
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
        if _contains_encoded_or_encrypted_shell_command(
            script_text,
            cwd=script_cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
            depth=depth + 1,
            visited_script_paths=visited_script_paths | frozenset({script_path}),
        ):
            return True
    return False


def _wget_segment_uses_file_upload(segment_args: list[str], *, stdin_uses_local_file: bool = False) -> bool:
    index = 0
    while index < len(segment_args):
        token = segment_args[index]
        if token == "--":
            return False
        if token in _WGET_UPLOAD_FLAGS_WITH_VALUE:
            value = segment_args[index + 1] if index + 1 < len(segment_args) else ""
            if _direct_file_operand_uses_local_file(value, stdin_uses_local_file=stdin_uses_local_file):
                return True
            index += 2
            continue
        if token.startswith("--body-file=") and _direct_file_operand_uses_local_file(
            token.split("=", 1)[1], stdin_uses_local_file=stdin_uses_local_file
        ):
            return True
        if token.startswith("--post-file=") and _direct_file_operand_uses_local_file(
            token.split("=", 1)[1], stdin_uses_local_file=stdin_uses_local_file
        ):
            return True
        index += 1
    return False


def _curl_upload_value_uses_local_file(flag: str, value: str, *, stdin_uses_local_file: bool = False) -> bool:
    stripped_value = value.strip()
    if flag in _CURL_DIRECT_FILE_FLAGS_WITH_VALUE:
        return _direct_file_operand_uses_local_file(stripped_value, stdin_uses_local_file=stdin_uses_local_file)
    if flag in _CURL_FORM_FLAGS_WITH_VALUE:
        return _curl_form_value_uses_local_file(stripped_value)
    if flag in _CURL_DATA_URLENCODE_FLAGS_WITH_VALUE:
        return _curl_data_urlencode_value_uses_local_file(stripped_value)
    if flag == "--data-raw":
        return False
    return _value_uses_local_file(stripped_value, stdin_uses_local_file=stdin_uses_local_file)


def _curl_form_value_uses_local_file(value: str) -> bool:
    stripped_value = _strip_cli_value(value)
    if not stripped_value:
        return False
    field_value = stripped_value.split("=", 1)[1] if "=" in stripped_value else stripped_value
    if not field_value or field_value[0] not in {"@", "<"}:
        return False
    return _direct_file_operand_uses_local_file(re.split(r"[;,]", field_value[1:], maxsplit=1)[0])


def _curl_data_urlencode_value_uses_local_file(value: str) -> bool:
    stripped_value = _strip_cli_value(value)
    if not stripped_value:
        return False
    if stripped_value.startswith("@"):
        return _value_uses_local_file(stripped_value)
    if "@" not in stripped_value:
        return False
    name, file_candidate = stripped_value.split("@", 1)
    if "=" in name:
        return False
    return _direct_file_operand_uses_local_file(file_candidate)


def _curl_variable_value_uses_local_file(value: str) -> bool:
    stripped_value = _strip_cli_value(value)
    if "@" not in stripped_value:
        return False
    variable_name, file_candidate = stripped_value.split("@", 1)
    normalized_name = variable_name.lstrip("%")
    if not normalized_name or "=" in normalized_name:
        return False
    return _direct_file_operand_uses_local_file(file_candidate)


def _curl_config_arguments(config_text: str) -> list[str]:
    arguments: list[str] = []
    for raw_line in config_text.splitlines():
        stripped_line = raw_line.strip()
        if not stripped_line or stripped_line.startswith("#"):
            continue
        try:
            tokens = shlex.split(stripped_line, comments=True, posix=True)
        except ValueError:
            continue
        if not tokens:
            continue
        if len(tokens) == 1 and not tokens[0].startswith("-") and ":" in tokens[0] and not tokens[0].endswith(":"):
            option_name, option_value = tokens[0].split(":", 1)
            if option_name and option_value:
                tokens = [option_name, option_value]
        if tokens[0].endswith(":"):
            tokens[0] = tokens[0][:-1]
        elif len(tokens) >= 3 and tokens[1] in {"=", ":"}:
            tokens = [tokens[0], *tokens[2:]]
        first_token = tokens[0]
        if not first_token.startswith("-"):
            first_token = f"--{first_token}"
        tokens[0] = first_token
        arguments.extend(tokens)
    return arguments


def _curl_clustered_short_flag_value(segment_args: list[str], index: int, flag_character: str) -> str | None:
    token = segment_args[index]
    if not token.startswith("-") or token.startswith("--") or len(token) <= 2:
        return None
    cluster = token[1:]
    for flag_index, cluster_flag in enumerate(cluster):
        if cluster_flag == flag_character:
            attached_value = cluster[flag_index + 1 :]
            if attached_value:
                return attached_value
            return segment_args[index + 1] if index + 1 < len(segment_args) else ""
        if cluster_flag in _CURL_SHORT_FLAGS_WITH_VALUES:
            return None
    return None


def _direct_file_operand_uses_local_file(value: str, *, stdin_uses_local_file: bool = False) -> bool:
    stripped_value = _strip_cli_value(value)
    if not stripped_value:
        return False
    if stripped_value in {"-", "@-"}:
        return stdin_uses_local_file
    return True


def _value_uses_local_file(value: str, *, stdin_uses_local_file: bool = False) -> bool:
    stripped_value = _strip_cli_value(value)
    if not stripped_value:
        return False
    if stripped_value == "@-":
        return stdin_uses_local_file
    if stripped_value.startswith("@"):
        return stripped_value[1:] != "-"
    return False


def _decoded_payload_looks_sensitive(
    payload: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    depth: int,
    visited_script_paths: frozenset[str],
) -> bool:
    lowered = payload.lower()
    if _looks_destructive_shell_command(payload, cwd=cwd, home_dir=home_dir):
        return True
    if any(token in lowered for token in _SENSITIVE_DECODED_PAYLOAD_TOKENS):
        return True
    return _contains_encoded_or_encrypted_shell_command(
        payload,
        cwd=cwd,
        home_dir=home_dir,
        depth=depth,
        visited_script_paths=visited_script_paths,
    )


def _decoded_shell_payloads(command_text: str) -> tuple[str, ...]:
    lowered = command_text.lower()
    payloads: list[str] = []
    if any(
        token in lowered
        for token in ("base64", "b64decode", "frombase64string", "-encodedcommand", " -enc ", "openssl", "gpg")
    ):
        for literal in _BASE64_LITERAL_PATTERN.findall(command_text):
            decoded = _decode_base64_literal(literal)
            if decoded is not None:
                payloads.append(decoded)
    if "xxd" in lowered:
        for literal in _HEX_LITERAL_PATTERN.findall(command_text):
            decoded = _decode_hex_literal(literal)
            if decoded is not None:
                payloads.append(decoded)
    return tuple(payloads)


__all__ = [
    "_contains_encoded_or_encrypted_shell_command",
    "_curl_clustered_short_flag_value",
    "_curl_config_arguments",
    "_curl_data_urlencode_value_uses_local_file",
    "_curl_form_value_uses_local_file",
    "_curl_upload_value_uses_local_file",
    "_curl_variable_value_uses_local_file",
    "_decoded_payload_looks_sensitive",
    "_decoded_shell_payloads",
    "_direct_file_operand_uses_local_file",
    "_value_uses_local_file",
    "_wget_segment_uses_file_upload",
]
