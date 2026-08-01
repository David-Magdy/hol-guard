"""Shell stdin and stdout payload tracing."""

from __future__ import annotations

from pathlib import Path

from .credential_exfiltration import _read_small_runtime_text_file
from .network_upload_detection import _looks_like_local_stdin_source, _stdin_redirect_uses_local_file
from .sensitive_read_pipeline import _resolved_runtime_path, _runtime_read_roots, _strip_cli_value
from .shell_tokenization import _shell_segment_primary_command, _stdin_redirect_target_from_token


def _shell_pipeline_stdin_uses_local_file(
    pipeline: list[list[str]],
    index: int,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    stdin_uses_local_file = False
    for upstream_segment in pipeline[:index]:
        stdin_uses_local_file = _shell_segment_stdout_uses_local_file(
            upstream_segment,
            stdin_uses_local_file=stdin_uses_local_file,
            cwd=cwd,
            home_dir=home_dir,
        )
    return stdin_uses_local_file or _shell_stdin_redirect_uses_local_file(
        pipeline[index],
        cwd=cwd,
        home_dir=home_dir,
    )


def _shell_pipeline_stdin_payloads(
    pipeline: list[list[str]],
    index: int,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
) -> tuple[tuple[str, Path | None], ...]:
    payloads: tuple[tuple[str, Path | None], ...] = ()
    for upstream_segment in pipeline[:index]:
        payloads = _shell_segment_stdout_payloads(
            upstream_segment,
            stdin_payloads=payloads,
            cwd=cwd,
            home_dir=home_dir,
            allowed_roots=allowed_roots,
        )
    current_redirect_payloads = _shell_stdin_redirect_payloads(
        pipeline[index],
        cwd=cwd,
        home_dir=home_dir,
        allowed_roots=allowed_roots,
    )
    return current_redirect_payloads or payloads


def _shell_segment_stdout_payloads(
    segment: list[str],
    *,
    stdin_payloads: tuple[tuple[str, Path | None], ...],
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
) -> tuple[tuple[str, Path | None], ...]:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return stdin_payloads
    segment_args = segment[command_index + 1 :]
    redirected_input_payloads = _shell_stdin_redirect_payloads(
        segment,
        cwd=cwd,
        home_dir=home_dir,
        allowed_roots=allowed_roots,
    )
    effective_input_payloads = redirected_input_payloads or stdin_payloads
    if command_name == "printf":
        payloads = _printf_stdout_payloads(segment_args)
        return tuple((payload, cwd) for payload in payloads)
    if command_name == "echo":
        payload = _echo_stdout_payload(segment_args)
        return ((payload, cwd),) if payload else ()
    if command_name == "cat":
        return (
            _cat_stdout_payloads(segment_args, cwd=cwd, home_dir=home_dir, allowed_roots=allowed_roots)
            or effective_input_payloads
        )
    if command_name in {"sed", "tr"}:
        return effective_input_payloads
    return ()


def _shell_segment_stdout_uses_local_file(
    segment: list[str],
    *,
    stdin_uses_local_file: bool,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return stdin_uses_local_file
    if _shell_stdin_redirect_uses_local_file(segment, cwd=cwd, home_dir=home_dir):
        return True
    segment_args = segment[command_index + 1 :]
    if command_name == "cat":
        return _cat_reads_local_file(segment_args, cwd=cwd, home_dir=home_dir) or stdin_uses_local_file
    if command_name in {"echo", "printf"}:
        return False
    return stdin_uses_local_file


def _printf_stdout_payloads(segment_args: list[str]) -> tuple[str, ...]:
    args = list(segment_args)
    if args and args[0] == "--":
        args = args[1:]
    decoded_args = tuple(decoded for decoded in (_decode_shell_text_literal(arg) for arg in args) if decoded)
    if not decoded_args:
        return ()
    if len(decoded_args) == 1:
        return decoded_args
    return (*decoded_args, "\n".join(decoded_args))


def _echo_stdout_payload(segment_args: list[str]) -> str | None:
    args = list(segment_args)
    while args and args[0] in {"-n", "-e", "-E"}:
        args = args[1:]
    if not args:
        return None
    decoded_parts = [decoded for decoded in (_decode_shell_text_literal(arg) for arg in args) if decoded]
    if not decoded_parts:
        return None
    return " ".join(decoded_parts)


def _cat_stdout_payloads(
    segment_args: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
) -> tuple[tuple[str, Path | None], ...]:
    payloads: list[tuple[str, Path | None]] = []
    consume_all = False
    read_roots = allowed_roots or _runtime_read_roots(cwd, home_dir)
    for token in segment_args:
        if token == "--":
            consume_all = True
            continue
        if not consume_all and token.startswith("-"):
            continue
        if token == "-":
            continue
        config_path = _resolved_runtime_path(token, cwd=cwd, home_dir=home_dir, allowed_roots=read_roots)
        if config_path is None:
            continue
        payload_text = _read_small_runtime_text_file(
            config_path,
            allowed_roots=read_roots,
        )
        if payload_text is None:
            continue
        payloads.append((payload_text, config_path.parent))
    return tuple(payloads)


def _cat_reads_local_file(
    segment_args: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    consume_all = False
    for token in segment_args:
        if token == "--":
            consume_all = True
            continue
        if not consume_all and token.startswith("-"):
            continue
        if token == "-":
            continue
        if _looks_like_local_stdin_source(token):
            return True
    return False


def _shell_stdin_redirect_payloads(
    segment: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
) -> tuple[tuple[str, Path | None], ...]:
    payloads: list[tuple[str, Path | None]] = []
    index = 0
    while index < len(segment):
        token = segment[index]
        if token == "<<<" and index + 1 < len(segment):
            payload_text = _decode_shell_text_literal(segment[index + 1])
            if payload_text:
                payloads.append((payload_text, cwd))
            index += 2
            continue
        if token.startswith("<<<"):
            payload_text = _decode_shell_text_literal(token[3:])
            if payload_text:
                payloads.append((payload_text, cwd))
            index += 1
            continue
        redirect_target, tokens_consumed = _stdin_redirect_target_from_token(
            token,
            next_token=segment[index + 1] if index + 1 < len(segment) else None,
        )
        if redirect_target is not None:
            redirect_payload = _stdin_redirect_payload(
                redirect_target,
                cwd=cwd,
                home_dir=home_dir,
                allowed_roots=allowed_roots,
            )
            if redirect_payload is not None:
                payloads.append(redirect_payload)
            index += tokens_consumed
            continue
        index += 1
    return tuple(payloads)


def _shell_stdin_redirect_uses_local_file(
    segment: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    index = 0
    while index < len(segment):
        token = segment[index]
        if token == "<" and index + 1 < len(segment):
            if _stdin_redirect_uses_local_file(segment[index + 1], cwd=cwd, home_dir=home_dir):
                return True
            index += 2
            continue
        redirect_target, tokens_consumed = _stdin_redirect_target_from_token(
            token,
            next_token=segment[index + 1] if index + 1 < len(segment) else None,
        )
        if redirect_target is not None and _stdin_redirect_uses_local_file(
            redirect_target,
            cwd=cwd,
            home_dir=home_dir,
        ):
            return True
        index += tokens_consumed if redirect_target is not None else 1
    return False


def _stdin_redirect_payload(
    target: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    allowed_roots: tuple[Path, ...] | None = None,
) -> tuple[str, Path | None] | None:
    read_roots = allowed_roots or _runtime_read_roots(cwd, home_dir)
    config_path = _resolved_runtime_path(target, cwd=cwd, home_dir=home_dir, allowed_roots=read_roots)
    if config_path is None:
        return None
    payload_text = _read_small_runtime_text_file(
        config_path,
        allowed_roots=read_roots,
    )
    if payload_text is None:
        return None
    return payload_text, config_path.parent


def _decode_shell_text_literal(value: str) -> str | None:
    stripped_value = _strip_cli_value(value)
    if not stripped_value:
        return None
    try:
        return bytes(stripped_value, "utf-8").decode("unicode_escape")
    except UnicodeDecodeError:
        return stripped_value


__all__ = [
    "_cat_reads_local_file",
    "_cat_stdout_payloads",
    "_decode_shell_text_literal",
    "_echo_stdout_payload",
    "_printf_stdout_payloads",
    "_shell_pipeline_stdin_payloads",
    "_shell_pipeline_stdin_uses_local_file",
    "_shell_segment_stdout_payloads",
    "_shell_segment_stdout_uses_local_file",
    "_shell_stdin_redirect_payloads",
    "_shell_stdin_redirect_uses_local_file",
    "_stdin_redirect_payload",
]
