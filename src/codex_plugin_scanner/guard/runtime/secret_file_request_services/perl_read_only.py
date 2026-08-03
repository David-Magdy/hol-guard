"""Read-only Perl filter validation."""

from __future__ import annotations

import os
import re
import shlex
import shutil
from pathlib import Path

from ..git_execution_safety import git_binary_path_is_trusted
from .request_models import classify_sensitive_path
from .shell_static_safety import _shell_token_has_command_substitution


def _looks_like_read_only_perl_filter(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    """Accept only Perl's read loop with a literal print-if-regex program."""

    try:
        tokens = shlex.split(command_text, posix=True)
    except ValueError:
        return False
    if len(tokens) < 4 or Path(tokens[0]).name.casefold() != "perl":
        return False
    if cwd is None or home_dir is None or not _perl_execution_environment_is_safe():
        return False
    if not _trusted_perl_command(tokens[0], cwd=cwd):
        return False
    if tokens[1] == "-ne":
        script_index = 2
    elif len(tokens) >= 5 and tokens[1:3] == ["-n", "-e"]:
        script_index = 3
    else:
        return False
    pattern = _perl_print_if_pattern(tokens[script_index])
    if pattern is None:
        return False
    if (
        len(pattern) > 4096
        or any(marker in pattern for marker in ("(?{", "(??{", "${", "`"))
        or re.search(r"(?<!\\)(?:\\\\)*@", pattern) is not None
        or re.search(r"(?<!\\)(?:\\\\)*\$(?!$|[)|])", pattern) is not None
    ):
        return False
    operands = tokens[script_index + 1 :]
    if not operands:
        return False
    try:
        workspace = cwd.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    for operand in operands:
        if (
            operand == "-"
            or operand.startswith(("-", "~"))
            or "$" in operand
            or any(character in operand for character in ("|", "<", ">", "\n", "\x00"))
            or _shell_token_has_command_substitution(operand)
        ):
            return False
        candidate = Path(operand)
        target = candidate if candidate.is_absolute() else workspace / candidate
        try:
            resolved = target.resolve(strict=True)
        except (OSError, RuntimeError):
            return False
        if (
            target.is_symlink()
            or not resolved.is_relative_to(workspace)
            or not resolved.is_file()
            or classify_sensitive_path(str(resolved), cwd=workspace, home_dir=home_dir) is not None
        ):
            return False
    return True


def _perl_execution_environment_is_safe() -> bool:
    return not any(
        os.environ.get(key, "").strip()
        for key in ("PERL5DB", "PERL5LIB", "PERL5OPT", "PERLIO", "PERLIO_DEBUG", "PERLLIB")
    )


def _trusted_perl_command(command: str, *, cwd: Path) -> bool:
    path_entries: list[str] = []
    for entry in os.environ.get("PATH", os.defpath).split(os.pathsep):
        candidate = Path(entry or ".").expanduser()
        if not candidate.is_absolute():
            candidate = cwd / candidate
        path_entries.append(str(candidate))
    located = shutil.which("perl", path=os.pathsep.join(path_entries))
    if located is None:
        return False
    try:
        resolved = Path(located).resolve(strict=True)
        requested = Path(command)
        if requested.name != command:
            requested_path = requested if requested.is_absolute() else cwd / requested
            if requested_path.resolve(strict=True) != resolved:
                return False
    except (OSError, RuntimeError):
        return False
    return git_binary_path_is_trusted(resolved, cwd=cwd)


def _perl_print_if_pattern(script: str) -> str | None:
    prefix = "print if /"
    if not script.startswith(prefix):
        return None
    escaped = False
    pattern: list[str] = []
    for index, character in enumerate(script[len(prefix) :], start=len(prefix)):
        if escaped:
            pattern.append(character)
            escaped = False
            continue
        if character == "\\":
            pattern.append(character)
            escaped = True
            continue
        if character != "/":
            pattern.append(character)
            continue
        flags = script[index + 1 :]
        return "".join(pattern) if re.fullmatch(r"[imsx]*", flags) is not None else None
    return None


__all__ = [
    "_looks_like_read_only_perl_filter",
    "_perl_execution_environment_is_safe",
    "_perl_print_if_pattern",
    "_trusted_perl_command",
]
