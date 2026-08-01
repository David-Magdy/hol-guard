"""Local read operand extraction and containment checks."""

from __future__ import annotations

import os
import re
from pathlib import Path

from .read_only_filters import _read_only_lookup_target_is_safe


def _shell_segment_file_operand_tokens(segment: list[str]) -> tuple[str, ...]:
    if not segment:
        return ()
    command_name = Path(segment[0]).name.lower()
    args = segment[1:]
    if command_name == "cat":
        return _cat_file_operand_tokens(args)
    if command_name in {"head", "tail"}:
        return _plain_file_operand_tokens(args)
    if command_name == "sed":
        return _sed_file_operand_tokens(args)
    if command_name in {"grep", "egrep", "fgrep", "rg"}:
        return _search_file_operand_tokens(command_name, args)
    return ()


def _local_read_operands_resolve_safely(
    command_name: str,
    args: list[str],
    *,
    cwd: Path,
    root: Path,
) -> bool:
    """Reject local read operands redirected through symlink path components."""

    allow_dirs = command_name in {"grep", "egrep", "fgrep", "rg"}
    try:
        resolved_root = root.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    for operand in _shell_segment_file_operand_tokens([command_name, *args]):
        stripped = operand.strip().strip("'\"")
        if not stripped or stripped == "-":
            continue
        has_glob_metacharacter = any(character in stripped for character in "*?[")
        candidate = Path(stripped)
        if not candidate.is_absolute():
            candidate = cwd / candidate
        if has_glob_metacharacter:
            if not _bounded_local_read_glob_is_safe(
                candidate,
                root=root,
                allow_dirs=allow_dirs,
            ):
                return False
            continue
        try:
            lexical = Path(os.path.abspath(os.fspath(candidate)))
            resolved = candidate.resolve(strict=True)
            relative = resolved.relative_to(resolved_root)
        except FileNotFoundError:
            continue
        except (OSError, RuntimeError, ValueError):
            return False
        safe_git_pointer = command_name == "cat" and relative.as_posix() == ".git"
        if resolved != lexical or (
            not safe_git_pointer
            and not _read_only_lookup_target_is_safe(
                relative.as_posix(),
                allow_dirs=allow_dirs and resolved.is_dir(),
                home_dir=root,
            )
        ):
            return False
    return True


def _bounded_local_read_glob_is_safe(
    candidate: Path,
    *,
    root: Path,
    allow_dirs: bool,
) -> bool:
    """Accept one-level read globs only when every match is a safe in-root target."""

    pattern = candidate.name
    pattern_match = re.fullmatch(r"([A-Za-z0-9_.-]+)\*", pattern)
    if pattern_match is None or any(character in os.fspath(candidate.parent) for character in "*?["):
        return False
    literal_prefix = pattern_match.group(1)
    try:
        root_resolved = root.resolve(strict=True)
        lexical_parent = Path(os.path.abspath(os.fspath(candidate.parent)))
        resolved_parent = candidate.parent.resolve(strict=True)
        resolved_parent.relative_to(root_resolved)
    except (FileNotFoundError, OSError, RuntimeError, ValueError):
        return False
    if resolved_parent != lexical_parent:
        return False
    matches: list[Path] = []
    try:
        entries_seen = 0
        for match in resolved_parent.iterdir():
            entries_seen += 1
            if entries_seen > 4096:
                return False
            if not match.name.casefold().startswith(literal_prefix.casefold()):
                continue
            matches.append(match)
            if len(matches) > 128:
                return False
    except (OSError, RuntimeError, ValueError):
        return False
    for match in matches:
        if match.name.startswith("-"):
            return False
        try:
            if match.is_symlink():
                return False
            lexical = Path(os.path.abspath(os.fspath(match)))
            resolved = match.resolve(strict=True)
            relative = resolved.relative_to(root_resolved)
        except (FileNotFoundError, OSError, RuntimeError, ValueError):
            return False
        if resolved != lexical or not _read_only_lookup_target_is_safe(
            relative.as_posix(),
            allow_dirs=allow_dirs and resolved.is_dir(),
            home_dir=root,
        ):
            return False
    return True


def _cat_file_operand_tokens(args: list[str]) -> tuple[str, ...]:
    operands: list[str] = []
    after_options = False
    for arg in args:
        if after_options:
            operands.append(arg)
            continue
        if arg == "--":
            after_options = True
            continue
        if arg == "-":
            continue
        if arg.startswith("-"):
            continue
        operands.append(arg)
    return tuple(operands)


def _plain_file_operand_tokens(args: list[str]) -> tuple[str, ...]:
    operands: list[str] = []
    skip_next = False
    after_options = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if after_options:
            operands.append(arg)
            continue
        if arg == "--":
            after_options = True
            continue
        if arg in {"-n", "--lines", "-c", "--bytes"}:
            skip_next = True
            continue
        if arg.startswith("--lines=") or arg.startswith("--bytes=") or re.fullmatch(r"-\d{1,6}", arg):
            continue
        if arg.startswith("-"):
            continue
        operands.append(arg)
    return tuple(operands)


def _sed_file_operand_tokens(args: list[str]) -> tuple[str, ...]:
    operands: list[str] = []
    scripts_seen = 0
    skip_script = False
    after_options = False
    for arg in args:
        if skip_script:
            skip_script = False
            scripts_seen += 1
            continue
        if after_options:
            operands.append(arg)
            continue
        if arg == "--":
            after_options = True
            continue
        if arg in {"-n", "--quiet", "--silent"}:
            continue
        if arg in {"-e", "--expression"}:
            skip_script = True
            continue
        if arg.startswith("-e") and len(arg) > 2:
            scripts_seen += 1
            continue
        if arg.startswith("--expression="):
            scripts_seen += 1
            continue
        if arg.startswith("-"):
            continue
        if scripts_seen == 0:
            scripts_seen += 1
            continue
        operands.append(arg)
    return tuple(operands)


def _search_file_operand_tokens(command_name: str, args: list[str]) -> tuple[str, ...]:
    operands: list[str] = []
    pattern_seen = False
    skip_next = False
    skip_next_is_operand = False
    after_options = False
    for arg in args:
        if skip_next:
            if skip_next_is_operand:
                operands.append(arg)
            skip_next = False
            skip_next_is_operand = False
            continue
        if after_options:
            operands.append(arg)
            continue
        if arg == "--":
            after_options = True
            continue
        if arg in {
            "-A",
            "-B",
            "-C",
            "-e",
            "-f",
            "-g",
            "-m",
            "-t",
            "--after-context",
            "--before-context",
            "--context",
            "--exclude",
            "--exclude-dir",
            "--file",
            "--glob",
            "--iglob",
            "--include",
            "--max-count",
            "--max-depth",
            "--max-filesize",
            "--regexp",
            "--type",
            "--type-not",
        }:
            skip_next = True
            skip_next_is_operand = command_name in {"grep", "egrep", "fgrep"} and arg == "--include"
            if command_name == "rg" and arg in {"-g", "--glob", "--iglob"}:
                skip_next_is_operand = True
            if arg in {"-e", "--regexp", "-f", "--file"}:
                pattern_seen = True
            continue
        search_value_flags = (
            "--after-context",
            "--before-context",
            "--context",
            "--exclude",
            "--exclude-dir",
            "--file",
            "--glob",
            "--iglob",
            "--include",
            "--max-count",
            "--max-depth",
            "--max-filesize",
            "--regexp",
            "--type",
            "--type-not",
        )
        if any(arg.startswith(f"{flag}=") for flag in search_value_flags):
            if command_name in {"grep", "egrep", "fgrep"} and arg.startswith("--include="):
                operands.append(arg.split("=", 1)[1])
                continue
            if command_name == "rg" and any(arg.startswith(f"{flag}=") for flag in ("--glob", "--iglob")):
                operands.append(arg.split("=", 1)[1])
                continue
            if arg.startswith(("--regexp=", "--file=")):
                pattern_seen = True
            continue
        option_value_prefixes = ("-A", "-B", "-C", "-m")
        if any(arg.startswith(prefix) and len(arg) > len(prefix) for prefix in option_value_prefixes):
            continue
        if command_name == "rg" and arg.startswith("-g") and len(arg) > 2:
            operands.append(arg[2:])
            continue
        if arg.startswith("-e") and len(arg) > 2:
            pattern_seen = True
            continue
        if arg.startswith("-"):
            continue
        if not pattern_seen:
            pattern_seen = True
            continue
        operands.append(arg)
    return tuple(operands)


__all__ = [
    "_bounded_local_read_glob_is_safe",
    "_cat_file_operand_tokens",
    "_local_read_operands_resolve_safely",
    "_plain_file_operand_tokens",
    "_search_file_operand_tokens",
    "_sed_file_operand_tokens",
    "_shell_segment_file_operand_tokens",
]
