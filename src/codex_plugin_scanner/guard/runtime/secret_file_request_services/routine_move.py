"""Conservative classification for routine local filesystem moves."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .request_models import classify_sensitive_path
from .shell_tokenization import _iter_shell_command_segments, _shell_segment_primary_command

_UNSAFE_PATH_CHARACTERS = frozenset("*?[]{}$`\n\r")
_SENSITIVE_DIRECTORY_NAMES = frozenset({".aws", ".codex", ".docker", ".hol-guard", ".kube", ".ssh"})
_GENERATED_DIRECTORY_NAMES = frozenset({".cache", ".next", "build", "coverage", "dist"})


def _looks_like_safe_routine_move(
    parts: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    """Return whether a single ``mv`` is a bounded, non-overwriting rename."""
    if cwd is None:
        return False
    segments = _iter_shell_command_segments(parts)
    if len(segments) != 1:
        return False
    segment = segments[0]
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name != "mv" or command_index != 0:
        return False
    operands = segment[command_index + 1 :]
    if operands[:1] == ["--"]:
        operands = operands[1:]
    if len(operands) != 2 or any(operand.startswith("-") for operand in operands):
        return False
    source_text, destination_text = operands
    if not _move_operand_is_static(source_text) or not _move_operand_is_static(destination_text):
        return False
    if classify_sensitive_path(source_text, cwd=cwd, home_dir=home_dir) is not None:
        return False
    if classify_sensitive_path(destination_text, cwd=cwd, home_dir=home_dir) is not None:
        return False

    source_candidate = _move_operand_candidate(source_text, cwd=cwd, home_dir=home_dir)
    destination_candidate = _move_operand_candidate(destination_text, cwd=cwd, home_dir=home_dir)
    if source_candidate is None or destination_candidate is None or os.path.lexists(destination_candidate):
        return False
    source = _resolve_move_candidate(source_candidate, strict=True)
    destination = _resolve_move_candidate(destination_candidate, strict=False)
    if source is None or destination is None or destination.exists():
        return False
    if _path_contains_sensitive_directory(source) or _path_contains_sensitive_directory(destination):
        return False
    try:
        _ = destination_candidate.parent.resolve(strict=True)
    except (OSError, RuntimeError):
        return False
    workspace = cwd.resolve()
    if source == workspace or destination == workspace:
        return False
    if _path_is_within(source, workspace) and _path_is_within(destination, workspace):
        return True
    temporary_root = Path(tempfile.gettempdir()).resolve()
    return (
        source.name in _GENERATED_DIRECTORY_NAMES
        and _path_is_within(source, workspace)
        and _path_is_within(destination, temporary_root)
    )


def _move_operand_is_static(operand: str) -> bool:
    return (
        bool(operand)
        and "..." not in operand
        and not any(character in operand for character in _UNSAFE_PATH_CHARACTERS)
    )


def _path_contains_sensitive_directory(path: Path) -> bool:
    return any(part.lower() in _SENSITIVE_DIRECTORY_NAMES for part in path.parts)


def _move_operand_candidate(
    operand: str,
    *,
    cwd: Path,
    home_dir: Path | None,
) -> Path | None:
    candidate = Path(operand)
    if operand == "~" or operand.startswith("~/"):
        if home_dir is None:
            return None
        candidate = home_dir / operand.removeprefix("~/") if operand != "~" else home_dir
    elif not candidate.is_absolute():
        candidate = cwd / candidate
    return candidate


def _resolve_move_candidate(candidate: Path, *, strict: bool) -> Path | None:
    try:
        return candidate.resolve(strict=strict)
    except (OSError, RuntimeError):
        return None


def _path_is_within(path: Path, boundary: Path) -> bool:
    try:
        _ = path.relative_to(boundary)
    except ValueError:
        return False
    return True


__all__ = ["_looks_like_safe_routine_move"]
