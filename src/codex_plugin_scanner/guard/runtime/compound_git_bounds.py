"""Bound validation for read-only Git inspection pipelines."""

from __future__ import annotations

from .shell_execution_context import ShellExecutionSegment

_MAX_OUTPUT_LINES = 1000


def safe_bound_segment(segment: ShellExecutionSegment, *, previous: ShellExecutionSegment) -> bool:
    if segment.control_before != ("|",) or len(segment.tokens) != 2:
        return False
    if not previous.tokens or previous.tokens[0] != "git" or previous.control_after != ("|",):
        return False
    count = segment.tokens[1]
    if not count.startswith("-") or not count[1:].isdigit():
        return False
    return 1 <= int(count[1:]) <= _MAX_OUTPUT_LINES
