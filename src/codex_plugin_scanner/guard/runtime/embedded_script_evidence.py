"""Structured audit evidence for scripts embedded in shell commands.

Heredoc bodies are already retained verbatim in the receipt envelope's
``envelope_full_json`` command text. These helpers add a hash-addressed index
over each embedded script so audits can locate, count, and verify the bodies
without re-parsing opaque envelope JSON, and so denial messages can tell
agents how to make one-off scripts auditable.
"""

from __future__ import annotations

import hashlib

from .command_model import parse_shell_command
from .command_tokens import executable_name
from .shell_structure import extract_heredocs

EMBEDDED_SCRIPT_EVIDENCE_SOURCE = "embedded_script"

# Executables that consume a heredoc body as code. Mirrors the parser's
# shell-only ``EmbeddedCommand`` semantics, extended to script interpreters;
# audit-classification only, never policy classification.
_SCRIPT_EXECUTING_EXECUTABLES = frozenset(
    {
        "ash",
        "bash",
        "bun",
        "dash",
        "deno",
        "node",
        "perl",
        "php",
        "python",
        "python3",
        "ruby",
        "sh",
        "zsh",
    }
)

_HEREDOC_DATA_EXECUTABLES = frozenset({"cat", "tee"})

EMBEDDED_SCRIPT_REMEDIATION_GUIDANCE = (
    "Put the script in a workspace file and run it by path so HOL Guard can audit it."
)

_MAX_EMBEDDED_SCRIPT_EVIDENCE_ENTRIES = 8


def embedded_script_evidence_entries(command_text: str | None) -> list[dict[str, object]]:
    """Return bounded scanner-evidence entries for each heredoc script body.

    Each entry carries the body hash, size, source span, and whether the body
    is executed (fed to an interpreter) or written to a file. The body itself
    is not duplicated; it remains in the retained envelope command text and is
    addressable via the span and sha256.
    """
    if not isinstance(command_text, str) or not command_text.strip():
        return []
    heredocs = extract_heredocs(command_text)
    if not heredocs:
        return []
    try:
        parsed = parse_shell_command(command_text)
    except (ValueError, RecursionError):
        parsed = None
    if parsed is not None:
        segment_owners = tuple(
            (segment.start, segment.end, executable_name(segment.executable) or "") for segment in parsed.segments
        )
    else:
        segment_owners = ()
    entries: list[dict[str, object]] = []
    for index, heredoc in enumerate(heredocs[:_MAX_EMBEDDED_SCRIPT_EVIDENCE_ENTRIES]):
        body = heredoc.body
        body_bytes = body.encode("utf-8")
        owner_executable = next(
            (executable for start, end, executable in segment_owners if start <= heredoc.operator_start <= end),
            None,
        )
        if owner_executable in _SCRIPT_EXECUTING_EXECUTABLES:
            executed: bool | None = True
            execution_status = "executed"
        elif owner_executable in _HEREDOC_DATA_EXECUTABLES:
            executed = False
            execution_status = "not_executed"
        else:
            executed = None
            execution_status = "indeterminate"
        entries.append(
            {
                "source": EMBEDDED_SCRIPT_EVIDENCE_SOURCE,
                "kind": "heredoc",
                "index": index,
                "delimiter": heredoc.delimiter,
                "quoted": heredoc.quoted,
                "executable": owner_executable,
                "executed": executed,
                "execution_status": execution_status,
                "sha256": hashlib.sha256(body_bytes).hexdigest(),
                "bytes": len(body_bytes),
                "lines": body.count("\n") + (1 if body and not body.endswith("\n") else 0),
                "span": {"start": heredoc.body_start, "end": heredoc.body_end},
            }
        )
    if len(heredocs) > _MAX_EMBEDDED_SCRIPT_EVIDENCE_ENTRIES:
        entries.append(
            {
                "source": EMBEDDED_SCRIPT_EVIDENCE_SOURCE,
                "kind": "summary",
                "truncated": True,
                "total_heredocs": len(heredocs),
            }
        )
    return entries


def command_has_embedded_script(command_text: str | None) -> bool:
    """True when the command carries an inline script body via heredoc."""
    return isinstance(command_text, str) and bool(extract_heredocs(command_text))
