"""Shared structural guards for proof-eligible command candidates."""

from __future__ import annotations

from .command_model import CanonicalCommand


def command_has_exact_plain_shell_shape(command: CanonicalCommand) -> bool:
    """Return whether a command has the exact, unwrapped POSIX shell shape."""

    return bool(command.segments) and all(
        (
            command.confidence == "exact",
            command.uncertainty_reason is None,
            command.dialect == "posix",
            command.transport == "shell_string",
            not command.wrapper_chain,
            not command.redirects,
            not command.embedded_commands,
            all(
                segment.execution_context.startswith("top:")
                and not segment.wrapper_chain
                and not segment.environment_names
                and not segment.path_overridden
                for segment in command.segments
            ),
        )
    )


__all__ = ["command_has_exact_plain_shell_shape"]
