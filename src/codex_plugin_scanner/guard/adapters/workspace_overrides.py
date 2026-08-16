"""Shared precedence checks for workspace-scoped MCP configuration."""

from __future__ import annotations

from typing import Protocol


class _HarnessContextLike(Protocol):
    @property
    def workspace_dir(self) -> object | None: ...


class _ManagedServerLike(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def source_scope(self) -> str: ...


def should_skip_workspace_override(
    *,
    context: _HarnessContextLike,
    server: _ManagedServerLike,
    existing_workspace_server_names: set[str],
    for_companion: bool = False,
) -> bool:
    """Return whether a workspace entry shadows the managed non-project server."""

    if context.workspace_dir is None:
        return False
    if server.source_scope == "project":
        return False
    if for_companion and server.source_scope == "global":
        return False
    return server.name in existing_workspace_server_names
