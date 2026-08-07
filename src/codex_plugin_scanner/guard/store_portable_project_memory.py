"""GuardStore compatibility layer for portable project-scoped memory."""

# pyright: reportAttributeAccessIssue=false

from __future__ import annotations

from collections.abc import Mapping

from .project_identity import (
    enrich_project_identity_metadata,
    is_portable_project_identity,
    portable_project_identity_revision,
    resolve_portable_project_identity,
)
from .store_base import PolicyDecisionLookupResult
from .store_policy import _most_restrictive_policy_lookup

_PROJECT_IDENTITY_CACHE_MAX_ITEMS = 128
_PROJECT_IDENTITY_CACHE: dict[tuple[str, int], str] = {}


def _cached_portable_project_identity(workspace: str) -> str | None:
    """Cache only successful identities and invalidate on any identity metadata change."""
    revision = portable_project_identity_revision(workspace)
    if revision is None:
        return resolve_portable_project_identity(workspace)
    cache_key = (workspace, revision)
    cached = _PROJECT_IDENTITY_CACHE.get(cache_key)
    if cached is not None:
        return cached

    identity = resolve_portable_project_identity(workspace)
    if identity is None:
        return None

    stale_keys = [key for key in _PROJECT_IDENTITY_CACHE if key[0] == workspace]
    for stale_key in stale_keys:
        _PROJECT_IDENTITY_CACHE.pop(stale_key, None)
    if len(_PROJECT_IDENTITY_CACHE) >= _PROJECT_IDENTITY_CACHE_MAX_ITEMS:
        oldest_key = next(iter(_PROJECT_IDENTITY_CACHE))
        _PROJECT_IDENTITY_CACHE.pop(oldest_key, None)
    _PROJECT_IDENTITY_CACHE[cache_key] = identity
    return identity


# Store mixins are composed dynamically in ``GuardStore``. Sibling mixins use
# the same file-level pyright setting because ``super()`` members are supplied
# by the final MRO rather than a direct base class.
class StorePortableProjectMemoryMixin:
    """Add a portable Git project selector without removing local path scope."""

    def get_guard_operation_for_approval_request(self, request_id: str) -> dict[str, object] | None:
        operation = super().get_guard_operation_for_approval_request(request_id)
        if not isinstance(operation, dict):
            return operation
        metadata = operation.get("metadata")
        if not isinstance(metadata, Mapping):
            return operation
        return {
            **operation,
            "metadata": enrich_project_identity_metadata(metadata),
        }

    def resolve_policy_decision_lookup(
        self,
        harness: str,
        artifact_id: str | None,
        artifact_hash: str | None = None,
        workspace: str | None = None,
        publisher: str | None = None,
        now: str | None = None,
        runtime_exact_match_context: str | None = None,
        consume_one_shot: bool = True,
    ) -> PolicyDecisionLookupResult:
        portable_workspace = self._portable_project_workspace(workspace)
        normalized_workspace = workspace.strip() if isinstance(workspace, str) else None
        if portable_workspace is None or portable_workspace == normalized_workspace:
            return super().resolve_policy_decision_lookup(
                harness,
                artifact_id,
                artifact_hash=artifact_hash,
                workspace=workspace,
                publisher=publisher,
                now=now,
                runtime_exact_match_context=runtime_exact_match_context,
                consume_one_shot=consume_one_shot,
            )

        if not consume_one_shot:
            local_preview = super().resolve_policy_decision_lookup(
                harness,
                artifact_id,
                artifact_hash=artifact_hash,
                workspace=workspace,
                publisher=publisher,
                now=now,
                runtime_exact_match_context=runtime_exact_match_context,
                consume_one_shot=False,
            )
            portable_preview = super().resolve_policy_decision_lookup(
                harness,
                artifact_id,
                artifact_hash=artifact_hash,
                workspace=portable_workspace,
                publisher=publisher,
                now=now,
                runtime_exact_match_context=runtime_exact_match_context,
                consume_one_shot=False,
            )
            return _most_restrictive_policy_lookup([local_preview, portable_preview])

        # Both selectors describe the same attempted operation. Consume any
        # matching one-shot authority on both selectors before composing the
        # result so an equal or weaker approval cannot leak into a later action.
        live_local = super().resolve_policy_decision_lookup(
            harness,
            artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            runtime_exact_match_context=runtime_exact_match_context,
            consume_one_shot=True,
        )
        live_portable = super().resolve_policy_decision_lookup(
            harness,
            artifact_id,
            artifact_hash=artifact_hash,
            workspace=portable_workspace,
            publisher=publisher,
            now=now,
            runtime_exact_match_context=runtime_exact_match_context,
            consume_one_shot=True,
        )
        return _most_restrictive_policy_lookup([live_local, live_portable])

    @staticmethod
    def _portable_project_workspace(workspace: str | None) -> str | None:
        if not isinstance(workspace, str) or not workspace.strip():
            return None
        normalized = workspace.strip()
        return normalized if is_portable_project_identity(normalized) else _cached_portable_project_identity(normalized)
