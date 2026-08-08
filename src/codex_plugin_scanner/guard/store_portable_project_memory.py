"""GuardStore compatibility layer for portable project-scoped memory."""

# pyright: reportAttributeAccessIssue=false

from __future__ import annotations

from collections.abc import Mapping

from .action_lattice import guard_action_severity
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
_PORTABLE_PERMISSION_FLOOR = guard_action_severity("review")


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


def _portable_lookup_without_permission_elevation(
    lookup: PolicyDecisionLookupResult,
) -> PolicyDecisionLookupResult:
    """Keep portable selectors restrictive-only and never reuse one-shot authority.

    Git metadata lives inside the workspace and can be forged by that
    workspace. A portable selector is therefore useful for carrying managed
    restrictions across clones, but it cannot safely prove that a permissive
    approval belongs to the current local workspace. Local-path authority is
    the only source allowed to lower enforcement below review.
    """
    decision = lookup.get("decision")
    if not isinstance(decision, dict):
        return lookup
    if decision.get("approval_id") is not None or guard_action_severity(
        decision.get("action"),
        unknown_action="block",
    ) < _PORTABLE_PERMISSION_FLOOR:
        return {**lookup, "decision": None}
    return lookup


# Store mixins are composed dynamically in ``GuardStore``. Sibling mixins use
# the same file-level pyright setting because ``super()`` members are supplied
# by the final MRO rather than a direct base class.
class StorePortableProjectMemoryMixin:
    """Add restrictive portable Git project policy without weakening local scope."""

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
        if portable_workspace is None:
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

        # Portable Git metadata is classification, not authentication. Always
        # inspect portable authority without consuming it, then discard any
        # one-shot or permission-lowering decision before composition. This
        # prevents a forged repository identity from inheriting an allow/warn
        # or burning reusable one-shot authority belonging to another clone.
        portable_preview = _portable_lookup_without_permission_elevation(
            super().resolve_policy_decision_lookup(
                harness,
                artifact_id,
                artifact_hash=artifact_hash,
                workspace=portable_workspace,
                publisher=publisher,
                now=now,
                runtime_exact_match_context=runtime_exact_match_context,
                consume_one_shot=False,
            )
        )
        normalized_workspace = workspace.strip() if isinstance(workspace, str) else None
        if portable_workspace == normalized_workspace:
            return portable_preview

        local_lookup = super().resolve_policy_decision_lookup(
            harness,
            artifact_id,
            artifact_hash=artifact_hash,
            workspace=workspace,
            publisher=publisher,
            now=now,
            runtime_exact_match_context=runtime_exact_match_context,
            consume_one_shot=consume_one_shot,
        )
        return _most_restrictive_policy_lookup([local_lookup, portable_preview])

    @staticmethod
    def _portable_project_workspace(workspace: str | None) -> str | None:
        if not isinstance(workspace, str) or not workspace.strip():
            return None
        normalized = workspace.strip()
        return normalized if is_portable_project_identity(normalized) else _cached_portable_project_identity(normalized)
