"""This-device allow and block grants for unlisted CLIs."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from .models import GuardAction
from .runtime.local_cli_identity import UnlistedCliIdentity, identify_unlisted_cli

LocalCliGrantState = Literal["allowed", "blocked"]


@dataclass(frozen=True, slots=True)
class LocalCliGrant:
    cli_id: str
    identity_hash: str
    state: LocalCliGrantState
    revision: int
    updated_at: str


def matching_local_cli_grant(
    *,
    store: object,
    command: str,
    cwd: Path,
    home_dir: Path | None,
    current_action: GuardAction,
) -> tuple[UnlistedCliIdentity, LocalCliGrantState] | None:
    """Return an enrolled grant when the command matches an unlisted CLI identity."""

    if current_action not in {"review", "require-reapproval", "warn"}:
        return None
    identity = identify_unlisted_cli(command, cwd=cwd, home_dir=home_dir)
    if identity is None:
        return None
    lookup = getattr(store, "read_local_cli_grant", None)
    if not callable(lookup):
        return None
    grant = lookup(identity.cli_id)
    if not isinstance(grant, Mapping):
        return None
    raw_state = grant.get("state")
    identity_hash = grant.get("identity_hash")
    if raw_state != "allowed" and raw_state != "blocked":
        return None
    state: LocalCliGrantState = "allowed" if raw_state == "allowed" else "blocked"
    if identity_hash != identity.identity_hash:
        return None
    return identity, state


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
