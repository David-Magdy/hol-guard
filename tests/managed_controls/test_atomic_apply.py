from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.atomic_apply import (
    AppliedManagedControls,
    AtomicApplyError,
    AtomicManagedControlsStore,
)


def _state(revision: int, value: str) -> AppliedManagedControls[str]:
    return AppliedManagedControls(
        revision,
        f"bundle-{revision}",
        "catalog",
        f"effective-{revision}",
        value,
    )


def test_policy_and_extension_projection_commit_together() -> None:
    store = AtomicManagedControlsStore(_state(1, "old"))
    result = store.apply(
        _state(2, "new"),
        validate=lambda _: None,
        compile_projection=lambda _: None,
    )
    assert result.value == "new"
    assert store.last_known_good == result


def test_failed_second_projection_preserves_complete_previous_state() -> None:
    previous = _state(1, "old")
    store = AtomicManagedControlsStore(previous)

    def fail(_: AppliedManagedControls[str]) -> None:
        raise ValueError("compiler failed")

    with pytest.raises(AtomicApplyError):
        store.apply(_state(2, "new"), validate=lambda _: None, compile_projection=fail)
    assert store.current == previous
    assert store.last_known_good == previous


def test_revision_rollback_is_rejected() -> None:
    store = AtomicManagedControlsStore(_state(3, "current"))
    with pytest.raises(AtomicApplyError):
        store.apply(_state(2, "old"), validate=lambda _: None, compile_projection=lambda _: None)
