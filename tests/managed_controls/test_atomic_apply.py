from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.atomic_apply import (
    AppliedManagedControls,
    AtomicApplyError,
    AtomicManagedControlsStore,
    PreparedProjection,
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
        compile_projection=lambda _: PreparedProjection(lambda: None, lambda: None),
    )
    assert result.value == "new"
    assert store.last_known_good == result


def test_failed_second_projection_preserves_complete_previous_state() -> None:
    previous = _state(1, "old")
    store = AtomicManagedControlsStore(previous)

    def fail(_: AppliedManagedControls[str]) -> PreparedProjection:
        raise ValueError("compiler failed")

    with pytest.raises(AtomicApplyError):
        store.apply(_state(2, "new"), validate=lambda _: None, compile_projection=fail)
    assert store.current == previous
    assert store.last_known_good == previous


def test_revision_rollback_is_rejected() -> None:
    store = AtomicManagedControlsStore(_state(3, "current"))
    with pytest.raises(AtomicApplyError):
        store.apply(
            _state(2, "old"),
            validate=lambda _: None,
            compile_projection=lambda _: PreparedProjection(lambda: None, lambda: None),
        )


def test_failed_commit_rolls_back_external_projection() -> None:
    previous = _state(1, "old")
    store = AtomicManagedControlsStore(previous)
    external = ["old"]

    def stage(_: AppliedManagedControls[str]) -> PreparedProjection:
        def commit() -> None:
            external.append("partial")
            raise ValueError("second projection failed")

        def rollback() -> None:
            external[:] = ["old"]

        return PreparedProjection(commit, rollback)

    with pytest.raises(AtomicApplyError):
        store.apply(_state(2, "new"), validate=lambda _: None, compile_projection=stage)
    assert external == ["old"]
    assert store.current == previous


def test_initial_negative_revision_is_rejected() -> None:
    with pytest.raises(AtomicApplyError):
        _state(-1, "invalid")
