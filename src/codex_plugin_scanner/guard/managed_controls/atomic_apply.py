"""Atomic policy and Extension-control application with last-known-good state."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")


class AtomicApplyError(RuntimeError):
    """Raised without committing a partial Managed Controls state."""


@dataclass(frozen=True, slots=True)
class AppliedManagedControls(Generic[T]):
    revision: int
    bundle_hash: str
    catalog_digest: str
    effective_digest: str
    value: T


class AtomicManagedControlsStore(Generic[T]):
    def __init__(self, initial: AppliedManagedControls[T] | None = None) -> None:
        self._current = initial
        self._last_known_good = initial

    @property
    def current(self) -> AppliedManagedControls[T] | None:
        return self._current

    @property
    def last_known_good(self) -> AppliedManagedControls[T] | None:
        return self._last_known_good

    def apply(
        self,
        candidate: AppliedManagedControls[T],
        *,
        validate: Callable[[AppliedManagedControls[T]], None],
        compile_projection: Callable[[AppliedManagedControls[T]], None],
    ) -> AppliedManagedControls[T]:
        previous = self._current
        try:
            if previous is not None and candidate.revision <= previous.revision:
                raise AtomicApplyError("managed controls revision must increase")
            validate(candidate)
            compile_projection(candidate)
        except Exception as error:
            self._current = previous
            if isinstance(error, AtomicApplyError):
                raise
            raise AtomicApplyError("managed controls apply failed") from error
        self._current = candidate
        self._last_known_good = candidate
        return candidate

    def restore_last_known_good(self) -> AppliedManagedControls[T]:
        if self._last_known_good is None:
            raise AtomicApplyError("no last-known-good managed controls state")
        self._current = self._last_known_good
        return self._last_known_good
