"""Drift classification for Local and Guard Cloud posture."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .acknowledgement import ManagedControlsAcknowledgement


class DriftState(StrEnum):
    CURRENT = "current"
    PENDING = "pending"
    CATALOG_MISMATCH = "catalog_mismatch"
    EFFECTIVE_MISMATCH = "effective_mismatch"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class ExpectedManagedControlsState:
    revision: int
    catalog_digest: str
    effective_digest: str


def classify_drift(
    expected: ExpectedManagedControlsState,
    acknowledgement: ManagedControlsAcknowledgement | None,
    *,
    supported: bool = True,
) -> DriftState:
    if not supported:
        return DriftState.UNSUPPORTED
    if acknowledgement is None or acknowledgement.revision < expected.revision:
        return DriftState.PENDING
    if acknowledgement.catalog_digest != expected.catalog_digest:
        return DriftState.CATALOG_MISMATCH
    if acknowledgement.effective_digest != expected.effective_digest:
        return DriftState.EFFECTIVE_MISMATCH
    return DriftState.CURRENT
