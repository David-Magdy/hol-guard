"""Independent Managed Controls rollout switches."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ManagedControlsFeatureFlags:
    authoring: bool = False
    compilation: bool = False
    delivery: bool = False
    enforcement: bool = False

    def validate(self) -> None:
        if self.enforcement and not self.compilation:
            raise ValueError("enforcement requires compilation")
        if self.delivery and not self.compilation:
            raise ValueError("delivery requires compilation")
