"""Authority modes and disable-dominant Extension control composition."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class AuthorityMode(StrEnum):
    PERSONAL_SHARED = "personal-shared"
    WORKSPACE_SHARED = "workspace-shared"
    MANAGED_RESTRICTIVE = "managed-restrictive"


class ControlEffect(StrEnum):
    INHERIT = "inherit"
    PERMIT = "permit"
    BLOCK = "block"
    LOCKDOWN = "lockdown"


class AuthorityValidationError(ValueError):
    """Raised when an authority attempts an unsupported outcome."""


@dataclass(frozen=True, slots=True)
class ControlInstruction:
    extension_id: str | None
    permission_id: str | None
    effect: ControlEffect
    authority: AuthorityMode
    source_id: str

    def __post_init__(self) -> None:
        if self.effect is ControlEffect.LOCKDOWN:
            if self.extension_id is not None or self.permission_id is not None:
                raise AuthorityValidationError("lockdown cannot target a permission")
        elif not self.extension_id:
            raise AuthorityValidationError("extension id is required")
        if (
            self.authority is AuthorityMode.MANAGED_RESTRICTIVE
            and self.effect not in {ControlEffect.BLOCK, ControlEffect.LOCKDOWN}
        ):
            raise AuthorityValidationError(
                "managed-restrictive authority may only block or lock down"
            )


@dataclass(frozen=True, slots=True)
class EffectiveControl:
    effect: ControlEffect
    sources: tuple[str, ...]
    managed_floor: bool


def compose_control_instructions(
    instructions: tuple[ControlInstruction, ...],
) -> EffectiveControl:
    lockdown = [item for item in instructions if item.effect is ControlEffect.LOCKDOWN]
    if lockdown:
        return EffectiveControl(
            ControlEffect.LOCKDOWN,
            tuple(item.source_id for item in lockdown),
            any(
                item.authority is AuthorityMode.MANAGED_RESTRICTIVE
                for item in lockdown
            ),
        )
    blocks = [item for item in instructions if item.effect is ControlEffect.BLOCK]
    if blocks:
        return EffectiveControl(
            ControlEffect.BLOCK,
            tuple(item.source_id for item in blocks),
            any(
                item.authority is AuthorityMode.MANAGED_RESTRICTIVE
                for item in blocks
            ),
        )
    permits = [item for item in instructions if item.effect is ControlEffect.PERMIT]
    if permits:
        return EffectiveControl(
            ControlEffect.PERMIT,
            tuple(item.source_id for item in permits),
            False,
        )
    return EffectiveControl(ControlEffect.INHERIT, (), False)
