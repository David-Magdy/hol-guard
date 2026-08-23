"""Delegated enforcement compilation for Package Firewall Extensions."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class EnforcementPlane(StrEnum):
    COMMAND = "command"
    PACKAGE_FIREWALL = "package_firewall"


class DelegationError(ValueError):
    """Raised when delegated protection is compiled into the wrong plane."""


@dataclass(frozen=True, slots=True)
class CompiledExtensionControl:
    extension_id: str
    permission_id: str | None
    blocked: bool
    enforcement_plane: EnforcementPlane


def compile_delegated_control(
    *,
    extension_id: str,
    permission_id: str | None,
    delegated_protection: str | None,
    blocked: bool,
) -> CompiledExtensionControl:
    if delegated_protection == "package-firewall":
        plane = EnforcementPlane.PACKAGE_FIREWALL
    elif delegated_protection is None:
        plane = EnforcementPlane.COMMAND
    else:
        raise DelegationError("unsupported delegated protection")
    return CompiledExtensionControl(
        extension_id,
        permission_id,
        blocked,
        plane,
    )


def require_package_firewall_path(control: CompiledExtensionControl) -> None:
    if control.enforcement_plane is not EnforcementPlane.PACKAGE_FIREWALL:
        raise DelegationError("package control did not use Package Firewall")
