from __future__ import annotations

from codex_plugin_scanner.guard.managed_controls.delegation import (
    EnforcementPlane,
    compile_delegated_control,
    require_package_firewall_path,
)


def test_package_extension_compiles_through_package_firewall() -> None:
    control = compile_delegated_control(
        extension_id="package.npm",
        permission_id="install",
        delegated_protection="package-firewall",
        blocked=True,
    )
    assert control.enforcement_plane is EnforcementPlane.PACKAGE_FIREWALL
    require_package_firewall_path(control)


def test_command_extension_stays_on_command_plane() -> None:
    control = compile_delegated_control(
        extension_id="command.git",
        permission_id="push",
        delegated_protection=None,
        blocked=False,
    )
    assert control.enforcement_plane is EnforcementPlane.COMMAND
