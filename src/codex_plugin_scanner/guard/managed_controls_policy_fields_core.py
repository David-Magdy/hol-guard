"""Strict HOL Guard Managed Controls policy-field parsing and shared posture projection."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, TypeGuard, cast

from .runtime.command_extensions import CommandSafetyExtensionRegistry
from .runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from .runtime.extension_control_limits import (
    MAX_CONTROLS_PER_LAYER,
    MAX_CONTROL_SET_TARGETS,
)

HOL_EXTENSION_CONTROLS_FIELD: Final = "x-hol-extension-controls"
HOL_EXTENSION_TARGETS_FIELD: Final = "x-hol-extension-targets"
HOL_EXTENSION_CONTROLS_SCHEMA_VERSION: Final = "guard.extension-controls.v1"
HOL_EXTENSION_TARGETS_SCHEMA_VERSION: Final = "guard.policy-extension-targets.v1"

EXTENSION_CONTROL_LAYER_CAPABILITY: Final = "extension-control-layer.v1"
POLICY_EXTENSION_TARGETS_CAPABILITY: Final = "policy-extension-targets.v1"
MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY: Final = "managed-controls-atomic-apply.v1"
PACKAGE_FIREWALL_CAPABILITY: Final = "package-firewall.v1"

_LEGACY_CAPABILITY_ALIASES: Final = {
    EXTENSION_CONTROL_LAYER_CAPABILITY: frozenset({"guard.managed-extension-controls.v1"}),
    POLICY_EXTENSION_TARGETS_CAPABILITY: frozenset({"guard.policy-extension-targets.v1"}),
    MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY: frozenset({"guard.managed-controls-atomic-apply.v1"}),
}
_AUTHORITY_MODES: Final = frozenset({"personal-shared", "workspace-shared", "managed-restrictive"})
_SHARED_AUTHORITY_MODES: Final = frozenset({"personal-shared", "workspace-shared"})
_CONTROL_STATES: Final = frozenset({"enabled", "disabled"})
_TARGET_KINDS: Final = frozenset({"extension", "permission"})
_EXTENSION_ID: Final = re.compile(r"^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*$")
_PERMISSION_ID: Final = re.compile(
    r"^command\.[a-z0-9]+(?:[.-][a-z0-9]+)*\.permission\.[a-z0-9]+(?:[.-][a-z0-9]+)*$"
)


class ManagedControlsPolicyError(ValueError):
    """Bounded parser failure with a stable reason code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class ExtensionRuleTargets:
    rule_id: str
    extension_ids: tuple[str, ...]
    permission_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DelegatedExtensionTarget:
    target: ControlTarget
    enforcement_owner: str = "package-firewall"


@dataclass(frozen=True, slots=True)
class ParsedManagedControlsPolicy:
    authority_mode: str | None
    signed_cloud_layer: ExtensionControlLayer | None
    managed_controls: tuple[ExtensionControl, ...]
    managed_global_lockdown: bool
    rule_targets: tuple[ExtensionRuleTargets, ...]
    delegated_targets: tuple[DelegatedExtensionTarget, ...]

    @property
    def has_extension_semantics(self) -> bool:
        return bool(
            self.signed_cloud_layer
            or self.managed_controls
            or self.managed_global_lockdown
            or self.rule_targets
            or self.delegated_targets
        )


def _is_mapping(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in cast(dict[object, object], value))


def _mapping(value: object, *, code: str, label: str) -> dict[str, object]:
    if not _is_mapping(value):
        raise ManagedControlsPolicyError(code, f"{label} must be an object.")
    return value


def _exact_keys(value: dict[str, object], allowed: frozenset[str], *, label: str) -> None:
    if any(key not in allowed for key in value):
        raise ManagedControlsPolicyError("unknown_field", f"{label} contains an unknown field.")


def _canonical_extension_id(value: object) -> str:
    if not isinstance(value, str) or len(value) > 256 or _EXTENSION_ID.fullmatch(value) is None:
        raise ManagedControlsPolicyError("invalid_extension_id", "Extension ID is not canonical.")
    if ".permission." in value:
        raise ManagedControlsPolicyError("invalid_extension_id", "Extension ID cannot be a permission ID.")
    return value


def _canonical_permission_id(value: object) -> str:
    if not isinstance(value, str) or len(value) > 256 or _PERMISSION_ID.fullmatch(value) is None:
        raise ManagedControlsPolicyError("invalid_permission_id", "Permission ID is not canonical.")
    return value


def _capability_present(capabilities: frozenset[str], capability: str) -> bool:
    return capability in capabilities or bool(_LEGACY_CAPABILITY_ALIASES.get(capability, frozenset()) & capabilities)


def _require_capabilities(
    capabilities: frozenset[str],
    *,
    controls_present: bool,
    targets_present: bool,
) -> None:
    required = {MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY}
    if controls_present:
        required.add(EXTENSION_CONTROL_LAYER_CAPABILITY)
    if targets_present:
        required.add(POLICY_EXTENSION_TARGETS_CAPABILITY)
    missing = sorted(capability for capability in required if not _capability_present(capabilities, capability))
    if missing:
        raise ManagedControlsPolicyError(
            "unnegotiated_extension_semantics",
            "Extension enforcement fields require negotiated capabilities: " + ", ".join(missing),
        )


def _target_extension(target: ControlTarget, registry: CommandSafetyExtensionRegistry):
    if target.kind is ControlTargetKind.EXTENSION:
        extension = registry.get(target.target_id)
        if extension is None or extension.extension_id != target.target_id:
            raise ManagedControlsPolicyError(
                "unknown_extension_target", "Extension target is not in the current catalog."
            )
        return extension
    permission = registry.permission(target.target_id)
    if permission is None or permission.permission_id != target.target_id:
        raise ManagedControlsPolicyError(
            "unknown_permission_target", "Permission target is not in the current catalog."
        )
    extension = registry.get(permission.extension_id)
    if extension is None:
        raise ManagedControlsPolicyError(
            "unknown_extension_target", "Permission owner is not in the current catalog."
        )
    return extension


def _parse_control(
    value: object,
    registry: CommandSafetyExtensionRegistry,
) -> tuple[ExtensionControl, object]:
    control = _mapping(value, code="invalid_control", label="Extension control")
    _exact_keys(control, frozenset({"targetKind", "targetId", "state"}), label="Extension control")
    target_kind_value = control.get("targetKind")
    if target_kind_value not in _TARGET_KINDS:
        raise ManagedControlsPolicyError("invalid_target_kind", "Extension control target kind is invalid.")
    state_value = control.get("state")
    if state_value not in _CONTROL_STATES:
        raise ManagedControlsPolicyError("invalid_control_state", "Extension control state is invalid.")
    if target_kind_value == "extension":
        target = ControlTarget(ControlTargetKind.EXTENSION, _canonical_extension_id(control.get("targetId")))
    else:
        target = ControlTarget(ControlTargetKind.PERMISSION, _canonical_permission_id(control.get("targetId")))
    extension = _target_extension(target, registry)
    return ExtensionControl(target, ControlState(str(state_value))), extension


def _parse_ids(value: object, *, label: str, parser, maximum: int) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ManagedControlsPolicyError("invalid_shape", f"{label} must be an array.")
    if len(value) > maximum:
        raise ManagedControlsPolicyError("target_limit_exceeded", f"{label} exceeds the supported limit.")
    parsed = tuple(sorted(parser(item) for item in value))
    if len(set(parsed)) != len(parsed):
        raise ManagedControlsPolicyError("duplicate_target", f"{label} contains a duplicate target.")
    return parsed


def _parse_rule_targets(
    document: dict[str, object],
    registry: CommandSafetyExtensionRegistry,
    *,
    package_firewall_supported: bool,
) -> tuple[tuple[ExtensionRuleTargets, ...], tuple[DelegatedExtensionTarget, ...]]:
    spec = _mapping(document.get("spec"), code="invalid_policy_document", label="GuardPolicy spec")
    rules = spec.get("rules")
    if not isinstance(rules, list):
        raise ManagedControlsPolicyError("invalid_policy_document", "GuardPolicy rules must be an array.")
    parsed_rules: list[ExtensionRuleTargets] = []
    delegated: set[DelegatedExtensionTarget] = set()
    total_targets = 0
    for rule_value in rules:
        rule = _mapping(rule_value, code="invalid_policy_document", label="GuardPolicy rule")
        field = rule.get(HOL_EXTENSION_TARGETS_FIELD)
        if field is None:
            continue
        targets = _mapping(field, code="invalid_extension_targets", label=HOL_EXTENSION_TARGETS_FIELD)
        _exact_keys(
            targets,
            frozenset({"schemaVersion", "extensionIds", "permissionIds"}),
            label=HOL_EXTENSION_TARGETS_FIELD,
        )
        if targets.get("schemaVersion") != HOL_EXTENSION_TARGETS_SCHEMA_VERSION:
            raise ManagedControlsPolicyError(
                "unsupported_target_schema", "Extension target schema version is unsupported."
            )
        extension_ids = _parse_ids(
            targets.get("extensionIds"),
            label="extensionIds",
            parser=_canonical_extension_id,
            maximum=MAX_CONTROL_SET_TARGETS,
        )
        permission_ids = _parse_ids(
            targets.get("permissionIds"),
            label="permissionIds",
            parser=_canonical_permission_id,
            maximum=MAX_CONTROL_SET_TARGETS,
        )
        total_targets += len(extension_ids) + len(permission_ids)
        if total_targets > MAX_CONTROL_SET_TARGETS:
            raise ManagedControlsPolicyError(
                "target_limit_exceeded", "Control Set targets exceed the supported limit."
            )
        observed_extensions: set[str] = set()
        for extension_id in extension_ids:
            extension = registry.get(extension_id)
            if extension is None or extension.extension_id != extension_id:
                raise ManagedControlsPolicyError(
                    "unknown_extension_target", "Extension target is not in the current catalog."
                )
            observed_extensions.add(extension_id)
            if extension.delegated_protection is not None:
                if not package_firewall_supported:
                    raise ManagedControlsPolicyError(
                        "unsupported_delegated_protection",
                        "Package Firewall is required for this Extension target.",
                    )
                delegated.add(
                    DelegatedExtensionTarget(ControlTarget(ControlTargetKind.EXTENSION, extension_id))
                )
        for permission_id in permission_ids:
            permission = registry.permission(permission_id)
            if permission is None or permission.permission_id != permission_id:
                raise ManagedControlsPolicyError(
                    "unknown_permission_target", "Permission target is not in the current catalog."
                )
            if observed_extensions and permission.extension_id not in observed_extensions:
                raise ManagedControlsPolicyError(
                    "target_owner_mismatch",
                    "Permission target is not owned by one of the rule's Extension targets.",
                )
            extension = registry.get(permission.extension_id)
            if extension is None:
                raise ManagedControlsPolicyError(
                    "unknown_extension_target", "Permission owner is not in the current catalog."
                )
            if extension.delegated_protection is not None:
                if not package_firewall_supported:
                    raise ManagedControlsPolicyError(
                        "unsupported_delegated_protection",
                        "Package Firewall is required for this permission target.",
                    )
                delegated.add(
                    DelegatedExtensionTarget(ControlTarget(ControlTargetKind.PERMISSION, permission_id))
                )
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise ManagedControlsPolicyError(
                "invalid_policy_document", "Extension-targeted rule requires an ID."
            )
        parsed_rules.append(ExtensionRuleTargets(rule_id, extension_ids, permission_ids))
    return tuple(parsed_rules), tuple(
        sorted(delegated, key=lambda item: (item.target.kind.value, item.target.target_id))
    )


def _controls_header(controls_value: object) -> tuple[str, bool, list[object]]:
    controls_field = _mapping(
        controls_value,
        code="invalid_extension_controls",
        label=HOL_EXTENSION_CONTROLS_FIELD,
    )
    _exact_keys(
        controls_field,
        frozenset({"schemaVersion", "authorityMode", "globalLockdown", "controls"}),
        label=HOL_EXTENSION_CONTROLS_FIELD,
    )
    if controls_field.get("schemaVersion") != HOL_EXTENSION_CONTROLS_SCHEMA_VERSION:
        raise ManagedControlsPolicyError(
            "unsupported_control_schema", "Extension control schema version is unsupported."
        )
    authority_mode = controls_field.get("authorityMode")
    if authority_mode not in _AUTHORITY_MODES:
        raise ManagedControlsPolicyError(
            "invalid_authority", "Managed Controls authority mode is invalid."
        )
    global_lockdown_value = controls_field.get("globalLockdown")
    if global_lockdown_value not in (None, True):
        raise ManagedControlsPolicyError(
            "invalid_global_lockdown", "Global lockdown must be true when present."
        )
    global_lockdown = global_lockdown_value is True
    if global_lockdown and authority_mode != "managed-restrictive":
        raise ManagedControlsPolicyError(
            "invalid_authority", "Global lockdown requires managed-restrictive authority."
        )
    controls = controls_field.get("controls")
    if not isinstance(controls, list):
        raise ManagedControlsPolicyError("invalid_shape", "Extension controls must be an array.")
    if len(controls) > MAX_CONTROLS_PER_LAYER:
        raise ManagedControlsPolicyError(
            "control_limit_exceeded", "Extension control layer exceeds the supported limit."
        )
    return str(authority_mode), global_lockdown, controls


def _append_control_projection(
    raw_control: object,
    *,
    authority_mode: str,
    registry: CommandSafetyExtensionRegistry,
    package_firewall_supported: bool,
    states_by_target: dict[ControlTarget, ControlState],
    generic_controls: list[ExtensionControl],
    managed_controls: list[ExtensionControl],
    delegated_controls: set[DelegatedExtensionTarget],
) -> None:
    control, extension = _parse_control(raw_control, registry)
    previous = states_by_target.get(control.target)
    if previous is not None:
        reason = "duplicate_target" if previous is control.state else "conflicting_target"
        raise ManagedControlsPolicyError(
            reason, "Duplicate or conflicting Extension controls are not allowed."
        )
    states_by_target[control.target] = control.state
    if authority_mode == "managed-restrictive" and control.state is not ControlState.DISABLED:
        raise ManagedControlsPolicyError(
            "managed_restrictive_broadening",
            "Managed-restrictive controls cannot enable a capability.",
        )
    if extension.delegated_protection is not None:
        if not package_firewall_supported:
            raise ManagedControlsPolicyError(
                "unsupported_delegated_protection",
                "Package Firewall is required for this control target.",
            )
        delegated_controls.add(DelegatedExtensionTarget(control.target))
        return
    if authority_mode == "managed-restrictive":
        managed_controls.append(control)
        return
    if control.state is ControlState.ENABLED:
        if control.target.kind is not ControlTargetKind.PERMISSION:
            raise ManagedControlsPolicyError(
                "shared_enable_requires_permission",
                "Shared Cloud enablement must target one configurable permission.",
            )
        permission = registry.permission(control.target.target_id)
        if permission is None or not permission.configurable:
            raise ManagedControlsPolicyError(
                "immutable_floor",
                "Shared Cloud enablement cannot weaken an immutable permission floor.",
            )
    if control.target.kind is ControlTargetKind.EXTENSION and control.state is ControlState.DISABLED:
        extension_value = registry.get(control.target.target_id)
        if extension_value is not None and extension_value.required:
            raise ManagedControlsPolicyError(
                "immutable_floor",
                "A required Extension cannot be disabled by shared Cloud posture.",
            )
    generic_controls.append(control)


def _parse_controls_projection(
    controls_value: object,
    *,
    registry: CommandSafetyExtensionRegistry,
    package_firewall_supported: bool,
    delegated_rule_targets: tuple[DelegatedExtensionTarget, ...],
) -> tuple[
    str,
    ExtensionControlLayer | None,
    tuple[ExtensionControl, ...],
    bool,
    tuple[DelegatedExtensionTarget, ...],
]:
    authority_mode, global_lockdown, raw_controls = _controls_header(controls_value)
    generic_controls: list[ExtensionControl] = []
    managed_controls: list[ExtensionControl] = []
    delegated_controls: set[DelegatedExtensionTarget] = set(delegated_rule_targets)
    states_by_target: dict[ControlTarget, ControlState] = {}
    for raw_control in raw_controls:
        _append_control_projection(
            raw_control,
            authority_mode=authority_mode,
            registry=registry,
            package_firewall_supported=package_firewall_supported,
            states_by_target=states_by_target,
            generic_controls=generic_controls,
            managed_controls=managed_controls,
            delegated_controls=delegated_controls,
        )

    def order(item: ExtensionControl | DelegatedExtensionTarget) -> tuple[str, str]:
        return (item.target.kind.value, item.target.target_id)

    signed_cloud_layer = (
        ExtensionControlLayer(
            schema_version=CONTROL_SCHEMA_VERSION,
            kind=ControlLayerKind.SIGNED_CLOUD,
            catalog_digest=registry.catalog_digest,
            global_lockdown=False,
            controls=tuple(sorted(generic_controls, key=order)),
        )
        if authority_mode in _SHARED_AUTHORITY_MODES
        else None
    )
    return (
        authority_mode,
        signed_cloud_layer,
        tuple(sorted(managed_controls, key=order)),
        global_lockdown,
        tuple(sorted(delegated_controls, key=order)),
    )


def parse_managed_controls_policy_fields(
    document: dict[str, object],
    *,
    registry: CommandSafetyExtensionRegistry,
    negotiated_capabilities: frozenset[str],
    package_firewall_supported: bool = False,
) -> ParsedManagedControlsPolicy:
    """Parse and materialize signed namespaced fields without changing legacy v2 behavior."""

    controls_value = document.get(HOL_EXTENSION_CONTROLS_FIELD)
    spec = _mapping(document.get("spec"), code="invalid_policy_document", label="GuardPolicy spec")
    rules = spec.get("rules")
    targets_present = isinstance(rules, list) and any(
        _is_mapping(rule) and HOL_EXTENSION_TARGETS_FIELD in rule for rule in rules
    )
    controls_present = controls_value is not None
    if not controls_present and not targets_present:
        return ParsedManagedControlsPolicy(None, None, (), False, (), ())
    _require_capabilities(
        negotiated_capabilities,
        controls_present=controls_present,
        targets_present=targets_present,
    )
    rule_targets, delegated_rule_targets = _parse_rule_targets(
        document,
        registry,
        package_firewall_supported=package_firewall_supported,
    )
    if not controls_present:
        return ParsedManagedControlsPolicy(
            None, None, (), False, rule_targets, delegated_rule_targets
        )
    (
        authority_mode,
        signed_cloud_layer,
        managed_controls,
        global_lockdown,
        delegated_targets,
    ) = _parse_controls_projection(
        controls_value,
        registry=registry,
        package_firewall_supported=package_firewall_supported,
        delegated_rule_targets=delegated_rule_targets,
    )
    return ParsedManagedControlsPolicy(
        authority_mode,
        signed_cloud_layer,
        managed_controls,
        global_lockdown,
        rule_targets,
        delegated_targets,
    )
