"""Strict parsing for signed Extension-targeted policy bundle fields."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .authority import AuthorityMode, ControlEffect, ControlInstruction
from .catalog import CatalogProjection, CatalogValidationError


class ManagedControlsBundleError(ValueError):
    """Raised when a bundle extension is malformed or unsupported."""


@dataclass(frozen=True, slots=True)
class ExtensionTarget:
    extension_id: str
    permission_id: str | None


@dataclass(frozen=True, slots=True)
class ParsedExtensionContract:
    controls: tuple[ControlInstruction, ...]
    rule_targets: dict[str, tuple[ExtensionTarget, ...]]


def _target(value: object, catalog: CatalogProjection) -> ExtensionTarget:
    if not isinstance(value, dict):
        raise ManagedControlsBundleError("extension target must be an object")
    extension_id = value.get("extension_id")
    permission_id = value.get("permission_id")
    if not isinstance(extension_id, str):
        raise ManagedControlsBundleError("extension target id is required")
    if permission_id is not None and not isinstance(permission_id, str):
        raise ManagedControlsBundleError("permission target id must be a string")
    if permission_id is not None:
        catalog.permission(extension_id, permission_id)
    elif not any(item.extension_id == extension_id for item in catalog.extensions):
        raise CatalogValidationError("unknown extension target")
    return ExtensionTarget(extension_id, permission_id)


def parse_extension_contract(
    document: dict[str, Any],
    catalog: CatalogProjection,
) -> ParsedExtensionContract:
    spec = document.get("spec")
    if not isinstance(spec, dict):
        raise ManagedControlsBundleError("policy spec is required")
    raw_controls = spec.get("x-hol-extension-controls", [])
    if not isinstance(raw_controls, list):
        raise ManagedControlsBundleError("extension controls must be an array")
    controls: list[ControlInstruction] = []
    for index, value in enumerate(raw_controls):
        if not isinstance(value, dict):
            raise ManagedControlsBundleError("extension control must be an object")
        try:
            authority = AuthorityMode(str(value["authority_mode"]))
            effect = ControlEffect(str(value["effect"]))
            target = _target(value, catalog)
            source_id = str(value.get("source_id", f"control-{index}"))
        except (KeyError, ValueError) as error:
            raise ManagedControlsBundleError("invalid extension control") from error
        controls.append(
            ControlInstruction(
                target.extension_id,
                target.permission_id,
                effect,
                authority,
                source_id,
            )
        )
    raw_rules = spec.get("rules", [])
    if not isinstance(raw_rules, list):
        raise ManagedControlsBundleError("policy rules must be an array")
    rule_targets: dict[str, tuple[ExtensionTarget, ...]] = {}
    for index, rule in enumerate(raw_rules):
        if not isinstance(rule, dict):
            raise ManagedControlsBundleError("policy rule must be an object")
        rule_id = str(rule.get("id", f"rule-{index}"))
        raw_targets = rule.get("x-hol-extension-targets", [])
        if not isinstance(raw_targets, list):
            raise ManagedControlsBundleError("extension targets must be an array")
        rule_targets[rule_id] = tuple(
            _target(value, catalog) for value in raw_targets
        )
    return ParsedExtensionContract(tuple(controls), rule_targets)
