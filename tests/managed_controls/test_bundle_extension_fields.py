from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.bundle import (
    ManagedControlsBundleError,
    parse_extension_contract,
)
from codex_plugin_scanner.guard.managed_controls.catalog import (
    CatalogExtension,
    CatalogPermission,
    CatalogProjection,
    CatalogValidationError,
)


def _catalog() -> CatalogProjection:
    return CatalogProjection(
        1,
        (
            CatalogExtension(
                "command.git",
                "Git",
                "1",
                (
                    CatalogPermission(
                        "command.git.permission.push",
                        "Push",
                        configurable=True,
                    ),
                ),
            ),
        ),
    )


def test_parses_document_and_rule_extension_fields() -> None:
    parsed = parse_extension_contract(
        {
            "x-hol-extension-controls": {
                "schemaVersion": "guard.extension-controls.v1",
                "authorityMode": "managed-restrictive",
                "controls": [
                    {
                        "targetKind": "permission",
                        "targetId": "command.git.permission.push",
                        "state": "disabled",
                    }
                ],
            },
            "spec": {
                "rules": [
                    {
                        "id": "rule-1",
                        "x-hol-extension-targets": {
                            "schemaVersion": "guard.policy-extension-targets.v1",
                            "extensionIds": ["command.git"],
                            "permissionIds": ["command.git.permission.push"],
                        },
                    }
                ],
            },
        },
        _catalog(),
    )
    assert parsed.controls[0].source_id == "control-0"
    assert parsed.rule_targets["rule-1"][1].permission_id == "command.git.permission.push"


def test_unknown_target_fails_deployment() -> None:
    with pytest.raises(CatalogValidationError):
        parse_extension_contract(
            {
                "spec": {
                    "rules": [
                        {
                            "id": "bad",
                            "x-hol-extension-targets": {
                                "schemaVersion": "guard.policy-extension-targets.v1",
                                "extensionIds": [],
                                "permissionIds": ["command.git.permission.unknown"],
                            },
                        }
                    ]
                }
            },
            _catalog(),
        )


def test_malformed_extension_collection_is_rejected() -> None:
    with pytest.raises(ManagedControlsBundleError):
        parse_extension_contract(
            {
                "x-hol-extension-controls": "not-an-object",
                "spec": {"rules": []},
            },
            _catalog(),
        )


def test_global_lockdown_and_duplicate_rule_ids_are_strict() -> None:
    parsed = parse_extension_contract(
        {
            "x-hol-extension-controls": {
                "schemaVersion": "guard.extension-controls.v1",
                "authorityMode": "managed-restrictive",
                "globalLockdown": True,
                "controls": [],
            },
            "spec": {"rules": []},
        },
        _catalog(),
    )
    assert parsed.controls[0].effect.value == "lockdown"

    duplicate_rule = {
        "id": "duplicate",
        "x-hol-extension-targets": {
            "schemaVersion": "guard.policy-extension-targets.v1",
            "extensionIds": ["command.git"],
            "permissionIds": [],
        },
    }
    with pytest.raises(ManagedControlsBundleError):
        parse_extension_contract(
            {"spec": {"rules": [duplicate_rule, duplicate_rule]}},
            _catalog(),
        )
