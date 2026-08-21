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
                (CatalogPermission("push", "Push", configurable=True),),
            ),
        ),
    )


def test_parses_document_and_rule_extension_fields() -> None:
    parsed = parse_extension_contract(
        {
            "spec": {
                "x-hol-extension-controls": [
                    {
                        "extension_id": "command.git",
                        "permission_id": "push",
                        "authority_mode": "managed-restrictive",
                        "effect": "block",
                        "source_id": "control-set-1",
                    }
                ],
                "rules": [
                    {
                        "id": "rule-1",
                        "x-hol-extension-targets": [
                            {
                                "extension_id": "command.git",
                                "permission_id": "push",
                            }
                        ],
                    }
                ],
            }
        },
        _catalog(),
    )
    assert parsed.controls[0].source_id == "control-set-1"
    assert parsed.rule_targets["rule-1"][0].permission_id == "push"


def test_unknown_target_fails_deployment() -> None:
    with pytest.raises(CatalogValidationError):
        parse_extension_contract(
            {
                "spec": {
                    "rules": [
                        {
                            "id": "bad",
                            "x-hol-extension-targets": [
                                {
                                    "extension_id": "command.git",
                                    "permission_id": "unknown",
                                }
                            ],
                        }
                    ]
                }
            },
            _catalog(),
        )


def test_malformed_extension_collection_is_rejected() -> None:
    with pytest.raises(ManagedControlsBundleError):
        parse_extension_contract(
            {"spec": {"x-hol-extension-controls": "not-an-array"}},
            _catalog(),
        )
