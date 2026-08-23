from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.identity import (
    CatalogIdentityState,
    ExtensionIdentity,
    compare_extension_identity,
)
from codex_plugin_scanner.guard.managed_controls.privacy import (
    CatalogPrivacyError,
    privacy_safe_catalog_payload,
)


def test_catalog_projection_excludes_commands_paths_and_secrets() -> None:
    payload = {
        "schema_version": 1,
        "catalog_digest": "a" * 64,
        "extensions": [
            {
                "extension_id": "command.git",
                "name": "Git",
                "version": "1",
                "permissions": [],
            }
        ],
    }
    assert privacy_safe_catalog_payload(payload) == payload
    with pytest.raises(CatalogPrivacyError):
        privacy_safe_catalog_payload(
            {**payload, "extensions": [{"raw_command": "rm -rf /"}]}
        )


def test_custom_identity_is_truthfully_local_only_without_cloud_match() -> None:
    local = ExtensionIdentity("custom.acme", "1", custom=True)
    assert (
        compare_extension_identity(local, None)
        is CatalogIdentityState.CUSTOM_LOCAL_ONLY
    )
