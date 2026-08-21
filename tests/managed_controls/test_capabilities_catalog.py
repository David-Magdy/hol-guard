from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.capabilities import (
    MANAGED_CONTROL_CAPABILITIES,
    CapabilityNegotiationError,
    RuntimeCapabilityAdvertisement,
)
from codex_plugin_scanner.guard.managed_controls.catalog import (
    CatalogExtension,
    CatalogPermission,
    CatalogProjection,
    CatalogValidationError,
)


def _catalog() -> CatalogProjection:
    permission = CatalogPermission("push", "Push", configurable=True)
    extension = CatalogExtension("command.git", "Git", "1", (permission,))
    return CatalogProjection(1, (extension,))


def test_requires_all_four_capabilities() -> None:
    advertisement = RuntimeCapabilityAdvertisement(MANAGED_CONTROL_CAPABILITIES)
    assert advertisement.supports_managed_controls
    advertisement.require(MANAGED_CONTROL_CAPABILITIES)
    with pytest.raises(CapabilityNegotiationError):
        RuntimeCapabilityAdvertisement(frozenset()).require(
            MANAGED_CONTROL_CAPABILITIES
        )


def test_catalog_identity_and_digest_are_deterministic() -> None:
    catalog = _catalog()
    assert len(catalog.digest) == 64
    assert catalog.permission("command.git", "push").configurable
    assert catalog.digest == _catalog().digest


def test_unknown_targets_fail_instead_of_disappearing() -> None:
    with pytest.raises(CatalogValidationError):
        _catalog().permission("command.git", "missing")
