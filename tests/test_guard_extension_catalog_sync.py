from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

import pytest

from codex_plugin_scanner.guard.runtime.extension_catalog_sync import (
    EXTENSION_CATALOG_SCHEMA_VERSION,
    MANAGED_CONTROLS_RUNTIME_CAPABILITIES,
    build_extension_catalog_wire,
    build_managed_controls_runtime_posture,
)


@dataclass(frozen=True)
class FakePermission:
    permission_id: str
    label: str
    configurable: bool
    risk_tier: str
    typed_capabilities: tuple[str, ...] = ()


@dataclass(frozen=True)
class FakeExtension:
    extension_id: str
    version: str
    name: str
    source: str
    executables: tuple[str, ...]
    ecosystem_ids: tuple[str, ...]
    risk_classes: tuple[str, ...]
    delegated_protection: str | None
    permissions: tuple[FakePermission, ...]


@dataclass(frozen=True)
class FakeRegistry:
    extensions: tuple[FakeExtension, ...]


def registry(*, reverse: bool = False) -> FakeRegistry:
    package = FakeExtension(
        extension_id="command.package-manager",
        version="1.0.0",
        name="Package manager",
        source="built-in",
        executables=("pnpm", "npm"),
        ecosystem_ids=("npm",),
        risk_classes=("supply_chain",),
        delegated_protection="package-firewall",
        permissions=(
            FakePermission(
                "command.package-manager.permission.package-protection",
                "Package protection",
                True,
                "high",
            ),
        ),
    )
    shell = FakeExtension(
        extension_id="command.shell",
        version="2.0.0",
        name="Shell",
        source="built-in",
        executables=("zsh", "bash", "bash"),
        ecosystem_ids=("posix",),
        risk_classes=("destructive", "execution"),
        delegated_protection=None,
        permissions=(
            FakePermission(
                "command.shell.permission.execute",
                "Execute shell",
                False,
                "critical",
                ("process.spawn", "process.exec"),
            ),
        ),
    )
    values = (package, shell)
    return FakeRegistry(tuple(reversed(values)) if reverse else values)


def test_wire_projection_is_order_independent_and_cross_language_canonical() -> None:
    first = build_extension_catalog_wire(
        registry(),
        guard_version="3.0.0a1",
        generated_at="2026-08-23T12:00:00Z",
    )
    second = build_extension_catalog_wire(
        registry(reverse=True),
        guard_version="3.0.0a1",
        generated_at="2026-08-23T12:00:01Z",
    )
    assert first["catalogDigest"] == second["catalogDigest"]
    assert [item["id"] for item in first["extensions"]] == [
        "command.package-manager",
        "command.shell",
    ]
    canonical = json.dumps(
        first["extensions"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    assert first["catalogDigest"] == hashlib.sha256(canonical.encode()).hexdigest()


def test_wire_projection_contains_only_privacy_safe_catalog_metadata() -> None:
    payload = build_extension_catalog_wire(
        registry(),
        guard_version="3.0.0a1",
        generated_at="2026-08-23T12:00:00Z",
    )
    encoded = json.dumps(payload)
    for forbidden in (
        "description",
        "rules",
        "ruleIds",
        "exampleCommand",
        "projectMarkers",
        "referenceUrls",
        "sourcePath",
        "workingDirectory",
        "environment",
        "secrets",
    ):
        assert forbidden not in encoded
    assert payload["schemaVersion"] == EXTENSION_CATALOG_SCHEMA_VERSION
    assert payload["extensions"][0]["delegatedProtection"] == "package-firewall"


def test_wire_projection_sorts_set_like_fields_and_preserves_fixed_floors() -> None:
    payload = build_extension_catalog_wire(
        registry(),
        guard_version="3.0.0a1",
        generated_at="2026-08-23T12:00:00Z",
    )
    shell = payload["extensions"][1]
    assert shell["executables"] == ["bash", "zsh"]
    assert shell["riskClasses"] == ["destructive", "execution"]
    permission = shell["permissions"][0]
    assert permission["required"] is True
    assert permission["typedCapabilities"] == ["process.exec", "process.spawn"]


def test_runtime_posture_uses_cloud_capabilities_and_bounded_digests() -> None:
    posture = build_managed_controls_runtime_posture(
        catalog_digest="a" * 64,
        extension_authority_revision=7,
        effective_projection_digest="b" * 64,
    )
    assert posture["managedControlsCapabilities"] == list(
        MANAGED_CONTROLS_RUNTIME_CAPABILITIES
    )
    assert posture["extensionAuthorityRevision"] == 7
    assert posture["effectiveProjectionDigest"] == "b" * 64


@pytest.mark.parametrize(
    ("catalog_digest", "authority_revision", "effective_digest"),
    [
        ("not-a-digest", None, None),
        ("a" * 64, -1, None),
        ("a" * 64, 0, "not-a-digest"),
    ],
)
def test_runtime_posture_rejects_invalid_evidence(
    catalog_digest: str,
    authority_revision: int | None,
    effective_digest: str | None,
) -> None:
    with pytest.raises(ValueError):
        build_managed_controls_runtime_posture(
            catalog_digest=catalog_digest,
            extension_authority_revision=authority_revision,
            effective_projection_digest=effective_digest,
        )
