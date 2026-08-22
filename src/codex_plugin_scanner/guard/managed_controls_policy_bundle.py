"""Signed bundle validation followed by negotiated Managed Controls parsing."""

from __future__ import annotations

from datetime import datetime

from .managed_controls_policy_fields import (
    ManagedControlsPolicyError,
    is_mapping,
    parse_managed_controls_policy_fields,
)
from .policy_bundle_trusted_keys import PolicyBundleVerificationKey
from .policy_bundle_v2 import validated_policy_bundle_v2_payload
from .runtime.command_extensions import CommandSafetyExtensionRegistry


def validated_managed_controls_policy_bundle_v2_payload(
    policy_bundle: dict[str, object],
    *,
    registry: CommandSafetyExtensionRegistry,
    negotiated_capabilities: frozenset[str],
    trusted_verification_keys: tuple[PolicyBundleVerificationKey, ...] = (),
    anchored_verification_keys: tuple[PolicyBundleVerificationKey, ...] = (),
    package_firewall_supported: bool = False,
    now: datetime | None = None,
):
    """Validate the signed envelope first, then parse negotiated Extension semantics."""

    validated, reason = validated_policy_bundle_v2_payload(
        policy_bundle,
        trusted_verification_keys=trusted_verification_keys,
        anchored_verification_keys=anchored_verification_keys,
        now=now,
    )
    if validated is None:
        return None, None, reason
    payload = validated.get("payload")
    if not is_mapping(payload):
        return None, None, "invalid_policy_document"
    try:
        parsed = parse_managed_controls_policy_fields(
            payload,
            registry=registry,
            negotiated_capabilities=negotiated_capabilities,
            package_firewall_supported=package_firewall_supported,
        )
    except ManagedControlsPolicyError as error:
        return None, None, error.code
    except ValueError:
        return None, None, "invalid_extension_semantics"
    return validated, parsed, None
