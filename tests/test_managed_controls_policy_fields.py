from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.managed_controls_policy_fields import (
    EXTENSION_CONTROL_LAYER_CAPABILITY,
    MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY,
    POLICY_EXTENSION_TARGETS_CAPABILITY,
    ManagedControlsPolicyError,
    parse_managed_controls_policy_fields,
    validated_managed_controls_policy_bundle_v2_payload,
)
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    POLICY_BUNDLE_KEY_PURPOSE,
    policy_bundle_verification_key_from_public_key,
)
from codex_plugin_scanner.guard.policy_bundle_v2 import (
    computed_policy_bundle_v2_hash,
    payload_hash_for_policy_bundle_v2,
    validate_policy_bundle_v2_transition,
)
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ControlLayerKind,
    ControlState,
    ControlTargetKind,
)

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE = json.loads(
    (_ROOT / "contracts/managed-controls/v1/policy-extension-fields.fixtures.json").read_text()
)
_SIGNATURE_VECTOR = json.loads(
    (_ROOT / "contracts/managed-controls/v1/policy-bundle-v2-extension-signature-vector.json").read_text()
)
_ROTATION_FIXTURE = json.loads(
    (_ROOT / "contracts/managed-controls/v1/policy-bundle-v2-rotation-rollback-fixtures.json").read_text()
)
_CAPABILITIES = frozenset(
    {
        EXTENSION_CONTROL_LAYER_CAPABILITY,
        POLICY_EXTENSION_TARGETS_CAPABILITY,
        MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY,
    }
)


def _document() -> dict[str, object]:
    return copy.deepcopy(_FIXTURE["document"])


def _error_code(document: dict[str, object], **kwargs: object) -> str:
    capabilities = kwargs.pop("capabilities", _CAPABILITIES)
    assert isinstance(capabilities, frozenset)
    with pytest.raises(ManagedControlsPolicyError) as captured:
        parse_managed_controls_policy_fields(
            document,
            registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
            negotiated_capabilities=capabilities,
            package_firewall_supported=bool(kwargs.pop("package_firewall_supported", False)),
        )
    return captured.value.code


def test_parses_managed_controls_only_after_full_capability_negotiation() -> None:
    parsed = parse_managed_controls_policy_fields(
        _document(),
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        negotiated_capabilities=_CAPABILITIES,
    )

    assert parsed.authority_mode == "managed-restrictive"
    assert parsed.signed_cloud_layer is None
    assert parsed.managed_global_lockdown is False
    assert len(parsed.managed_controls) == 1
    assert parsed.managed_controls[0].target.kind is ControlTargetKind.PERMISSION
    assert parsed.managed_controls[0].state is ControlState.DISABLED
    assert parsed.rule_targets[0].extension_ids == ("command.git",)
    assert parsed.rule_targets[0].permission_ids == (
        "command.git.permission.force-push",
    )

    for capability in _CAPABILITIES:
        downgraded = frozenset(_CAPABILITIES - {capability})
        assert (
            _error_code(_document(), capabilities=downgraded)
            == "unnegotiated_extension_semantics"
        )


def test_accepts_legacy_capability_aliases_without_advertising_them_as_canonical() -> None:
    parsed = parse_managed_controls_policy_fields(
        _document(),
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        negotiated_capabilities=frozenset(_FIXTURE["legacyCapabilityAliases"]),
    )
    assert parsed.has_extension_semantics


def test_v2_policy_without_extension_fields_keeps_existing_behavior() -> None:
    document = _document()
    document.pop("x-hol-extension-controls")
    rules = document["spec"]["rules"]  # type: ignore[index]
    rules[0].pop("x-hol-extension-targets")  # type: ignore[index,union-attr]

    parsed = parse_managed_controls_policy_fields(
        document,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        negotiated_capabilities=frozenset(),
    )

    assert parsed.has_extension_semantics is False
    assert parsed.signed_cloud_layer is None


def test_materializes_shared_posture_into_the_signed_cloud_layer() -> None:
    document = _document()
    document["x-hol-extension-controls"] = copy.deepcopy(_FIXTURE["sharedEnabled"])

    parsed = parse_managed_controls_policy_fields(
        document,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        negotiated_capabilities=_CAPABILITIES,
    )

    assert parsed.authority_mode == "workspace-shared"
    assert parsed.signed_cloud_layer is not None
    assert parsed.signed_cloud_layer.kind is ControlLayerKind.SIGNED_CLOUD
    assert parsed.signed_cloud_layer.catalog_digest == (
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    )
    assert parsed.signed_cloud_layer.controls[0].state is ControlState.ENABLED


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (
            lambda value: value["x-hol-extension-controls"].update(
                {"schemaVersion": "guard.extension-controls.v2"}
            ),
            "unsupported_control_schema",
        ),
        (
            lambda value: value["x-hol-extension-controls"].update(
                {"authorityMode": "root-admin"}
            ),
            "invalid_authority",
        ),
        (
            lambda value: value["x-hol-extension-controls"]["controls"][0].update(
                {"targetKind": "detector"}
            ),
            "invalid_target_kind",
        ),
        (
            lambda value: value["x-hol-extension-controls"]["controls"][0].update(
                {"targetId": "git.force-push"}
            ),
            "invalid_permission_id",
        ),
        (
            lambda value: value["x-hol-extension-controls"]["controls"][0].update(
                {"state": "prompt"}
            ),
            "invalid_control_state",
        ),
        (
            lambda value: value["x-hol-extension-controls"]["controls"][0].update(
                {"targetId": "command.git.permission.unknown"}
            ),
            "unknown_permission_target",
        ),
        (
            lambda value: value["spec"]["rules"][0][
                "x-hol-extension-targets"
            ].update({"authorityMode": "managed-restrictive"}),
            "unknown_field",
        ),
    ],
)
def test_rejects_malformed_namespaced_fields(mutation, expected: str) -> None:
    document = _document()
    mutation(document)
    assert _error_code(document) == expected


def test_rejects_duplicate_and_conflicting_controls_before_projection() -> None:
    document = _document()
    controls = document["x-hol-extension-controls"]["controls"]  # type: ignore[index]
    controls.append(copy.deepcopy(controls[0]))  # type: ignore[union-attr,index]
    assert _error_code(document) == "duplicate_target"

    document = _document()
    controls = document["x-hol-extension-controls"]["controls"]  # type: ignore[index]
    conflict = copy.deepcopy(controls[0])  # type: ignore[index]
    conflict["state"] = "enabled"
    controls.append(conflict)  # type: ignore[union-attr]
    assert _error_code(document) == "conflicting_target"


def test_rejects_control_and_target_limit_overflow() -> None:
    document = _document()
    control = document["x-hol-extension-controls"]["controls"][0]  # type: ignore[index]
    document["x-hol-extension-controls"]["controls"] = [  # type: ignore[index]
        {**control, "targetId": f"command.git.permission.force-push-{index}"}
        for index in range(513)
    ]
    assert _error_code(document) == "control_limit_exceeded"

    document = _document()
    document["spec"]["rules"][0]["x-hol-extension-targets"]["extensionIds"] = [  # type: ignore[index]
        f"command.tool-{index}" for index in range(1025)
    ]
    assert _error_code(document) == "target_limit_exceeded"


def test_managed_restrictive_controls_are_disable_or_lockdown_only() -> None:
    document = _document()
    document["x-hol-extension-controls"]["controls"][0]["state"] = "enabled"  # type: ignore[index]
    assert _error_code(document) == "managed_restrictive_broadening"

    document = _document()
    document["x-hol-extension-controls"] = copy.deepcopy(_FIXTURE["globalLockdown"])
    parsed = parse_managed_controls_policy_fields(
        document,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        negotiated_capabilities=_CAPABILITIES,
    )
    assert parsed.managed_global_lockdown is True


def test_delegated_targets_require_package_firewall_support_and_never_become_generic_controls() -> None:
    delegated = next(
        extension
        for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
        if extension.delegated_protection == "package-firewall"
    )
    permission = delegated.permissions[0]
    document = _document()
    document["spec"]["rules"][0].pop("x-hol-extension-targets")  # type: ignore[index]
    document["x-hol-extension-controls"] = {
        "schemaVersion": "guard.extension-controls.v1",
        "authorityMode": "workspace-shared",
        "controls": [
            {
                "targetKind": "permission",
                "targetId": permission.permission_id,
                "state": "disabled",
            }
        ],
    }

    assert _error_code(document) == "unsupported_delegated_protection"
    parsed = parse_managed_controls_policy_fields(
        document,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        negotiated_capabilities=_CAPABILITIES,
        package_firewall_supported=True,
    )
    assert parsed.signed_cloud_layer is not None
    assert parsed.signed_cloud_layer.controls == ()
    assert parsed.delegated_targets[0].target.target_id == permission.permission_id


def test_shared_enable_cannot_target_an_extension_or_immutable_permission() -> None:
    document = _document()
    document["spec"]["rules"][0].pop("x-hol-extension-targets")  # type: ignore[index]
    document["x-hol-extension-controls"] = {
        "schemaVersion": "guard.extension-controls.v1",
        "authorityMode": "workspace-shared",
        "controls": [
            {
                "targetKind": "extension",
                "targetId": "command.git",
                "state": "enabled",
            }
        ],
    }
    assert _error_code(document) == "shared_enable_requires_permission"

    immutable = next(
        permission
        for permission in BUILT_IN_COMMAND_EXTENSION_REGISTRY.permissions
        if not permission.configurable
    )
    document["x-hol-extension-controls"]["controls"] = [  # type: ignore[index]
        {
            "targetKind": "permission",
            "targetId": immutable.permission_id,
            "state": "enabled",
        }
    ]
    assert _error_code(document) == "immutable_floor"


@pytest.mark.parametrize(
    "bad_value",
    [
        None,
        [],
        "controls",
        {"schemaVersion": "guard.extension-controls.v1"},
        {"schemaVersion": 1, "authorityMode": "workspace-shared", "controls": []},
        {
            "schemaVersion": "guard.extension-controls.v1",
            "authorityMode": "workspace-shared",
            "controls": "not-an-array",
        },
    ],
)
def test_malformed_field_fuzz_matrix_fails_closed(bad_value: object) -> None:
    document = _document()
    document["x-hol-extension-controls"] = bad_value
    assert _error_code(document) in {
        "invalid_extension_controls",
        "invalid_shape",
        "unsupported_control_schema",
        "invalid_authority",
    }


def test_shared_signature_vector_validates_before_extension_projection() -> None:
    vector = _SIGNATURE_VECTOR
    bundle = copy.deepcopy(vector["bundle"])
    public_key = policy_bundle_verification_key_from_public_key(
        key_id=bundle["verifier"]["keyId"],
        public_key_pem=bundle["verifier"]["publicKeyPem"],
        purpose=POLICY_BUNDLE_KEY_PURPOSE,
        workspace_id=bundle["workspaceId"],
    )
    validated, parsed, reason = validated_managed_controls_policy_bundle_v2_payload(
        bundle,
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        negotiated_capabilities=_CAPABILITIES,
        trusted_verification_keys=(public_key,),
        anchored_verification_keys=(public_key,),
    )

    assert reason is None
    assert validated is not None
    assert parsed is not None and parsed.has_extension_semantics
    assert computed_policy_bundle_v2_hash(bundle) == vector["expectedBundleHash"]
    assert payload_hash_for_policy_bundle_v2(bundle) == vector["expectedPayloadHash"]


def test_rotation_rollback_and_downgrade_fixtures_are_monotonic() -> None:
    for case in _ROTATION_FIXTURE["transitionCases"]:
        candidate = {
            "bundleVersion": case["candidateVersion"],
            "bundleHash": case["candidateHash"],
        }
        assert (
            validate_policy_bundle_v2_transition(
                candidate,
                current_bundle_version=case["currentVersion"],
                current_bundle_hash=case["currentHash"],
            )
            == case["expected"]
        )

    rollback = copy.deepcopy(_ROTATION_FIXTURE["authorizedRollback"])
    assert (
        validate_policy_bundle_v2_transition(
            rollback,
            current_bundle_version=8,
            current_bundle_hash=rollback["rollback"]["rollbackOfBundleHash"],
            expected_last_good_bundle_version=7,
            expected_last_good_bundle_hash=rollback["rollback"]["lastGoodBundleHash"],
        )
        is None
    )
