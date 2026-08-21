from __future__ import annotations

from pathlib import Path


def replace_once(path: Path, old: str, new: str) -> None:
    source = path.read_text(encoding="utf-8")
    if new in source:
        return
    if old not in source:
        raise SystemExit(f"expected source block missing from {path}")
    path.write_text(source.replace(old, new, 1), encoding="utf-8")


def main() -> None:
    parser = Path("src/codex_plugin_scanner/guard/managed_controls_policy_fields.py")
    replace_once(
        parser,
        "from .runtime.extension_control_limits import MAX_CONTROLS_PER_LAYER, MAX_CONTROL_SET_TARGETS\n",
        "from .runtime.extension_control_limits import (\n"
        "    MAX_CONTROLS_PER_LAYER,\n"
        "    MAX_CONTROL_SET_RULES,\n"
        "    MAX_CONTROL_SET_TARGETS,\n"
        ")\n",
    )
    replace_once(
        parser,
        """    parsed_rules: list[ExtensionRuleTargets] = []
    delegated: set[DelegatedExtensionTarget] = set()
    total_targets = 0
    for rule_value in rules:
        rule = _mapping(rule_value, code="invalid_policy_document", label="GuardPolicy rule")
        field = rule.get(HOL_EXTENSION_TARGETS_FIELD)
        if field is None:
            continue
        targets = _mapping(field, code="invalid_extension_targets", label=HOL_EXTENSION_TARGETS_FIELD)
""",
        """    parsed_rules: list[ExtensionRuleTargets] = []
    delegated: set[DelegatedExtensionTarget] = set()
    total_targets = 0
    targeted_rule_count = 0
    for rule_value in rules:
        rule = _mapping(rule_value, code="invalid_policy_document", label="GuardPolicy rule")
        if HOL_EXTENSION_TARGETS_FIELD not in rule:
            continue
        targeted_rule_count += 1
        if targeted_rule_count > MAX_CONTROL_SET_RULES:
            raise ManagedControlsPolicyError(
                "rule_limit_exceeded",
                "Extension-targeted rules exceed the supported limit.",
            )
        targets = _mapping(
            rule[HOL_EXTENSION_TARGETS_FIELD],
            code="invalid_extension_targets",
            label=HOL_EXTENSION_TARGETS_FIELD,
        )
""",
    )
    replace_once(
        parser,
        """        observed_extensions: set[str] = set()
        for extension_id in extension_ids:
""",
        """        declared_extensions: set[str] = set()
        for extension_id in extension_ids:
""",
    )
    replace_once(
        parser,
        "            observed_extensions.add(extension_id)\n",
        "            declared_extensions.add(extension_id)\n",
    )
    replace_once(
        parser,
        """            if observed_extensions and permission.extension_id not in observed_extensions:
                raise ManagedControlsPolicyError(
                    "target_owner_mismatch",
                    "Permission target is not owned by one of the rule's Extension targets.",
                )
            extension = registry.get(permission.extension_id)
""",
        """            # Permission-only targets are valid. When Extension IDs are also
            # declared, every permission must belong to that explicit Extension set.
            if extension_ids and permission.extension_id not in declared_extensions:
                raise ManagedControlsPolicyError(
                    "target_owner_mismatch",
                    "Permission target is not owned by one of the rule's Extension targets.",
                )
            extension = registry.get(permission.extension_id)
""",
    )
    replace_once(
        parser,
        """    controls_value = document.get(HOL_EXTENSION_CONTROLS_FIELD)
    spec = _mapping(document.get("spec"), code="invalid_policy_document", label="GuardPolicy spec")
""",
        """    controls_present = HOL_EXTENSION_CONTROLS_FIELD in document
    controls_value = document.get(HOL_EXTENSION_CONTROLS_FIELD)
    spec = _mapping(document.get("spec"), code="invalid_policy_document", label="GuardPolicy spec")
""",
    )
    source = parser.read_text(encoding="utf-8")
    source = source.replace("    controls_present = controls_value is not None\n", "", 1)
    parser.write_text(source, encoding="utf-8")

    bundle = Path("src/codex_plugin_scanner/guard/managed_controls_policy_bundle.py")
    replace_once(
        bundle,
        "from __future__ import annotations\n\n",
        "from __future__ import annotations\n\nfrom datetime import datetime\n\n",
    )
    replace_once(
        bundle,
        """    anchored_verification_keys: tuple[PolicyBundleVerificationKey, ...] = (),
    package_firewall_supported: bool = False,
):
""",
        """    anchored_verification_keys: tuple[PolicyBundleVerificationKey, ...] = (),
    package_firewall_supported: bool = False,
    now: datetime | None = None,
):
""",
    )
    replace_once(
        bundle,
        """        trusted_verification_keys=trusted_verification_keys,
        anchored_verification_keys=anchored_verification_keys,
    )
""",
        """        trusted_verification_keys=trusted_verification_keys,
        anchored_verification_keys=anchored_verification_keys,
        now=now,
    )
""",
    )
    replace_once(
        bundle,
        """    except ManagedControlsPolicyError as error:
        return None, None, error.code
    return validated, parsed, None
""",
        """    except ManagedControlsPolicyError as error:
        return None, None, error.code
    except ValueError:
        return None, None, "invalid_extension_semantics"
    return validated, parsed, None
""",
    )

    tests = Path("tests/test_managed_controls_policy_fields.py")
    replace_once(
        tests,
        "import copy\nimport json\n",
        "import copy\nimport json\nfrom datetime import datetime, timezone\n",
    )
    replace_once(
        tests,
        """    EXTENSION_CONTROL_LAYER_CAPABILITY,
    MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY,
    POLICY_EXTENSION_TARGETS_CAPABILITY,
""",
        """    EXTENSION_CONTROL_LAYER_CAPABILITY,
    HOL_EXTENSION_CONTROLS_FIELD,
    HOL_EXTENSION_TARGETS_FIELD,
    MANAGED_CONTROLS_ATOMIC_APPLY_CAPABILITY,
    POLICY_EXTENSION_TARGETS_CAPABILITY,
""",
    )
    replace_once(
        tests,
        """from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ControlLayerKind,
    ControlState,
    ControlTargetKind,
)
""",
        """from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ControlLayerKind,
    ControlState,
    ControlTargetKind,
)
from codex_plugin_scanner.guard.runtime.extension_control_limits import (
    MAX_CONTROL_SET_RULES,
)
""",
    )
    replace_once(
        tests,
        """    delegated = next(
        extension
        for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
        if extension.delegated_protection == "package-firewall"
    )
    permission = delegated.permissions[0]
""",
        """    delegated = next(
        (
            extension
            for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
            if extension.delegated_protection == "package-firewall"
        ),
        None,
    )
    assert delegated is not None, "built-in registry must include Package Firewall delegation"
    permission = delegated.permissions[0]
""",
    )
    replace_once(
        tests,
        """        trusted_verification_keys=(public_key,),
        anchored_verification_keys=(public_key,),
    )
""",
        """        trusted_verification_keys=(public_key,),
        anchored_verification_keys=(public_key,),
        now=datetime(2026, 8, 22, tzinfo=timezone.utc),
    )
""",
    )
    marker = "def test_managed_restrictive_is_disable_or_lockdown_only() -> None:\n"
    additions = """def test_explicit_null_extension_fields_fail_closed() -> None:
    document = _document()
    document[HOL_EXTENSION_CONTROLS_FIELD] = None
    assert _code(document) == "invalid_extension_controls"

    document = _document()
    document["spec"]["rules"][0][HOL_EXTENSION_TARGETS_FIELD] = None
    assert _code(document) == "invalid_extension_targets"


def test_targeted_rule_count_limit_is_enforced() -> None:
    document = _document()
    seed = document["spec"]["rules"][0]
    document["spec"]["rules"] = [
        {
            **copy.deepcopy(seed),
            "id": f"managed-rule-{index}",
            HOL_EXTENSION_TARGETS_FIELD: {
                "schemaVersion": "guard.policy-extension-targets.v1",
                "extensionIds": [],
                "permissionIds": [],
            },
        }
        for index in range(MAX_CONTROL_SET_RULES + 1)
    ]
    assert _code(document) == "rule_limit_exceeded"


def test_permission_only_target_validates_its_catalog_owner() -> None:
    document = _document()
    targets = document["spec"]["rules"][0][HOL_EXTENSION_TARGETS_FIELD]
    targets["extensionIds"] = []
    parsed = _parse(document)
    assert parsed.rule_targets[0].extension_ids == ()
    assert parsed.rule_targets[0].permission_ids == (
        "command.git.permission.force-push",
    )


"""
    source = tests.read_text(encoding="utf-8")
    if additions not in source:
        if marker not in source:
            raise SystemExit("test insertion marker missing")
        source = source.replace(marker, additions + marker, 1)
    tests.write_text(source, encoding="utf-8")


if __name__ == "__main__":
    main()
