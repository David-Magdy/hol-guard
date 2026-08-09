from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.daemon.extension_control_api import ExtensionControlApiService
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth, ExtensionControlAuthorityView
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntime
from codex_plugin_scanner.guard.store import GuardStore


def _service(tmp_path: Path) -> ExtensionControlApiService:
    view = ExtensionControlAuthorityView(
        AuthorityHealth.PROTECTED,
        1,
        BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
        (),
    )
    return ExtensionControlApiService(
        store=GuardStore(tmp_path / "guard-home"),
        registry=BUILT_IN_COMMAND_EXTENSION_REGISTRY,
        runtime=ExtensionControlRuntime(view),
    )


def test_catalog_exposes_stable_extension_permission_and_rule_detail_contract(tmp_path: Path) -> None:
    payload = _service(tmp_path).catalog()
    extensions = payload["extensions"]
    assert isinstance(extensions, list)
    assert extensions
    for extension in extensions:
        assert isinstance(extension, dict)
        extension_id = extension["extension_id"]
        assert isinstance(extension_id, str) and extension_id.startswith("command.")
        assert extension["permission_count"] == len(extension["permissions"])
        assert extension["rule_count"] == len(extension["rules"])
        assert isinstance(extension["aliases"], list)
        assert isinstance(extension["dependencies"], list)
        assert isinstance(extension["conflicts"], list)

        rule_ids = {rule["rule_id"] for rule in extension["rules"]}
        governed_rule_ids: set[str] = set()
        for permission in extension["permissions"]:
            permission_id = permission["permission_id"]
            assert isinstance(permission_id, str)
            assert permission_id.startswith(f"{extension_id}.permission.")
            assert permission["extension_id"] == extension_id
            assert permission["risk_tier"] in {"low", "medium", "high", "critical"}
            assert permission["baseline_floor"] in {
                "allow", "warn", "review", "require-reapproval", "sandbox-required", "block"
            }
            assert isinstance(permission["configurable"], bool)
            assert isinstance(permission["dependencies"], list)
            assert isinstance(permission["conflicts"], list)
            assert isinstance(permission["implied_permissions"], list)
            governed_rule_ids.update(permission["rule_ids"])

        # Compatibility/fallback rules may intentionally have no permission owner,
        # but every permission-owned rule must exist in this extension version.
        assert governed_rule_ids <= rule_ids
        for rule in extension["rules"]:
            assert rule["rule_id"].startswith(f"{extension_id}.")
            assert rule["severity"] in {"low", "medium", "high", "critical"}
            assert rule["default_mode"] in {"required", "enforce", "review", "monitor", "disabled"}
            assert isinstance(rule["matcher_kind"], str)
            assert isinstance(rule["safe_variants"], list)
