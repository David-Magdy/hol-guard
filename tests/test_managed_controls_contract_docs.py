from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DECISION_PATH = ROOT / "contracts" / "managed-controls" / "v1" / "product-decision.json"
ADR_PATH = ROOT / "docs" / "guard" / "adr" / "0011-extension-first-managed-controls.md"
GLOSSARY_PATH = ROOT / "docs" / "guard" / "managed-controls-glossary.md"
NAVIGATION_PATH = ROOT / "dashboard" / "src" / "shell-navigation-model.ts"
RULES_PAGE_PATH = ROOT / "dashboard" / "src" / "policy-workspace-page.tsx"


def _decision() -> dict[str, object]:
    value = json.loads(DECISION_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_managed_controls_decision_is_versioned_and_complete() -> None:
    decision = _decision()
    assert decision["schema_version"] == 1
    assert decision["decision_id"] == "hol-guard.extension-first-managed-controls.v1"
    assert decision["authority_modes"] == [
        "personal-shared",
        "workspace-shared",
        "managed-restrictive",
    ]
    definitions = decision["definitions"]
    assert isinstance(definitions, dict)
    assert set(definitions) == {
        "control_set",
        "deployment",
        "detector_rule",
        "exception",
        "extension",
        "local_setting",
        "managed_restriction",
        "permission",
        "remembered_rule",
    }


def test_managed_controls_decision_preserves_security_boundaries() -> None:
    enforcement = _decision()["enforcement"]
    assert isinstance(enforcement, dict)
    assert enforcement["local_registry_authoritative"] is True
    assert enforcement["cloud_must_not_redefine_detector_matchers"] is True
    assert enforcement["contextual_policy_precedence_preserved"] is True
    assert enforcement["non_weakenable_authority_requires_negotiation"] is True
    assert enforcement["managed_restrictive_actions"] == [
        "disable-extension",
        "disable-permission",
        "global-lockdown",
    ]
    assert enforcement["package_manager_delegate"] == "package-firewall"


def test_adr_and_glossary_reference_the_canonical_decision() -> None:
    adr = ADR_PATH.read_text(encoding="utf-8")
    glossary = GLOSSARY_PATH.read_text(encoding="utf-8")
    assert "hol-guard.extension-first-managed-controls.v1" in adr
    assert "contracts/managed-controls/v1/product-decision.json" in adr
    for term in (
        "Extension",
        "Permission",
        "Detector rule",
        "Remembered rule",
        "Control Set",
        "Managed restriction",
        "Deployment",
        "Exception",
    ):
        assert term in glossary


def test_local_navigation_uses_product_language_without_breaking_routes() -> None:
    navigation = NAVIGATION_PATH.read_text(encoding="utf-8")
    rules_page = RULES_PAGE_PATH.read_text(encoding="utf-8")
    assert 'href: "/policy"' in navigation
    assert 'label: "Rules & exceptions"' in navigation
    assert 'shortLabel: "Rules"' in navigation
    assert 'href: "/extensions"' in navigation
    assert 'description: "Tools and capabilities protected on this device"' in navigation
    assert 'eyebrow="Rules & exceptions"' in rules_page
    assert 'title="Remembered decisions and exceptions"' in rules_page
    assert "Configure tools and capability posture in Extensions." in rules_page
    assert "Managed extensions and integrations" not in navigation
