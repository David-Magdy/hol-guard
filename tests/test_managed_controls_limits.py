from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.extension_control_limits import (
    MAX_CONTROL_LAYERS,
    MAX_CONTROLS_PER_LAYER,
    MAX_CONTROLS_TOTAL,
    MAX_INPUT_TEXT_LENGTH,
    MAX_OBSERVATIONS,
    MAX_RESOLUTION_IDS,
    ExtensionControlLimitViolation,
    advertised_extension_control_limits,
    extension_control_limit_violation,
)

ROOT = Path(__file__).resolve().parents[1]
LIMITS_PATH = ROOT / "contracts" / "managed-controls" / "v1" / "limits.json"
API_PATH = ROOT / "src" / "codex_plugin_scanner" / "guard" / "daemon" / "extension_control_api.py"
NAVIGATION_PATH = ROOT / "dashboard" / "src" / "shell-navigation-model.ts"
RULES_PAGE_PATH = ROOT / "dashboard" / "src" / "policy-workspace-page.tsx"


def test_shared_limits_fixture_matches_runtime_constants() -> None:
    fixture = json.loads(LIMITS_PATH.read_text(encoding="utf-8"))
    assert fixture == advertised_extension_control_limits()
    assert fixture["max_controls_total"] == (
        fixture["max_control_layers"] * fixture["max_controls_per_layer"]
    )


@pytest.mark.parametrize("count", [MAX_CONTROLS_PER_LAYER - 1, MAX_CONTROLS_PER_LAYER])
def test_per_layer_control_boundary_accepts_limit_and_below(count: int) -> None:
    assert extension_control_limit_violation(layer_sizes=(count,)) is None


def test_per_layer_control_boundary_rejects_limit_plus_one() -> None:
    assert extension_control_limit_violation(layer_sizes=(MAX_CONTROLS_PER_LAYER + 1,)) is (
        ExtensionControlLimitViolation.PER_LAYER
    )


@pytest.mark.parametrize("layer_count", [MAX_CONTROL_LAYERS - 1, MAX_CONTROL_LAYERS])
def test_layer_boundary_accepts_limit_and_below(layer_count: int) -> None:
    assert extension_control_limit_violation(layer_sizes=(0,) * layer_count) is None


def test_layer_boundary_rejects_limit_plus_one() -> None:
    assert extension_control_limit_violation(layer_sizes=(0,) * (MAX_CONTROL_LAYERS + 1)) is (
        ExtensionControlLimitViolation.LAYERS
    )


def test_total_control_boundary_is_consistent() -> None:
    assert MAX_CONTROLS_TOTAL == MAX_CONTROL_LAYERS * MAX_CONTROLS_PER_LAYER
    assert extension_control_limit_violation(
        layer_sizes=(MAX_CONTROLS_PER_LAYER, MAX_CONTROLS_PER_LAYER)
    ) is None


@pytest.mark.parametrize(
    (field, accepted, rejected, violation),
    [
        ("extension_id_count", MAX_RESOLUTION_IDS, MAX_RESOLUTION_IDS + 1, ExtensionControlLimitViolation.RESOLUTION_IDS),
        ("permission_id_count", MAX_RESOLUTION_IDS, MAX_RESOLUTION_IDS + 1, ExtensionControlLimitViolation.RESOLUTION_IDS),
        ("observation_count", MAX_OBSERVATIONS, MAX_OBSERVATIONS + 1, ExtensionControlLimitViolation.OBSERVATIONS),
        ("max_input_length", MAX_INPUT_TEXT_LENGTH, MAX_INPUT_TEXT_LENGTH + 1, ExtensionControlLimitViolation.INPUT_TEXT),
    ],
)
def test_resolution_boundaries(
    field: str,
    accepted: int,
    rejected: int,
    violation: ExtensionControlLimitViolation,
) -> None:
    accepted_values = {field: accepted}
    rejected_values = {field: rejected}
    assert extension_control_limit_violation(layer_sizes=(), **accepted_values) is None
    assert extension_control_limit_violation(layer_sizes=(), **rejected_values) is violation


def test_daemon_api_uses_shared_limits_and_no_longer_advertises_4096_controls() -> None:
    source = API_PATH.read_text(encoding="utf-8")
    assert "advertised_extension_control_limits" in source
    assert "MAX_CONTROLS_TOTAL" in source
    assert "_MAX_CONTROLS = 4096" not in source


def test_accessible_product_language_matches_visible_navigation() -> None:
    navigation = NAVIGATION_PATH.read_text(encoding="utf-8")
    rules_page = RULES_PAGE_PATH.read_text(encoding="utf-8")
    assert 'label: "Rules & exceptions"' in navigation
    assert 'description: "Remembered decisions, Guard Cloud rules, and exceptions"' in navigation
    assert 'label: "Extensions"' in navigation
    assert 'eyebrow="Rules & exceptions"' in rules_page
    assert 'href: "/policy"' in navigation
