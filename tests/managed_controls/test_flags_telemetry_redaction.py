from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.managed_controls.feature_flags import (
    ManagedControlsFeatureFlags,
)
from codex_plugin_scanner.guard.managed_controls.redaction import (
    redact_managed_controls,
)
from codex_plugin_scanner.guard.managed_controls.telemetry import (
    TelemetryPrivacyError,
    managed_controls_telemetry_event,
)


def test_feature_flags_can_disable_each_pipeline_stage() -> None:
    ManagedControlsFeatureFlags().validate()
    with pytest.raises(ValueError):
        ManagedControlsFeatureFlags(enforcement=True).validate()


def test_telemetry_is_allowlisted_and_privacy_safe() -> None:
    assert managed_controls_telemetry_event(
        {"event": "apply", "result": "success"}
    ) == {"event": "apply", "result": "success"}
    with pytest.raises(TelemetryPrivacyError):
        managed_controls_telemetry_event({"raw_command": "cat .env"})


def test_diagnostics_redact_sensitive_values_recursively() -> None:
    assert redact_managed_controls(
        {"extension_id": "command.git", "proof": "sensitive"}
    ) == {"extension_id": "command.git", "proof": "[REDACTED]"}
