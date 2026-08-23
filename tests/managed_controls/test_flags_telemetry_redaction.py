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
    assert managed_controls_telemetry_event({"event": "apply", "result": "success"}) == {
        "event": "apply",
        "result": "success",
    }
    with pytest.raises(TelemetryPrivacyError):
        managed_controls_telemetry_event({"raw_command": "cat .env"})
    with pytest.raises(TelemetryPrivacyError):
        managed_controls_telemetry_event({"event": "https://user:secret@example.test"})


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("event", "customer-acme"),
        ("result", "workspace-123"),
        ("control_count_bucket", "102"),
        ("latency_bucket", "123ms"),
    ),
)
def test_telemetry_rejects_noncanonical_identifiers(field: str, value: str) -> None:
    with pytest.raises(TelemetryPrivacyError):
        managed_controls_telemetry_event({field: value})


@pytest.mark.parametrize("depth", (1, 8, 64))
def test_telemetry_rejects_bounded_recursive_payloads(depth: int) -> None:
    nested: object = "sensitive"
    for _ in range(depth):
        nested = {"token": nested}
    with pytest.raises(TelemetryPrivacyError):
        managed_controls_telemetry_event({"event": nested})


def test_telemetry_accepts_only_canonical_buckets() -> None:
    assert managed_controls_telemetry_event(
        {"event": "drift_check", "result": "blocked", "control_count_bucket": 0}
    ) == {"event": "drift_check", "result": "blocked", "control_count_bucket": "0"}


def test_diagnostics_redact_sensitive_values_recursively() -> None:
    assert redact_managed_controls({"extension_id": "command.git", "proof": "sensitive"}) == {
        "extension_id": "command.git",
        "proof": "[REDACTED]",
    }
    assert redact_managed_controls({"access_token": "sensitive", "workspace_path": "/private"}) == {
        "access_token": "[REDACTED]",
        "workspace_path": "[REDACTED]",
    }
