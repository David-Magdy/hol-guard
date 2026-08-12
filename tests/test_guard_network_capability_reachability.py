from __future__ import annotations

import copy
from pathlib import Path

from codex_plugin_scanner.guard.runtime.network_capability_reachability import (
    REQUIRED_CAPABILITY_IDS,
    load_reachability_manifest,
    repository_manifest_path,
    validate_reachability_manifest,
)
from codex_plugin_scanner.guard.runtime.network_status import build_network_status

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_repository_network_capability_manifest_is_truthful() -> None:
    manifest_path = repository_manifest_path(_REPOSITORY_ROOT)
    payload = load_reachability_manifest(manifest_path)

    assert validate_reachability_manifest(payload, repository_root=_REPOSITORY_ROOT) == ()
    assert {item["id"] for item in payload["capabilities"]} == REQUIRED_CAPABILITY_IDS


def test_advertised_network_capability_requires_installed_behavior_links() -> None:
    payload = copy.deepcopy(load_reachability_manifest(repository_manifest_path(_REPOSITORY_ROOT)))
    capability = payload["capabilities"][0]
    capability["advertised"] = True
    capability["state"] = "active"
    capability["achieved_grade"] = "deny-all"
    capability["production_ready"] = True

    errors = validate_reachability_manifest(payload, repository_root=_REPOSITORY_ROOT)

    assert any("production_entrypoint" in error for error in errors)
    assert any("installed_artifact" in error for error in errors)
    assert any("live_probe" in error for error in errors)
    assert any("active_generation_source" in error for error in errors)
    assert any("observer" in error for error in errors)
    assert any("behavioral_test" in error for error in errors)


def test_default_network_status_is_host_specific_and_unavailable_without_probe() -> None:
    linux_status = build_network_status(platform_name="linux")
    macos_status = build_network_status(platform_name="darwin")

    assert linux_status["host_platform"] == "linux"
    assert {backend["platform"] for backend in linux_status["backends"]} == {"linux"}
    assert macos_status["host_platform"] == "macos"
    assert {backend["platform"] for backend in macos_status["backends"]} == {"macos"}
    for status in (linux_status, macos_status):
        assert status["effective_grade"] == "unavailable"
        assert status["independently_observed_grade"] == "unavailable"
        assert status["protection_active"] is False
        assert status["independently_observed"] is False
        assert all(backend["installed"] is False for backend in status["backends"])
        assert all(backend["verified"] is False for backend in status["backends"])
        assert all(backend["active"] is False for backend in status["backends"])
        assert all(backend["observed"] is False for backend in status["backends"])
        assert all(backend["production_ready"] is False for backend in status["backends"])


def test_unknown_host_does_not_foreground_foreign_network_backends() -> None:
    status = build_network_status(platform_name="freebsd14")

    assert status["host_platform"] == "unsupported"
    assert status["backends"] == []
    assert status["reason_code"] == "unsupported-host-platform"
