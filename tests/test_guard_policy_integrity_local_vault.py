"""Regression coverage for desktop policy-integrity local-vault recovery."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard import local_trust_controller as local_trust_controller_module
from codex_plugin_scanner.guard import store_policy_integrity_backend as policy_integrity_backend_module
from codex_plugin_scanner.guard.local_trust_controller import resolve_passive_trust_state
from codex_plugin_scanner.guard.store import (
    EncryptedFileSecretStore,
    GuardStore,
    SystemKeyringSecretStore,
)


def _disable_system_keyring(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(policy_integrity_backend_module.sys, "platform", "linux", raising=False)
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_backend_is_available",
        classmethod(lambda cls: False),
    )


def test_linux_policy_integrity_uses_local_vault_without_system_keyring(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_system_keyring(monkeypatch)

    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)

    assert isinstance(store._policy_integrity_secret_store, EncryptedFileSecretStore)
    before = store.get_policy_integrity_status()
    assert before["mode"] == "degraded"

    repaired = store.setup_policy_integrity(now="2026-08-07T20:00:00Z", include_items=False)

    assert repaired["mode"] == "protected"
    assert repaired["trust_status"]["runtime_protection"] == "protected"
    assert repaired["trust_status"]["remembered_rules"] == "enforced"


def test_linux_system_keyring_remains_authoritative_for_policy_integrity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Once available, the OS keyring remains the single authoritative integrity store.
    monkeypatch.setattr(policy_integrity_backend_module.sys, "platform", "linux", raising=False)
    monkeypatch.setattr(
        SystemKeyringSecretStore,
        "_backend_is_available",
        classmethod(lambda cls: True),
    )

    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)

    assert isinstance(store._policy_integrity_secret_store, SystemKeyringSecretStore)


def test_doctor_can_report_protected_after_linux_local_vault_repair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _disable_system_keyring(monkeypatch)
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    repaired = store.setup_policy_integrity(now="2026-08-07T20:00:00Z", include_items=False)

    monkeypatch.setattr(
        local_trust_controller_module,
        "load_authenticated_daemon_state",
        lambda _guard_home: {"trust_status": repaired["trust_status"]},
    )

    resolved = resolve_passive_trust_state(store, backend_requested="auto")

    assert resolved.backend_selected == "local-vault"
    assert resolved.mode == "protected"
    assert resolved.trust_status.runtime_protection == "protected"
    assert resolved.trust_status.remembered_rules == "enforced"
