"""Focused protection-repair retry behavior."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import protection_repair_retry
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.runtime.protection_health import ProtectionCheckStatus
from codex_plugin_scanner.guard.store import GuardStore


def test_protection_repair_all_retries_a_transient_containment_probe_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)
    monkeypatch.setattr(
        GuardStore,
        "setup_policy_integrity",
        lambda self, **_kwargs: {"mode": "protected"},
    )
    containment_probes: list[bool] = []

    def containment_payload(self, *, force_refresh=False):
        containment_probes.append(force_refresh)
        if len(containment_probes) == 1:
            raise RuntimeError("transient probe failure")
        return {}

    monkeypatch.setattr(
        daemon_server_module._GuardDaemonHandler,
        "_containment_health_payload",
        containment_payload,
    )
    monkeypatch.setattr(
        protection_repair_retry,
        "containment_health_signals",
        lambda value, **_kwargs: {
            check_id: SimpleNamespace(status=ProtectionCheckStatus.PASS)
            for check_id in (
                "decision_plane_compatibility",
                "containment_compatibility",
                "sandbox",
            )
        },
    )
    monkeypatch.setattr(GuardStore, "maintain_command_activity", lambda self, **_kwargs: None)
    monkeypatch.setattr(
        GuardStore,
        "get_command_activity_persistence_health",
        lambda self: SimpleNamespace(active_error_count=0),
    )
    monkeypatch.setattr(GuardStore, "count_command_activities", lambda self: 0)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}/v1/protection/repair",
        data=json.dumps({"check_id": "all"}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        daemon.stop()

    assert payload["repaired"] is True
    assert containment_probes == [True, True]
