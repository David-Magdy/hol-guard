"""Regression coverage for authenticated daemon generation refreshes."""

from __future__ import annotations

import io
import json
import sys
import threading
from http.server import HTTPServer
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge
from tests.codex_daemon_hook_bridge_fixtures import (
    _bridge_config,
    _DaemonHandler,
    _write_authenticated_daemon_files,
)


def test_authenticated_trust_metadata_refresh_keeps_same_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    guard_home = tmp_path / "guard-home"
    daemon = HTTPServer(("127.0.0.1", 0), _DaemonHandler)
    daemon_thread = threading.Thread(target=daemon.serve_forever, daemon=True)
    daemon_thread.start()
    _write_authenticated_daemon_files(guard_home, daemon.server_address[1])
    _DaemonHandler.challenge_mode = "refresh-trust-status"
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(json.dumps({"hook_event_name": "UserPromptSubmit"})),
    )
    config = _bridge_config(guard_home, daemon.server_address[1])
    config["fallback_command"] = [sys.executable, "-c", "raise SystemExit(1)"]

    try:
        exit_code = bridge.main(**config)
    finally:
        daemon.shutdown()
        daemon_thread.join(timeout=5)

    assert exit_code == 0
    assert _DaemonHandler.challenge_count == 1
    assert _DaemonHandler.captured_guard_token == "fixture-token"
    assert json.loads(str(_DaemonHandler.captured_hook_body))["hook_event_name"] == "UserPromptSubmit"
    assert json.loads(capsys.readouterr().out) == {}
