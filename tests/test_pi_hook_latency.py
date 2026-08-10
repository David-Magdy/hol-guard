from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.client import HTTPResponse
from pathlib import Path
from typing import Protocol, cast

import pytest

from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessReview, HookProcessRunner
from codex_plugin_scanner.guard.daemon.manager import GUARD_DAEMON_COMPATIBILITY_VERSION
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


class _DaemonInternals(Protocol):
    auth_token: str
    hook_process_runner: HookProcessRunner


def _daemon_internals(daemon: GuardDaemonServer) -> _DaemonInternals:
    return cast(_DaemonInternals, vars(daemon)["_server"])


def _decode_json_object(payload: str | bytes) -> dict[str, object]:
    loaded = cast(object, json.loads(payload))
    assert isinstance(loaded, dict)
    return cast(dict[str, object], loaded)


def _read_json_object(response: HTTPResponse) -> dict[str, object]:
    return _decode_json_object(response.read())


def _bun_executable() -> str | None:
    path_without_guard_shims = os.pathsep.join(
        entry for entry in os.environ.get("PATH", "").split(os.pathsep) if "package-shims" not in entry
    )
    unwrapped = shutil.which("bun", path=path_without_guard_shims)
    if unwrapped is not None:
        return unwrapped
    user_install = Path.home() / ".bun" / "bin" / "bun"
    if user_install.is_file():
        return str(user_install)
    return shutil.which("bun")


def _pi_hook_request(*, daemon: GuardDaemonServer, guard_home: str, call_id: str) -> urllib.request.Request:
    query = urllib.parse.urlencode({"guard-home": guard_home, "home": guard_home})
    return urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?{query}",
        data=json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_call_id": call_id,
                "tool_name": "read",
                "tool_input": {"path": "README.md"},
            }
        ).encode(),
        headers={"Content-Type": "application/json", "X-Guard-Token": _daemon_internals(daemon).auth_token},
        method="POST",
    )


def test_review_required_pi_hook_returns_before_worker_deadline(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    (guard_home / "config.toml").write_text(
        'security_level = "custom"\n[risk_actions]\nlocal_secret_read = "review"\n',
        encoding="utf-8",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    assert _daemon_internals(daemon).hook_process_runner.wait_for_capacity(minimum_workers=1, timeout_seconds=5)
    query = urllib.parse.urlencode(
        {
            "guard-home": str(guard_home),
            "home": str(tmp_path),
            "workspace": str(tmp_path),
        }
    )
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?{query}",
        data=json.dumps(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Read",
                "tool_input": {"path": "~/.ssh/config"},
            }
        ).encode(),
        headers={"Content-Type": "application/json", "X-Guard-Token": _daemon_internals(daemon).auth_token},
        method="POST",
    )
    try:
        started = time.monotonic()
        with urllib.request.urlopen(request, timeout=2) as response:
            result = _read_json_object(response)
        elapsed = time.monotonic() - started
    finally:
        daemon.stop()

    assert result["decision"] == "deny"
    assert store.count_pending_requests(harness="pi") == 1
    assert elapsed < 1.45


def test_pi_hook_is_not_queued_behind_unrelated_overlay_free_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_started = threading.Event()
    release_first = threading.Event()

    def fake_review(**kwargs: object) -> HookProcessReview:
        payload = kwargs["payload"]
        assert isinstance(payload, dict)
        if payload["tool_call_id"] == "first":
            first_started.set()
            assert release_first.wait(timeout=2)
        return HookProcessReview({"decision": "allow"}, None)

    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    monkeypatch.setattr(_daemon_internals(daemon).hook_process_runner, "review", fake_review)
    daemon.start()
    first_result: list[dict[str, object]] = []

    def run_first() -> None:
        request = _pi_hook_request(daemon=daemon, guard_home=str(store.guard_home), call_id="first")
        with cast(HTTPResponse, urllib.request.urlopen(request, timeout=3)) as response:
            first_result.append(_read_json_object(response))

    first_thread = threading.Thread(target=run_first)
    first_thread.start()
    try:
        assert first_started.wait(timeout=1)
        request = _pi_hook_request(daemon=daemon, guard_home=str(store.guard_home), call_id="second")
        with cast(HTTPResponse, urllib.request.urlopen(request, timeout=1)) as response:
            second_result = _read_json_object(response)
    finally:
        release_first.set()
        first_thread.join(timeout=3)
        daemon.stop()

    assert second_result == {"decision": "allow"}
    assert first_result == [{"decision": "allow"}]


def test_pi_extension_keeps_fallbacks_inside_outer_hook_deadline(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source

    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "settings.json",
    )

    assert "const GUARD_TIMEOUT_MS = 4250;" in source
    assert "const GUARD_DEADLINE_RESERVE_MS = 250;" in source
    assert "const GUARD_DAEMON_TIMEOUT_MS = 3100;" in source
    assert "const GUARD_DAEMON_RECOVERY_TIMEOUT_MS = 250;" in source
    assert "const GUARD_DAEMON_RETRY_TIMEOUT_MS = 150;" in source
    assert "const GUARD_CLI_TIMEOUT_MS = 300;" in source
    assert 'const GUARD_ARGS = ["hook", "--json"' in source
    assert "compatibility_version !== GUARD_COMPATIBILITY_VERSION" in source
    assert "error.name === 'AbortError'" in source
    assert source.index("error.name === 'AbortError'") > source.index("await fetch")
    timeout_branch = source[source.index("error.name === 'AbortError'") :]
    assert 'recoveryKind: "transport-failure"' in timeout_branch
    assert "response.status === 401 || response.status === 403" in source
    assert 'recoveryKind: "authenticated-control-plane-failure"' in source
    assert "failure_kind=sys.argv[1]" in source
    assert "recover_guard_daemon_after_hook_failure" in source
