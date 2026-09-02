"""Authenticated daemon session used by the installed native SLO proof."""

from __future__ import annotations

import json
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from contextlib import suppress
from http.client import HTTPConnection, HTTPResponse
from pathlib import Path
from typing import cast

from codex_plugin_scanner.guard.adapters.codex_daemon_hook_auth import _DaemonResponseError
from codex_plugin_scanner.guard.adapters.codex_daemon_hook_transport import _daemon_response_once
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.native_resident_client import close_native_resident_clients
from codex_plugin_scanner.guard.native_runtime import native_runtime_health
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_adapter import Observation, is_allowed, payload, route_counts, route_delta
from scripts.native_slo_contract import MAX_READINESS_P95_MS

_MAX_HTTP_RESPONSE_BYTES = 2 * 1024 * 1024
_CAPACITY_FAIL_SAFE = {
    "decision": "deny",
    "model_output_action": "block",
    "policy_action": "deny",
    "reason_code": "daemon_capacity",
}
_CAPACITY_REASON_CODES = frozenset(
    {
        "daemon_capacity",
        "daemon_overloaded",
        "daemon_hook_queue_capacity",
        "daemon_hook_queue_bytes",
        "daemon_hook_deadline_exhausted",
        "native_overloaded",
    }
)


def stop_native_resident(runtime: Path, guard_home: Path) -> bool:
    """Stop one Rust resident through its bounded lifecycle command."""

    close_native_resident_clients(guard_home)
    with suppress(OSError, subprocess.TimeoutExpired):
        result = subprocess.run(
            (str(runtime), "resident-stop", "--state-dir", str(guard_home / "native-runtime")),
            check=False,
            capture_output=True,
            timeout=2,
        )
        return result.returncode == 0
    return False


def _request(
    daemon: GuardDaemonServer,
    *,
    guard_home: Path,
    workspace: Path,
    harness: str,
    request_payload: Mapping[str, object],
    connection: HTTPConnection | None = None,
) -> Mapping[str, object]:
    query = urllib.parse.urlencode({"home": str(guard_home), "workspace": str(workspace)})
    encoded = json.dumps(request_payload, separators=(",", ":"))
    if harness == "codex":
        try:
            response = cast(
                object,
                _daemon_response_once(
                    state_path=guard_home / "daemon-state.json",
                    query=query,
                    data=encoded,
                    timeout_seconds=5,
                ),
            )
        except _DaemonResponseError as error:
            if error.status != 503:
                raise RuntimeError("adapter request failed") from error
            return _CAPACITY_FAIL_SAFE.copy()
    else:
        try:
            path = f"/v1/hooks/{harness}?{query}"
            headers = {"Content-Type": "application/json", "X-Guard-Token": daemon._server.auth_token}
            if connection is None:
                request = urllib.request.Request(
                    f"http://127.0.0.1:{daemon.port}{path}",
                    data=encoded.encode("utf-8"),
                    headers=headers,
                    method="POST",
                )
                opened = cast(HTTPResponse, urllib.request.urlopen(request, timeout=5))
            else:
                connection.request("POST", path, body=encoded.encode("utf-8"), headers=headers)
                opened = connection.getresponse()
            status = opened.status
            raw = opened.read(_MAX_HTTP_RESPONSE_BYTES + 1)
            opened.close()
        except urllib.error.HTTPError as error:
            if error.code == 503:
                return _CAPACITY_FAIL_SAFE.copy()
            raise RuntimeError("adapter request failed") from error
        except (OSError, urllib.error.URLError) as error:
            raise RuntimeError("adapter request failed") from error
        if len(raw) > _MAX_HTTP_RESPONSE_BYTES:
            raise RuntimeError("adapter response exceeded bound")
        if status == 503:
            return _CAPACITY_FAIL_SAFE.copy()
        try:
            response = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("adapter response was not JSON") from error
    if not isinstance(response, Mapping):
        raise RuntimeError("native_installed_slo_failed: adapter response was not an object")
    return response


def _is_explicit_capacity_response(response: Mapping[str, object]) -> bool:
    """Recognize only the daemon's bounded overload/capacity outcomes."""

    reason_code = response.get("reason_code")
    return isinstance(reason_code, str) and reason_code in _CAPACITY_REASON_CODES


class AdapterSession:
    """One private daemon and workspace, with deterministic resident cleanup."""

    def __init__(self, runtime: Path) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="hol-guard-slo-")
        # Keep the synthetic paths canonical. macOS may expose ``/tmp`` as
        # ``/private/tmp`` after the daemon validates a hook workspace; using
        # one spelling avoids registering the same workspace twice and
        # invalidating the ACKed native policy snapshot on the first request.
        self.root = Path(self.temporary.name).resolve()
        self.guard_home = self.root / "guard-home"
        self.workspace = self.root / "workspace"
        self.guard_home.mkdir(mode=0o700)
        self.workspace.mkdir(mode=0o700)
        self.store = GuardStore(self.guard_home)
        self.daemon = GuardDaemonServer(self.store, host="127.0.0.1", port=0)
        self.runtime = runtime
        self.readiness_ms = 0.0
        self._connection: HTTPConnection | None = None
        self._owner_thread_id = 0

    def __enter__(self) -> AdapterSession:
        try:
            self.start()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def start(self) -> None:
        self.daemon.start()
        self._connection = HTTPConnection("127.0.0.1", self.daemon.port, timeout=5)
        self._owner_thread_id = threading.get_ident()
        started = time.perf_counter()
        prepared = self.daemon._server.hook_worker.prepare_workspace_policy(
            self.workspace,
            deadline=time.monotonic() + 0.25,
        )
        self.readiness_ms = (time.perf_counter() - started) * 1_000.0
        if prepared is None:
            raise RuntimeError("native_installed_slo_failed: native policy was not ready")
        if self.readiness_ms > MAX_READINESS_P95_MS:
            raise RuntimeError("native_installed_slo_failed: native readiness exceeded budget")

    def observe(
        self,
        harness: str,
        event: str,
        size_class: str,
        request_payload: Mapping[str, object] | None = None,
    ) -> Observation:
        request = request_payload or payload(event, size_class)
        before = route_counts(self.daemon._server.hook_worker.metrics.snapshot())
        started = time.perf_counter()
        response = _request(
            self.daemon,
            guard_home=self.guard_home,
            workspace=self.workspace,
            harness=harness,
            request_payload=request,
            connection=self._connection if threading.get_ident() == self._owner_thread_id else None,
        )
        elapsed_ms = (time.perf_counter() - started) * 1_000.0
        after = route_counts(self.daemon._server.hook_worker.metrics.snapshot())
        return Observation(
            harness,
            event,
            size_class,
            elapsed_ms,
            route_delta(before, after),
            is_allowed(event, response),
            _is_explicit_capacity_response(response),
        )

    def native_overload_count(self) -> int:
        """Return the process-local native overload counter for this session."""

        return native_runtime_health(self.guard_home).overloads

    def close(self) -> None:
        try:
            if self._connection is not None:
                self._connection.close()
        finally:
            try:
                self.daemon.stop()
            finally:
                deadline = time.monotonic() + 2.0
                while getattr(self.daemon._server, "active_hook_requests", 0) > 0 and time.monotonic() < deadline:
                    time.sleep(0.01)
                stop_native_resident(self.runtime, self.guard_home)
                self.temporary.cleanup()

    def stop_resident(self) -> bool:
        """Close serving-worker clients before a linearizable resident stop."""

        close_clients = getattr(self.daemon._server.hook_process_runner, "close_native_resident_clients", None)
        if callable(close_clients) and close_clients() is False:
            return False
        return stop_native_resident(self.runtime, self.guard_home)


__all__ = ["AdapterSession", "stop_native_resident"]
