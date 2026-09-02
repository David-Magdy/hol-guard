"""Minimal launcher for the package-bound Rust resident client.

Python supplies only the verified binary path, private Guard state root, bounded
bytes, and deadline. Rust owns discovery, authentication, framing, restart,
generation state, response binding, and resident lifecycle.
"""

from __future__ import annotations

import atexit
import re
import struct
import subprocess
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from contextvars import ContextVar
from pathlib import Path
from queue import Empty, Full, Queue

from .codex_hook_launch_runtime import (
    BoundedHookProcessResult,
    isolated_hook_environment,
)
from .codex_hook_launch_runtime import (
    run_isolated_hook_process as _legacy_run_isolated_hook_process,
)
from .native_resident_transport import write_frame

# Retain the old runner name as a test seam. Production always leaves this
# binding untouched and uses the persistent Rust client below.
run_isolated_hook_process = _legacy_run_isolated_hook_process

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_STREAM_FRAME_HEADER_BYTES = 4
_CLIENT_CLOSE_TIMEOUT_SECONDS = 0.5
_MAX_PERSISTENT_CLIENTS = 16
_MAX_PERSISTENT_POOLS = 16
_MAX_FAILURE_CODE_LENGTH = 128
_FAILURE_CODE_PATTERN = re.compile(r"native_[a-z0-9_]+")
_LAST_FAILURE_CODE: ContextVar[str | None] = ContextVar(
    "native_resident_client_failure_code",
    default=None,
)


def native_resident_client_failure_code() -> str | None:
    """Return the current context's privacy-safe native failure code."""
    return _LAST_FAILURE_CODE.get()


def _allowlisted_failure_code(stderr: str) -> str | None:
    for line in stderr.splitlines():
        if len(line) <= _MAX_FAILURE_CODE_LENGTH and _FAILURE_CODE_PATTERN.fullmatch(line):
            return line
    return None


def _classify_failure(result: BoundedHookProcessResult) -> str:
    if result.containment_failed:
        return "native_client_containment_failed"
    if result.timed_out:
        return "native_client_timed_out"
    if result.output_limit_exceeded:
        return "native_client_output_limit_exceeded"
    if result.returncode is None:
        return "native_client_status_missing"
    if result.returncode != 0:
        return "native_client_exit_nonzero"
    if not result.stdout:
        return "native_client_output_missing"
    return "native_client_process_failed"


def _record_failure_code(result: BoundedHookProcessResult) -> None:
    _LAST_FAILURE_CODE.set(_allowlisted_failure_code(result.stderr) or _classify_failure(result))


class _StreamFailure:
    """Sentinel for a client stream that exited before returning a frame."""


class _PersistentNativeClient:
    """One bounded Rust client process with a persistent stdin/stdout stream."""

    def __init__(self, *, executable: Path, state_dir: Path, environment: Mapping[str, str]) -> None:
        self._executable = executable
        self._state_dir = state_dir
        self._environment = isolated_hook_environment(environment)
        self._process: subprocess.Popen[bytes] | None = None
        self._responses: Queue[bytes | _StreamFailure] = Queue(maxsize=1)
        self._reader: threading.Thread | None = None
        self._lock = threading.Lock()
        # Keep process teardown out of the response wait.  The process-state
        # lock protects snapshots; this lock protects the response queue and
        # process snapshot until the response is consumed. Writes stay
        # outside it so close() can interrupt a blocked platform pipe writer.
        self._lifecycle_lock = threading.RLock()
        self._request_lock = threading.Lock()

    def _start(self) -> bool:
        if self._process is not None:
            if self._process.poll() is None:
                return True
            # Reap/close the previous generation before replacing its process
            # and response queue. Its reader may still be draining EOF.
            self._close_locked()
        responses: Queue[bytes | _StreamFailure] = Queue(maxsize=1)
        self._responses = responses
        try:
            process = subprocess.Popen(
                (
                    str(self._executable),
                    "resident-client-stream",
                    "--stdin",
                    str(self._state_dir),
                ),
                cwd=self._executable.parent,
                env=self._environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError:
            self._process = None
            return False
        self._process = process
        self._reader = threading.Thread(
            target=self._read_responses,
            args=(process, responses),
            name="hol-guard-native-client",
            daemon=True,
        )
        self._reader.start()
        return True

    def _read_responses(
        self,
        process: subprocess.Popen[bytes],
        responses: Queue[bytes | _StreamFailure],
    ) -> None:
        stdout = process.stdout if process is not None else None
        if stdout is None:
            return
        try:
            while True:
                header = stdout.read(_STREAM_FRAME_HEADER_BYTES)
                if not header:
                    break
                if len(header) != _STREAM_FRAME_HEADER_BYTES:
                    break
                length = struct.unpack(">I", header)[0]
                if length <= 0 or length > _MAX_RESPONSE_BYTES:
                    break
                response = stdout.read(length)
                if len(response) != length:
                    break
                try:
                    responses.put_nowait(response)
                except Full:
                    break
        except (OSError, ValueError):
            pass
        with suppress(Exception):
            responses.put_nowait(_StreamFailure())

    @staticmethod
    def _write_frame(
        stdin: object,
        frame: bytes,
        *,
        deadline_monotonic: float,
    ) -> bool:
        return write_frame(
            stdin,
            frame,
            deadline_monotonic=deadline_monotonic,
        )

    def _request_snapshot(
        self,
    ) -> tuple[subprocess.Popen[bytes], object, Queue[bytes | _StreamFailure]] | None:
        with self._lifecycle_lock, self._lock:
            if not self._start():
                _LAST_FAILURE_CODE.set("native_client_start_failed")
                return None
            process = self._process
            stdin = process.stdin if process is not None else None
            if stdin is None or process is None:
                _LAST_FAILURE_CODE.set("native_client_stdin_unavailable")
                return None
            return process, stdin, self._responses

    def request(self, payload: bytes, *, deadline_monotonic: float) -> bytes | None:
        if not payload or len(payload) > _MAX_REQUEST_BYTES:
            _LAST_FAILURE_CODE.set("native_client_request_invalid")
            return None
        with self._request_lock:
            snapshot = self._request_snapshot()
            if snapshot is None:
                return None
            process, stdin, responses = snapshot
            if not self._request_is_current(process, responses):
                _LAST_FAILURE_CODE.set("native_client_stream_failed")
                return None
            frame = struct.pack(">I", len(payload)) + payload
            if not self._write_frame(stdin, frame, deadline_monotonic=deadline_monotonic):
                self.close()
                _LAST_FAILURE_CODE.set(
                    "native_client_timed_out"
                    if time.monotonic() >= deadline_monotonic
                    else "native_client_frame_write_failed"
                )
                return None
            if not self._request_is_current(process, responses):
                _LAST_FAILURE_CODE.set("native_client_stream_failed")
                return None
            # A pool teardown may call close() while this request waits for
            # its response. Hold the lifecycle lock for that wait so teardown
            # cannot close the captured process or queue mid-read. The lock is
            # intentionally acquired after the write, allowing close() to
            # interrupt a blocked write on platforms that need a stoppable
            # writer fallback.
            with self._lifecycle_lock:
                if not self._request_is_current(process, responses):
                    _LAST_FAILURE_CODE.set("native_client_stream_failed")
                    return None
                remaining = deadline_monotonic - time.monotonic()
                if remaining <= 0:
                    self.close()
                    _LAST_FAILURE_CODE.set("native_client_timed_out")
                    return None
                try:
                    response = responses.get(timeout=remaining)
                except Empty:
                    self.close()
                    _LAST_FAILURE_CODE.set("native_client_timed_out")
                    return None
                if isinstance(response, _StreamFailure):
                    self.close()
                    _LAST_FAILURE_CODE.set("native_client_stream_failed")
                    return None
                return response

    def _request_is_current(
        self,
        process: subprocess.Popen[bytes],
        responses: Queue[bytes | _StreamFailure],
    ) -> bool:
        """Reject a snapshot invalidated by concurrent client teardown."""

        with self._lifecycle_lock, self._lock:
            return self._process is process and self._responses is responses and process.poll() is None

    def _close_locked(self) -> None:
        process = self._process
        reader = self._reader
        responses = self._responses
        self._process = None
        self._reader = None
        if process is None:
            return
        with suppress(Full):
            responses.put_nowait(_StreamFailure())
        if process.poll() is None:
            with suppress(OSError):
                process.terminate()
            try:
                process.wait(timeout=_CLIENT_CLOSE_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                with suppress(OSError):
                    process.kill()
                with suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=_CLIENT_CLOSE_TIMEOUT_SECONDS)
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                with suppress(OSError, ValueError):
                    stream.close()
        if reader is not None and reader is not threading.current_thread():
            reader.join(timeout=_CLIENT_CLOSE_TIMEOUT_SECONDS)

    def close(self) -> None:
        with self._lifecycle_lock, self._lock:
            self._close_locked()


class _PersistentNativeClientPool:
    """Bounded lazy pool of streams for one executable and Guard state root.

    A stream carries one request at a time because its response frames have no
    request identifier. Multiple persistent streams therefore provide bounded
    parallel dispatch without changing the authenticated wire protocol.
    """

    def __init__(self, *, executable: Path, state_dir: Path, environment: Mapping[str, str]) -> None:
        self._executable = executable
        self._state_dir = state_dir
        self._environment = environment
        self._clients: set[_PersistentNativeClient] = set()
        self._idle: list[_PersistentNativeClient] = []
        self._condition = threading.Condition()
        self._closed = False

    def _lease(self, *, deadline_monotonic: float) -> _PersistentNativeClient | None:
        with self._condition:
            while not self._closed:
                if self._idle:
                    return self._idle.pop()
                if len(self._clients) < _MAX_PERSISTENT_CLIENTS:
                    client = _PersistentNativeClient(
                        executable=self._executable,
                        state_dir=self._state_dir,
                        environment=self._environment,
                    )
                    self._clients.add(client)
                    return client
                remaining = deadline_monotonic - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(timeout=remaining)
        _LAST_FAILURE_CODE.set("native_client_pool_exhausted")
        return None

    def request(self, payload: bytes, *, deadline_monotonic: float) -> bytes | None:
        client = self._lease(deadline_monotonic=deadline_monotonic)
        if client is None:
            return None
        response: bytes | None = None
        try:
            response = client.request(payload, deadline_monotonic=deadline_monotonic)
            return response
        finally:
            close_client = False
            with self._condition:
                if client not in self._clients:
                    close_client = True
                elif self._closed or response is None:
                    self._clients.remove(client)
                    close_client = True
                else:
                    self._idle.append(client)
                self._condition.notify()
            if close_client:
                client.close()

    def close(self) -> None:
        with self._condition:
            self._closed = True
            clients = tuple(self._clients)
            self._clients.clear()
            self._idle.clear()
            self._condition.notify_all()
        for client in clients:
            client.close()


_CLIENTS_LOCK = threading.Lock()
_CLIENT_POOLS: dict[tuple[str, str], _PersistentNativeClientPool] = {}


def _client_pool_for(executable: Path, state_dir: Path, environment: Mapping[str, str]) -> _PersistentNativeClientPool:
    normalized_state_dir = state_dir.expanduser().resolve()
    key = (str(executable), str(normalized_state_dir))
    evicted: _PersistentNativeClientPool | None = None
    with _CLIENTS_LOCK:
        pool = _CLIENT_POOLS.get(key)
        if pool is None:
            if len(_CLIENT_POOLS) >= _MAX_PERSISTENT_POOLS:
                evicted_key = next(iter(_CLIENT_POOLS))
                evicted = _CLIENT_POOLS.pop(evicted_key)
            pool = _PersistentNativeClientPool(
                executable=executable,
                state_dir=normalized_state_dir,
                environment=environment,
            )
            _CLIENT_POOLS[key] = pool
    if evicted is not None:
        evicted.close()
    return pool


def close_native_resident_clients(guard_home: Path | None = None) -> None:
    """Close persistent Rust clients, optionally limited to one Guard home."""

    with _CLIENTS_LOCK:
        selected = [
            (key, pool)
            for key, pool in _CLIENT_POOLS.items()
            if guard_home is None or Path(key[1]).parent == guard_home.expanduser().resolve()
        ]
        for key, _pool in selected:
            _CLIENT_POOLS.pop(key, None)
    for _key, pool in selected:
        pool.close()


atexit.register(close_native_resident_clients)


def _legacy_native_resident_client_request(
    *,
    executable: Path,
    guard_home: Path,
    environment: Mapping[str, str],
    payload: bytes,
    timeout_seconds: float | None,
    raw_hook_envelope: bool,
    deadline_monotonic: float | None,
) -> bytes | None:
    """Exercise the former one-shot seam for isolated unit-test fakes only."""

    try:
        input_text = payload.decode("utf-8")
    except UnicodeDecodeError:
        _LAST_FAILURE_CODE.set("native_client_request_invalid")
        return None
    state_dir = guard_home / "native-runtime"
    command = "hook-client" if raw_hook_envelope else "resident-client"
    try:
        if deadline_monotonic is not None:
            result = run_isolated_hook_process(
                (str(executable), command, "--stdin", str(state_dir)),
                input_text=input_text,
                cwd=executable.parent,
                environment=dict(environment),
                timeout_seconds=None,
                deadline_monotonic=deadline_monotonic,
                output_limit=_MAX_RESPONSE_BYTES,
                windows_kill_on_job_close=False,
            )
        else:
            assert timeout_seconds is not None
            result = run_isolated_hook_process(
                (str(executable), command, "--stdin", str(state_dir)),
                input_text=input_text,
                cwd=executable.parent,
                environment=dict(environment),
                timeout_seconds=timeout_seconds,
                output_limit=_MAX_RESPONSE_BYTES,
                windows_kill_on_job_close=False,
            )
    except (OSError, RuntimeError, ValueError):
        _LAST_FAILURE_CODE.set("native_client_launcher_failed")
        return None
    if (
        result.returncode != 0
        or result.timed_out
        or result.output_limit_exceeded
        or result.containment_failed
        or not result.stdout
    ):
        _record_failure_code(result)
        return None
    return result.stdout.encode("utf-8")


def native_resident_client_request(
    *,
    executable: Path,
    guard_home: Path,
    environment: Mapping[str, str],
    payload: bytes,
    timeout_seconds: float | None = None,
    raw_hook_envelope: bool = False,
    deadline_monotonic: float | None = None,
) -> bytes | None:
    """Send bounded bytes through a persistent Rust resident client."""
    _LAST_FAILURE_CODE.set(None)
    if not payload or (deadline_monotonic is None and (timeout_seconds is None or timeout_seconds <= 0)):
        _LAST_FAILURE_CODE.set("native_client_request_invalid")
        return None
    if len(payload) > _MAX_REQUEST_BYTES:
        _LAST_FAILURE_CODE.set("native_client_request_invalid")
        return None
    if run_isolated_hook_process is not _legacy_run_isolated_hook_process:
        return _legacy_native_resident_client_request(
            executable=executable,
            guard_home=guard_home,
            environment=environment,
            payload=payload,
            timeout_seconds=timeout_seconds,
            raw_hook_envelope=raw_hook_envelope,
            deadline_monotonic=deadline_monotonic,
        )
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError:
        _LAST_FAILURE_CODE.set("native_client_request_invalid")
        return None
    del raw_hook_envelope
    deadline = deadline_monotonic
    if deadline is None:
        assert timeout_seconds is not None
        deadline = time.monotonic() + timeout_seconds
    return _client_pool_for(executable, guard_home / "native-runtime", environment).request(
        payload,
        deadline_monotonic=deadline,
    )


__all__ = [
    "close_native_resident_clients",
    "native_resident_client_failure_code",
    "native_resident_client_request",
]
