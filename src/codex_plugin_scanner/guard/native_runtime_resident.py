"""Resident local transport for the Rust PostToolUse runtime.

The resident service is POSIX-only in this wave. It runs through Guard's
existing contained process launcher, speaks a length-prefixed protocol over an
owner-only Unix socket, and falls back to the one-shot native path on any
startup, transport, or lifecycle failure.
"""

from __future__ import annotations

import atexit
import os
import socket
import stat
import threading
import time
from collections.abc import Mapping
from pathlib import Path

from .codex_hook_launch_runtime import run_isolated_hook_process

_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_SOCKET_PATH_BYTES = 100
_START_TIMEOUT_SECONDS = 0.4
_SERVICE_LIFETIME_SECONDS = 7 * 24 * 60 * 60
_SERVICE_OUTPUT_LIMIT = 64 * 1024


class _ResidentService:
    def __init__(
        self,
        *,
        executable: Path,
        identity_sha256: str,
        guard_home: Path,
        environment: Mapping[str, str],
    ) -> None:
        self.executable = executable
        self.identity_sha256 = identity_sha256
        self.guard_home = guard_home
        self.environment = dict(environment)
        self.socket_path = _resident_socket_path(guard_home, identity_sha256)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._starts = 0

    @property
    def starts(self) -> int:
        with self._lock:
            return self._starts

    def request(self, payload: bytes, *, timeout_seconds: float) -> bytes | None:
        if self.socket_path is None or len(payload) > _MAX_REQUEST_BYTES or timeout_seconds <= 0:
            return None
        response = _send_request(self.socket_path, payload, timeout_seconds=min(timeout_seconds, 0.05))
        if response is not None:
            return response
        if not self._ensure_started(timeout_seconds=min(timeout_seconds, _START_TIMEOUT_SECONDS)):
            return None
        return _send_request(self.socket_path, payload, timeout_seconds=timeout_seconds)

    def _ensure_started(self, *, timeout_seconds: float) -> bool:
        if self.socket_path is None or timeout_seconds <= 0:
            return False
        with self._lock:
            thread = self._thread
            if thread is None or not thread.is_alive():
                self._stop_event = threading.Event()
                thread = threading.Thread(
                    target=self._run,
                    name="hol-guard-native-runtime",
                    daemon=True,
                )
                self._thread = thread
                self._starts += 1
                thread.start()
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if self._socket_accepts_connections():
                return True
            with self._lock:
                if self._thread is None or not self._thread.is_alive():
                    return False
            time.sleep(0.01)
        return self._socket_accepts_connections()

    def _socket_accepts_connections(self) -> bool:
        if self.socket_path is None:
            return False
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(0.025)
                client.connect(str(self.socket_path))
            return True
        except OSError:
            return False

    def _run(self) -> None:
        socket_path = self.socket_path
        if socket_path is None:
            return
        _ = run_isolated_hook_process(
            (str(self.executable), "serve", "--socket", str(socket_path)),
            input_text="",
            cwd=self.executable.parent,
            environment=self.environment,
            timeout_seconds=_SERVICE_LIFETIME_SECONDS,
            output_limit=_SERVICE_OUTPUT_LIMIT,
            stop_event=self._stop_event,
        )

    def close(self) -> None:
        with self._lock:
            self._stop_event.set()
            thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=1.5)
        _unlink_owned_socket(self.socket_path)


_SERVICES_LOCK = threading.Lock()
_SERVICES: dict[tuple[str, str, str], _ResidentService] = {}


def _private_runtime_dir(guard_home: Path) -> Path | None:
    if os.name == "nt" or not hasattr(socket, "AF_UNIX"):
        return None
    try:
        resolved_guard_home = guard_home.expanduser().resolve(strict=True)
        guard_metadata = resolved_guard_home.lstat()
        if stat.S_ISLNK(guard_metadata.st_mode) or not stat.S_ISDIR(guard_metadata.st_mode):
            return None
        runtime_dir = resolved_guard_home / "native-runtime"
        runtime_dir.mkdir(mode=0o700, exist_ok=True)
        metadata = runtime_dir.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            return None
        current_uid = os.getuid() if hasattr(os, "getuid") else None
        if current_uid is not None and getattr(metadata, "st_uid", current_uid) != current_uid:
            return None
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            runtime_dir.chmod(0o700)
            metadata = runtime_dir.lstat()
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                return None
        return runtime_dir.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None


def _resident_socket_path(guard_home: Path, identity_sha256: str) -> Path | None:
    runtime_dir = _private_runtime_dir(guard_home)
    if runtime_dir is None:
        return None
    suffix = identity_sha256[:16] if identity_sha256 else "unknown"
    socket_path = runtime_dir / f"hook-v1-{suffix}.sock"
    if len(os.fsencode(socket_path)) > _MAX_SOCKET_PATH_BYTES:
        return None
    return socket_path


def _read_exact(client: socket.socket, length: int) -> bytes | None:
    if length < 0:
        return None
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = client.recv(min(remaining, 64 * 1024))
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _send_request(socket_path: Path, payload: bytes, *, timeout_seconds: float) -> bytes | None:
    if len(payload) > _MAX_REQUEST_BYTES or timeout_seconds <= 0:
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout_seconds)
            client.connect(str(socket_path))
            client.sendall(len(payload).to_bytes(4, "big") + payload)
            header = _read_exact(client, 4)
            if header is None:
                return None
            response_length = int.from_bytes(header, "big")
            if response_length > _MAX_RESPONSE_BYTES:
                return None
            return _read_exact(client, response_length)
    except (OSError, OverflowError):
        return None


def resident_native_request(
    *,
    executable: Path,
    identity_sha256: str,
    guard_home: Path,
    environment: Mapping[str, str],
    payload: bytes,
    timeout_seconds: float,
) -> bytes | None:
    """Send one request to a resident native runtime, starting it lazily."""
    if os.name == "nt" or not hasattr(socket, "AF_UNIX"):
        return None
    try:
        resolved_executable = executable.resolve(strict=True)
        resolved_guard_home = guard_home.expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None
    key = (str(resolved_executable), identity_sha256, str(resolved_guard_home))
    with _SERVICES_LOCK:
        service = _SERVICES.get(key)
        if service is None:
            service = _ResidentService(
                executable=resolved_executable,
                identity_sha256=identity_sha256,
                guard_home=resolved_guard_home,
                environment=environment,
            )
            _SERVICES[key] = service
    return service.request(payload, timeout_seconds=timeout_seconds)


def resident_service_starts(*, executable: Path, identity_sha256: str, guard_home: Path) -> int:
    """Return an aggregate-only lifecycle counter for tests and diagnostics."""
    try:
        key = (
            str(executable.resolve(strict=True)),
            identity_sha256,
            str(guard_home.expanduser().resolve(strict=True)),
        )
    except (OSError, RuntimeError, ValueError):
        return 0
    with _SERVICES_LOCK:
        service = _SERVICES.get(key)
    return service.starts if service is not None else 0


def close_resident_native_runtimes() -> None:
    """Stop every resident runtime through the contained launcher path."""
    with _SERVICES_LOCK:
        services = list(_SERVICES.values())
        _SERVICES.clear()
    for service in services:
        service.close()


def _unlink_owned_socket(socket_path: Path | None) -> None:
    if socket_path is None:
        return
    try:
        metadata = socket_path.lstat()
        if stat.S_ISSOCK(metadata.st_mode):
            socket_path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


atexit.register(close_resident_native_runtimes)


__all__ = [
    "close_resident_native_runtimes",
    "resident_native_request",
    "resident_service_starts",
]
