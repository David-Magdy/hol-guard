from __future__ import annotations

import argparse
import importlib
import json
import multiprocessing
import os
import queue
import signal
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from multiprocessing.connection import Connection
from pathlib import Path
from typing import TYPE_CHECKING, cast, final

from .hook_process_protocol import (
    HOOK_ENV_ALLOWLIST,
    applied_hook_environment,
    as_string_object_dict,
    capture_hook_command,
    is_pair,
)
from .hook_process_worker import HookProcessReview, HookWorkerSlot, terminate_worker_tree

if TYPE_CHECKING:
    from ..store import GuardStore
    from .hook_worker import HookWorker

_HOOK_PROCESS_LIMIT = 4
_HOOK_PROCESS_TIMEOUT_SECONDS = 1.45
_HOOK_PROCESS_READY_TIMEOUT_SECONDS = 5.0
_HOOK_PROCESS_RETRY_MAX_SECONDS = 5.0
_HOOK_SQLITE_TIMEOUT_ENV = "HOL_GUARD_INTERNAL_HOOK_SQLITE_TIMEOUT_MS"
_TERMINATE_SIGNAL = getattr(signal, "SIGTERM", 15)
_KILL_SIGNAL = getattr(signal, "SIGKILL", 9)


@final
class HookProcessRunner:
    def __init__(
        self,
        *,
        guard_home: Path | None = None,
        process_limit: int = _HOOK_PROCESS_LIMIT,
        timeout_seconds: float = _HOOK_PROCESS_TIMEOUT_SECONDS,
    ):
        if process_limit < 1:
            raise ValueError("process_limit must be positive")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._guard_home: Path | None = guard_home.resolve(strict=False) if guard_home is not None else None
        self._process_limit: int = process_limit
        self._timeout_seconds: float = timeout_seconds
        self._slots: queue.Queue[HookWorkerSlot] = queue.Queue(maxsize=process_limit)
        self._all_slots: dict[int, HookWorkerSlot] = {}
        self._recovery_event: threading.Event = threading.Event()
        self._spawn_thread: threading.Thread | None = None
        self._supervisor_thread: threading.Thread | None = None
        self._state_lock: threading.Lock = threading.Lock()
        self._metrics_lock: threading.Lock = threading.Lock()
        self._generation: int = 0
        self._closed: bool = False
        self._started: bool = False
        self._timeouts: int = 0
        self._failures: int = 0
        self._restarts: int = 0

    def start(self) -> None:
        """Prewarm the fixed worker set before the daemon accepts hooks."""

        with self._state_lock:
            if self._started and not self._closed:
                return
            if self._closed:
                self._slots = queue.Queue(maxsize=self._process_limit)
            self._recovery_event.clear()
            self._generation += 1
            generation = self._generation
            self._closed = False
            self._started = True
            supervisor = threading.Thread(
                target=lambda: self._supervise_capacity(generation),
                name="hol-guard-hook-worker-supervisor",
                daemon=True,
            )
            self._supervisor_thread = supervisor
        supervisor.start()
        deadline = time.monotonic() + _HOOK_PROCESS_READY_TIMEOUT_SECONDS
        while self._slots.qsize() < self._process_limit and time.monotonic() < deadline:
            _ = self._recovery_event.wait(timeout=min(0.02, max(0.0, deadline - time.monotonic())))

    def review(
        self,
        *,
        payload: Mapping[str, object],
        harness: str,
        home_dir: Path,
        guard_home: Path,
        workspace: Path | None,
        hook_env: Mapping[str, str],
    ) -> HookProcessReview:
        """Return parsed hook JSON or a stable fail-safe reason."""

        if self._closed:
            return HookProcessReview(None, "daemon_hook_process_closed")
        if not self._started:
            return HookProcessReview(None, "daemon_hook_process_not_ready")
        try:
            slot = self._slots.get_nowait()
        except queue.Empty:
            return HookProcessReview(None, "daemon_hook_process_overloaded")

        request = {
            "payload": dict(payload),
            "harness": harness,
            "home_dir": str(home_dir),
            "guard_home": str(guard_home),
            "workspace": str(workspace) if workspace is not None else None,
            "hook_env": {key: value for key, value in hook_env.items() if key in HOOK_ENV_ALLOWLIST},
        }
        try:
            slot.connection.send(("review", request))
            if not slot.connection.poll(self._timeout_seconds):
                self._increment_metric("timeouts")
                self._replace_slot_async(slot)
                return HookProcessReview(None, "daemon_hook_process_timeout")
            raw_message = slot.connection.recv()
        except (BrokenPipeError, EOFError, OSError):
            self._increment_metric("failures")
            self._replace_slot_async(slot)
            return HookProcessReview(None, "daemon_hook_process_failed")

        if not is_pair(raw_message):
            self._increment_metric("failures")
            self._replace_slot_async(slot)
            return HookProcessReview(None, "daemon_hook_process_invalid_json")
        message_type, result = raw_message
        if message_type != "result":
            self._increment_metric("failures")
            self._replace_slot_async(slot)
            return HookProcessReview(None, "daemon_hook_process_invalid_json")
        if slot.process.is_alive() and not self._closed:
            self._slots.put_nowait(slot)
        else:
            self._replace_slot_async(slot)
        typed_result = as_string_object_dict(result)
        if typed_result is None:
            return HookProcessReview(None, "daemon_hook_process_invalid_json")
        reason_code = typed_result.get("reason_code")
        response = typed_result.get("payload")
        if response is None:
            return HookProcessReview(
                None,
                reason_code if isinstance(reason_code, str) else "daemon_hook_process_failed",
            )
        typed_response = as_string_object_dict(response)
        if typed_response is None:
            return HookProcessReview(None, "daemon_hook_process_invalid_json")
        return HookProcessReview(typed_response, None)

    def stats(self) -> dict[str, int]:
        """Return content-free worker health counters."""

        with self._state_lock:
            worker_count = len(self._all_slots)
        with self._metrics_lock:
            return {
                "configured": self._process_limit,
                "workers": worker_count,
                "ready": self._slots.qsize(),
                "timeouts": self._timeouts,
                "failures": self._failures,
                "restarts": self._restarts,
            }

    def close(self) -> None:
        _ = self.close_contained()

    def close_contained(self) -> bool:
        with self._state_lock:
            self._closed = True
            self._started = False
            self._generation += 1
            slots = list(self._all_slots.values())
            supervisor = self._supervisor_thread
            spawn_thread = self._spawn_thread
            self._recovery_event.set()
        contained = True
        for slot in slots:
            contained = self._retire_slot(slot, graceful=True) and contained
        if supervisor is not None:
            supervisor.join(timeout=1.0)
        if spawn_thread is not None:
            spawn_thread.join(timeout=0.2)
        with self._state_lock:
            if supervisor is not None and not supervisor.is_alive():
                self._supervisor_thread = None
            if spawn_thread is not None and not spawn_thread.is_alive():
                self._spawn_thread = None
            contained = (
                contained and not self._all_slots and self._supervisor_thread is None and self._spawn_thread is None
            )
        return contained

    def _start_slot(self, *, generation: int) -> HookWorkerSlot:
        context = multiprocessing.get_context("spawn")
        parent_connection, child_connection = context.Pipe(duplex=True)
        process = context.Process(
            target=_hook_worker_main,
            args=(child_connection, str(self._guard_home) if self._guard_home is not None else None),
            name="hol-guard-hook-worker",
            daemon=True,
        )
        try:
            process.start()
        except BaseException:
            parent_connection.close()
            child_connection.close()
            raise
        child_connection.close()
        slot = HookWorkerSlot(process=process, connection=parent_connection)
        with self._state_lock:
            stale = self._closed or generation != self._generation
            self._all_slots[process.pid or id(slot)] = slot
        if stale:
            _ = self._retire_slot(slot)
        return slot

    @staticmethod
    def _slot_became_ready(slot: HookWorkerSlot, timeout: float) -> bool:
        if timeout <= 0:
            return False
        try:
            return slot.connection.poll(timeout) and slot.connection.recv() == ("ready", None)
        except (EOFError, OSError):
            return False

    def _supervise_capacity(self, generation: int) -> None:
        """Reconcile desired worker capacity with bounded spawn pressure."""

        retry_delay = 0.05
        while True:
            with self._state_lock:
                closed = self._closed or generation != self._generation
                should_wait = len(self._all_slots) >= self._process_limit
            if closed:
                return
            if should_wait:
                _ = self._recovery_event.wait()
                self._recovery_event.clear()
                retry_delay = 0.05
                continue
            self._recovery_event.clear()
            replacement = self._start_slot_interruptibly(generation)
            if replacement is None:
                with self._state_lock:
                    closed = self._closed or generation != self._generation
                if closed:
                    return
                _ = self._recovery_event.wait(timeout=retry_delay)
                retry_delay = min(retry_delay * 2, _HOOK_PROCESS_RETRY_MAX_SECONDS)
                continue
            if not self._slot_became_ready(replacement, _HOOK_PROCESS_READY_TIMEOUT_SECONDS):
                self._increment_metric("failures")
                if not self._retire_slot(replacement):
                    self._mark_containment_failed()
                    return
                _ = self._recovery_event.wait(timeout=retry_delay)
                retry_delay = min(retry_delay * 2, _HOOK_PROCESS_RETRY_MAX_SECONDS)
                continue
            try:
                self._slots.put_nowait(replacement)
            except queue.Full:
                if not self._retire_slot(replacement):
                    self._mark_containment_failed()
                    return
            retry_delay = 0.05

    def _start_slot_interruptibly(self, generation: int) -> HookWorkerSlot | None:
        outcomes: queue.Queue[HookWorkerSlot | BaseException] = queue.Queue(maxsize=1)

        def attempt() -> None:
            try:
                outcomes.put(self._start_slot(generation=generation))
            except BaseException as error:
                outcomes.put(error)
            finally:
                with self._state_lock:
                    if self._spawn_thread is threading.current_thread():
                        self._spawn_thread = None

        thread = threading.Thread(target=attempt, name="hol-guard-hook-worker-spawn", daemon=True)
        with self._state_lock:
            if self._closed or generation != self._generation:
                return None
            self._spawn_thread = thread
        thread.start()
        while thread.is_alive():
            _ = self._recovery_event.wait(timeout=0.05)
            with self._state_lock:
                if self._closed or generation != self._generation:
                    return None
        outcome = outcomes.get_nowait()
        if isinstance(outcome, BaseException):
            self._increment_metric("failures")
            return None
        return outcome

    def _replace_slot_async(self, slot: HookWorkerSlot) -> None:
        contained = self._retire_slot(slot)
        if not contained:
            self._mark_containment_failed()
            return
        self._increment_metric("restarts")
        self._recovery_event.set()

    def _mark_containment_failed(self) -> None:
        with self._state_lock:
            self._closed = True
            self._started = False
            self._generation += 1
        self._recovery_event.set()
        self._increment_metric("failures")

    def _increment_metric(self, metric: str) -> None:
        with self._metrics_lock:
            if metric == "timeouts":
                self._timeouts += 1
            elif metric == "failures":
                self._failures += 1
            elif metric == "restarts":
                self._restarts += 1

    def _retire_slot(self, slot: HookWorkerSlot, *, graceful: bool = False) -> bool:
        with slot.retire_lock:
            if slot.retired:
                return not slot.process.is_alive()
            slot.retired = True
        if graceful and slot.process.is_alive():
            with suppress(BrokenPipeError, OSError):
                slot.connection.send(("stop", None))
            slot.process.join(timeout=0.2)
        if slot.process.is_alive():
            terminate_worker_tree(slot.process, _TERMINATE_SIGNAL)
            slot.process.join(timeout=0.5)
        if slot.process.is_alive():
            terminate_worker_tree(slot.process, _KILL_SIGNAL)
            slot.process.join(timeout=0.5)
        contained = not slot.process.is_alive()
        if contained:
            with self._state_lock:
                _ = self._all_slots.pop(slot.process.pid or id(slot), None)
            with suppress(OSError):
                slot.connection.close()
        else:
            with slot.retire_lock:
                slot.retired = False
        return contained


def _hook_worker_main(connection: Connection, configured_guard_home: str | None) -> None:
    if os.name != "nt":
        with suppress(OSError):
            os.setsid()
    os.environ[_HOOK_SQLITE_TIMEOUT_ENV] = "250"
    for module_name in (
        "codex_plugin_scanner.guard.cli.commands_hook",
        "codex_plugin_scanner.guard.cli.commands_support_connect",
        "codex_plugin_scanner.guard.config",
    ):
        _ = importlib.import_module(module_name)
    stores: dict[str, GuardStore] = {}
    hook_workers: dict[str, HookWorker] = {}
    connection.send(("ready", None))
    while True:
        try:
            raw_message = cast(object, connection.recv())
        except EOFError:
            return
        if not is_pair(raw_message):
            connection.send(("result", {"payload": None, "reason_code": "daemon_hook_process_invalid_request"}))
            continue
        message_type, raw_request = raw_message
        if message_type == "stop":
            return
        typed_request = as_string_object_dict(raw_request)
        if message_type != "review" or typed_request is None:
            connection.send(("result", {"payload": None, "reason_code": "daemon_hook_process_invalid_request"}))
            continue
        try:
            response = _run_resident_hook_request(
                typed_request,
                stores=stores,
                hook_workers=hook_workers,
                configured_guard_home=configured_guard_home,
            )
        except BaseException:
            response = {"payload": None, "reason_code": "daemon_hook_process_failed"}
        connection.send(("result", response))


def _run_resident_hook_request(
    request: dict[str, object],
    *,
    stores: dict[str, GuardStore],
    hook_workers: dict[str, HookWorker],
    configured_guard_home: str | None,
) -> dict[str, object]:
    from ..adapters.base import HarnessContext
    from ..cli.commands_hook import _run_guard_hook_command
    from ..cli.commands_support_connect import _synced_policy_payload
    from ..config import load_guard_config, overlay_synced_guard_policy
    from ..store import GuardStore
    from .hook_worker import HookWorker, HookWorkerUnsupported

    payload = request.get("payload")
    harness = request.get("harness")
    home_value = request.get("home_dir")
    guard_home_value = request.get("guard_home")
    workspace_value = request.get("workspace")
    if (
        not isinstance(payload, dict)
        or not isinstance(harness, str)
        or not isinstance(home_value, str)
        or not isinstance(guard_home_value, str)
        or (workspace_value is not None and not isinstance(workspace_value, str))
    ):
        return {"payload": None, "reason_code": "daemon_hook_process_invalid_request"}
    guard_home = Path(guard_home_value).resolve(strict=False)
    if configured_guard_home is not None and guard_home != Path(configured_guard_home):
        return {"payload": None, "reason_code": "daemon_hook_process_guard_home_mismatch"}
    store_key = str(guard_home)
    store = stores.get(store_key)
    if store is None:
        store = GuardStore(guard_home)
        stores[store_key] = store
    home_dir = Path(home_value)
    workspace = Path(workspace_value) if isinstance(workspace_value, str) else None
    context = HarnessContext(
        home_dir=home_dir,
        workspace_dir=workspace,
        guard_home=guard_home,
        home_override_explicit=True,
        workspace_override_explicit=workspace is not None,
    )
    event_name = payload.get("hook_event_name", payload.get("event"))
    if event_name == "PostToolUse":
        worker = hook_workers.get(store_key)
        if worker is None:
            worker = HookWorker(store=store)
            hook_workers[store_key] = worker
        try:
            worker_payload = worker.review_http_payload(
                payload=payload,
                params={"runtime-harness": [harness]},
                default_harness=harness,
                home_dir=home_dir,
                guard_home=guard_home,
                workspace=workspace,
            )
        except HookWorkerUnsupported:
            pass
        else:
            return {"payload": worker_payload, "reason_code": None}
    with applied_hook_environment(request):
        config = overlay_synced_guard_policy(
            load_guard_config(guard_home, workspace=workspace),
            _synced_policy_payload(store),
        )
        args = argparse.Namespace(
            guard_command="hook",
            home=str(home_dir),
            guard_home=str(guard_home),
            workspace=str(workspace) if workspace is not None else None,
            runtime_harness=harness,
            harness=harness,
            artifact_id=None,
            artifact_name=None,
            policy_action=None,
            event_file=None,
            json=True,
        )
        return capture_hook_command(
            lambda output: _run_guard_hook_command(
                args,
                guard_home=guard_home,
                workspace=workspace,
                context=context,
                store=store,
                config=config,
                input_text=json.dumps(payload, separators=(",", ":")),
                output_stream=output,
            )
        )


__all__ = ["HookProcessReview", "HookProcessRunner"]
