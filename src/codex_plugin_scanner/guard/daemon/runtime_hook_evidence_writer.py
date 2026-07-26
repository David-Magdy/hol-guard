"""Bounded asynchronous persistence for non-authoritative hook evidence."""

from __future__ import annotations

import json
import threading
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TypedDict, cast, final

from ..cli.commands_support_command_activity import record_post_hook_command_activity_best_effort
from ..sqlite_tuning import sqlite_connect_timeout_override
from ..store import GuardStore


class RuntimeHookEvidenceWriterStats(TypedDict):
    queued: int
    queued_bytes: int
    accepted: int
    processed: int
    dropped: int
    failures: int
    running: bool


@dataclass(frozen=True, slots=True)
class _CommandActivityRecord:
    harness: str
    event: str
    payload: dict[str, object]
    succeeded: bool
    payload_bytes: int


@final
class RuntimeHookEvidenceWriter:
    """Keeps best-effort activity writes outside security-decision workers."""

    def __init__(
        self,
        *,
        store: GuardStore,
        max_records: int = 2_000,
        max_bytes: int = 16 * 1024 * 1024,
        max_batch: int = 50,
        batch_wait_seconds: float = 0.025,
    ) -> None:
        if min(max_records, max_bytes, max_batch) < 1 or batch_wait_seconds < 0:
            raise ValueError("runtime hook evidence writer limits are invalid")
        self._store = store
        self._guard_home = store.guard_home
        self._max_records = max_records
        self._max_bytes = max_bytes
        self._max_batch = max_batch
        self._batch_wait_seconds = batch_wait_seconds
        self._condition = threading.Condition()
        self._records: deque[_CommandActivityRecord] = deque()
        self._queued_bytes = 0
        self._accepted = 0
        self._processed = 0
        self._dropped = 0
        self._failures = 0
        self._stopping = False
        self._sqlite_timeout_seconds = 0.05
        self._thread = threading.Thread(
            target=self._run,
            name="hol-guard-hook-evidence",
            daemon=True,
        )
        self._thread.start()

    def submit_command_activity(
        self,
        *,
        harness: str,
        event: str,
        payload: Mapping[str, object],
        succeeded: bool,
    ) -> bool:
        try:
            encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
            decoded = cast(object, json.loads(encoded))
        except (TypeError, ValueError):
            with self._condition:
                self._dropped += 1
            return False
        if not isinstance(decoded, dict):
            with self._condition:
                self._dropped += 1
            return False
        snapshot = cast(dict[str, object], decoded)
        record = _CommandActivityRecord(
            harness=harness,
            event=event,
            payload=snapshot,
            succeeded=succeeded,
            payload_bytes=len(encoded),
        )
        with self._condition:
            if (
                self._stopping
                or len(self._records) >= self._max_records
                or self._queued_bytes + record.payload_bytes > self._max_bytes
            ):
                self._dropped += 1
                return False
            self._records.append(record)
            self._queued_bytes += record.payload_bytes
            self._accepted += 1
            self._condition.notify()
        return True

    def stats(self) -> RuntimeHookEvidenceWriterStats:
        with self._condition:
            return {
                "queued": len(self._records),
                "queued_bytes": self._queued_bytes,
                "accepted": self._accepted,
                "processed": self._processed,
                "dropped": self._dropped,
                "failures": self._failures,
                "running": self._thread.is_alive() and not self._stopping,
            }

    def stop(self, *, timeout_seconds: float = 1.0) -> bool:
        with self._condition:
            if self._records:
                self._dropped += len(self._records)
                self._records.clear()
                self._queued_bytes = 0
            self._stopping = True
            self._condition.notify_all()
        self._thread.join(timeout=max(0.0, timeout_seconds))
        return not self._thread.is_alive()

    def _run(self) -> None:
        while True:
            batch = self._next_batch()
            if not batch:
                return
            for index, record in enumerate(batch):
                with self._condition:
                    if self._stopping:
                        self._dropped += len(batch) - index
                        return
                try:
                    with sqlite_connect_timeout_override(self._sqlite_timeout_seconds):
                        _ = record_post_hook_command_activity_best_effort(
                            store=self._store,
                            guard_home=self._guard_home,
                            harness=record.harness,
                            event=record.event,
                            payload=record.payload,
                            succeeded=record.succeeded,
                        )
                except Exception:
                    with self._condition:
                        self._failures += 1
                finally:
                    with self._condition:
                        self._processed += 1

    def _next_batch(self) -> list[_CommandActivityRecord]:
        with self._condition:
            while not self._records and not self._stopping:
                _ = self._condition.wait()
            if not self._records:
                return []
            if not self._stopping and self._batch_wait_seconds:
                _ = self._condition.wait(timeout=self._batch_wait_seconds)
            batch: list[_CommandActivityRecord] = []
            while self._records and len(batch) < self._max_batch:
                record = self._records.popleft()
                self._queued_bytes -= record.payload_bytes
                batch.append(record)
            return batch


__all__ = ["RuntimeHookEvidenceWriter", "RuntimeHookEvidenceWriterStats"]
