"""Bounded, deadline-aware admission for local runtime hook reviews."""

from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final, Literal, TypedDict, final

RuntimeHookLane = Literal["decision", "content-security", "evidence"]
RuntimeHookAdmissionReason = Literal[
    "daemon_hook_deadline_exhausted",
    "daemon_hook_queue_capacity",
    "daemon_hook_queue_bytes",
]

_LANE_WEIGHTS: Final[dict[RuntimeHookLane, int]] = {
    "decision": 4,
    "content-security": 3,
    "evidence": 1,
}
_LANE_WHEEL: Final[tuple[RuntimeHookLane, ...]] = tuple(
    lane for lane, weight in _LANE_WEIGHTS.items() for _ in range(weight)
)


class RuntimeHookSchedulerStats(TypedDict):
    active: int
    active_limit: int
    queued: int
    queued_limit: int
    retained_bytes: int
    retained_bytes_limit: int
    admitted: int
    completed: int
    expired: int
    rejected: dict[str, int]
    per_harness_active: dict[str, int]
    per_harness_queued: dict[str, int]


@dataclass(slots=True)
class _QueuedHook:
    sequence: int
    harness: str
    client_key: str
    lane: RuntimeHookLane
    payload_bytes: int
    deadline: float
    admitted: bool = False


@final
class RuntimeHookPermit:
    """An acquired scheduler slot that must be released exactly once."""

    def __init__(self, scheduler: RuntimeHookScheduler, item: _QueuedHook):
        self._scheduler = scheduler
        self._item = item
        self._released = False

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        self._scheduler.release_permit(self._item)

    def __enter__(self) -> RuntimeHookPermit:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.release()


@final
class RuntimeHookByteReservation:
    """A bounded payload-byte reservation that can transfer to queued work."""

    def __init__(self, scheduler: RuntimeHookScheduler, payload_bytes: int):
        self._scheduler = scheduler
        self.payload_bytes = payload_bytes
        self._transferred = False
        self._released = False

    def transfer(self) -> None:
        if self._released or self._transferred:
            raise RuntimeError("runtime hook byte reservation is no longer transferable")
        self._transferred = True

    def is_owned_by(self, scheduler: RuntimeHookScheduler) -> bool:
        return self._scheduler is scheduler

    def resize(
        self,
        payload_bytes: int,
        *,
        deadline: float,
    ) -> RuntimeHookAdmissionReason | None:
        if self._released or self._transferred:
            raise RuntimeError("runtime hook byte reservation is no longer resizable")
        if payload_bytes < 0:
            raise ValueError("runtime hook byte reservation cannot be negative")
        if payload_bytes > self.payload_bytes:
            reason = self._scheduler.grow_reserved_bytes(
                current_bytes=self.payload_bytes,
                payload_bytes=payload_bytes,
                deadline=deadline,
            )
            if reason is not None:
                return reason
        released_bytes = self.payload_bytes - payload_bytes
        self.payload_bytes = payload_bytes
        if released_bytes > 0:
            self._scheduler.release_reserved_bytes(released_bytes)
        return None

    def release(self) -> None:
        if self._released or self._transferred:
            return
        self._released = True
        self._scheduler.release_reserved_bytes(self.payload_bytes)

    def __enter__(self) -> RuntimeHookByteReservation:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.release()


@dataclass(frozen=True, slots=True)
class RuntimeHookAdmission:
    permit: RuntimeHookPermit | None
    reason_code: RuntimeHookAdmissionReason | None


@final
class RuntimeHookScheduler:
    """Queues short hook bursts while bounding count, bytes, and wait time."""

    def __init__(
        self,
        *,
        active_limit: int = 32,
        per_harness_active_limit: int = 24,
        queued_limit: int = 128,
        per_harness_queued_limit: int = 64,
        per_client_queued_limit: int = 32,
        retained_bytes_limit: int = 32 * 1024 * 1024,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        limits = (
            active_limit,
            per_harness_active_limit,
            queued_limit,
            per_harness_queued_limit,
            per_client_queued_limit,
            retained_bytes_limit,
        )
        if any(limit < 1 for limit in limits):
            raise ValueError("runtime hook scheduler limits must be positive")
        self._active_limit = active_limit
        self._per_harness_active_limit = per_harness_active_limit
        self._queued_limit = queued_limit
        self._per_harness_queued_limit = per_harness_queued_limit
        self._per_client_queued_limit = per_client_queued_limit
        self._retained_bytes_limit = retained_bytes_limit
        self._monotonic = monotonic
        self._condition = threading.Condition()
        self._queues: dict[
            RuntimeHookLane,
            OrderedDict[tuple[str, str], deque[_QueuedHook]],
        ] = {lane: OrderedDict() for lane in _LANE_WEIGHTS}
        self._sequence = 0
        self._lane_cursor = 0
        self._active = 0
        self._active_by_harness: dict[str, int] = {}
        self._active_by_client: dict[str, int] = {}
        self._queued = 0
        self._queued_by_harness: dict[str, int] = {}
        self._queued_by_client: dict[str, int] = {}
        self._retained_bytes = 0
        self._admitted = 0
        self._completed = 0
        self._expired = 0
        self._rejected: dict[str, int] = {}

    def acquire(
        self,
        *,
        harness: str,
        client_key: str,
        lane: RuntimeHookLane,
        payload_bytes: int,
        deadline: float,
        byte_reservation: RuntimeHookByteReservation | None = None,
    ) -> RuntimeHookAdmission:
        if payload_bytes < 0:
            raise ValueError("payload_bytes must not be negative")
        with self._condition:
            now = self._monotonic()
            if deadline <= now:
                return self._reject("daemon_hook_deadline_exhausted")
            if self._queued >= self._queued_limit:
                return self._reject("daemon_hook_queue_capacity")
            if self._queued_by_harness.get(harness, 0) >= self._per_harness_queued_limit:
                return self._reject("daemon_hook_queue_capacity")
            if self._queued_by_client.get(client_key, 0) >= self._per_client_queued_limit:
                return self._reject("daemon_hook_queue_capacity")
            if byte_reservation is None and self._retained_bytes + payload_bytes > self._retained_bytes_limit:
                return self._reject("daemon_hook_queue_bytes")
            if byte_reservation is not None and byte_reservation.payload_bytes != payload_bytes:
                raise ValueError("runtime hook byte reservation does not match payload size")
            if byte_reservation is not None and not byte_reservation.is_owned_by(self):
                raise ValueError("runtime hook byte reservation belongs to another scheduler")

            self._sequence += 1
            item = _QueuedHook(
                sequence=self._sequence,
                harness=harness,
                client_key=client_key,
                lane=lane,
                payload_bytes=payload_bytes,
                deadline=deadline,
            )
            self._enqueue(item)
            if byte_reservation is not None:
                byte_reservation.transfer()
            else:
                self._retained_bytes += payload_bytes
            self._dispatch()
            while not item.admitted:
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    if self._remove_queued(item):
                        self._expired += 1
                        self._condition.notify_all()
                    return RuntimeHookAdmission(None, "daemon_hook_deadline_exhausted")
                _ = self._condition.wait(timeout=remaining)
                self._dispatch()
            return RuntimeHookAdmission(RuntimeHookPermit(self, item), None)

    def reserve_bytes(
        self,
        *,
        payload_bytes: int,
        deadline: float,
    ) -> tuple[RuntimeHookByteReservation | None, RuntimeHookAdmissionReason | None]:
        if payload_bytes < 0:
            raise ValueError("payload_bytes must not be negative")
        with self._condition:
            if deadline <= self._monotonic():
                admission = self._reject("daemon_hook_deadline_exhausted")
                return None, admission.reason_code
            if payload_bytes > self._retained_bytes_limit:
                admission = self._reject("daemon_hook_queue_bytes")
                return None, admission.reason_code
            while self._retained_bytes + payload_bytes > self._retained_bytes_limit:
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    admission = self._reject("daemon_hook_deadline_exhausted")
                    return None, admission.reason_code
                _ = self._condition.wait(timeout=remaining)
            self._retained_bytes += payload_bytes
            return RuntimeHookByteReservation(self, payload_bytes), None

    def release_reserved_bytes(self, payload_bytes: int) -> None:
        with self._condition:
            self._retained_bytes -= payload_bytes
            self._condition.notify_all()

    def grow_reserved_bytes(
        self,
        *,
        current_bytes: int,
        payload_bytes: int,
        deadline: float,
    ) -> RuntimeHookAdmissionReason | None:
        with self._condition:
            if payload_bytes > self._retained_bytes_limit:
                return self._reject("daemon_hook_queue_bytes").reason_code
            additional_bytes = payload_bytes - current_bytes
            if additional_bytes < 0:
                raise ValueError("runtime hook byte growth cannot be negative")
            while self._retained_bytes + additional_bytes > self._retained_bytes_limit:
                remaining = deadline - self._monotonic()
                if remaining <= 0:
                    return self._reject("daemon_hook_deadline_exhausted").reason_code
                _ = self._condition.wait(timeout=remaining)
            self._retained_bytes += additional_bytes
            return None

    def stats(self) -> RuntimeHookSchedulerStats:
        with self._condition:
            return {
                "active": self._active,
                "active_limit": self._active_limit,
                "queued": self._queued,
                "queued_limit": self._queued_limit,
                "retained_bytes": self._retained_bytes,
                "retained_bytes_limit": self._retained_bytes_limit,
                "admitted": self._admitted,
                "completed": self._completed,
                "expired": self._expired,
                "rejected": dict(self._rejected),
                "per_harness_active": dict(self._active_by_harness),
                "per_harness_queued": dict(self._queued_by_harness),
            }

    def _reject(self, reason_code: RuntimeHookAdmissionReason) -> RuntimeHookAdmission:
        self._rejected[reason_code] = self._rejected.get(reason_code, 0) + 1
        return RuntimeHookAdmission(None, reason_code)

    def _enqueue(self, item: _QueuedHook) -> None:
        clients = self._queues[item.lane]
        clients.setdefault((item.client_key, item.harness), deque()).append(item)
        self._queued += 1
        self._queued_by_harness[item.harness] = self._queued_by_harness.get(item.harness, 0) + 1
        self._queued_by_client[item.client_key] = self._queued_by_client.get(item.client_key, 0) + 1

    def _dispatch(self) -> None:
        self._expire_waiters()
        while self._active < self._active_limit and self._queued > 0:
            item = self._next_item()
            if item is None:
                break
            self._decrement_queued(item)
            item.admitted = True
            self._active += 1
            self._active_by_harness[item.harness] = self._active_by_harness.get(item.harness, 0) + 1
            self._active_by_client[item.client_key] = self._active_by_client.get(item.client_key, 0) + 1
            self._admitted += 1
        self._condition.notify_all()

    def _next_item(self) -> _QueuedHook | None:
        active_share_limit = max(1, math.ceil(self._active_limit / 2))
        for _ in range(len(_LANE_WHEEL)):
            lane = _LANE_WHEEL[self._lane_cursor]
            self._lane_cursor = (self._lane_cursor + 1) % len(_LANE_WHEEL)
            clients = self._queues[lane]
            if not clients:
                continue
            for _ in range(len(clients)):
                group_key, items = clients.popitem(last=False)
                client_key, _harness = group_key
                if self._active_by_harness.get(items[0].harness, 0) >= self._per_harness_active_limit:
                    clients[group_key] = items
                    continue
                competing_client = self._has_competing_client(client_key)
                if competing_client and self._active_by_client.get(client_key, 0) >= active_share_limit:
                    clients[group_key] = items
                    continue
                item = items.popleft()
                if items:
                    clients[group_key] = items
                return item
        return None

    def _has_competing_client(self, client_key: str) -> bool:
        return any(
            queued_client != client_key for clients in self._queues.values() for queued_client, _harness in clients
        )

    def _expire_waiters(self) -> None:
        now = self._monotonic()
        for clients in self._queues.values():
            for group_key in tuple(clients):
                items = clients[group_key]
                retained = deque(item for item in items if item.deadline > now)
                for item in items:
                    if item.deadline <= now:
                        self._drop_queued(item)
                        self._expired += 1
                if retained:
                    clients[group_key] = retained
                else:
                    _ = clients.pop(group_key, None)

    def _remove_queued(self, target: _QueuedHook) -> bool:
        clients = self._queues[target.lane]
        group_key = (target.client_key, target.harness)
        items = clients.get(group_key)
        if items is None:
            return False
        try:
            items.remove(target)
        except ValueError:
            return False
        if not items:
            _ = clients.pop(group_key, None)
        self._drop_queued(target)
        return True

    def _decrement_queued(self, item: _QueuedHook) -> None:
        self._queued -= 1
        self._decrement_counter(self._queued_by_harness, item.harness)
        self._decrement_counter(self._queued_by_client, item.client_key)

    def _drop_queued(self, item: _QueuedHook) -> None:
        self._decrement_queued(item)
        self._retained_bytes -= item.payload_bytes

    def release_permit(self, item: _QueuedHook) -> None:
        """Release one admitted work item and dispatch the next waiter."""

        with self._condition:
            self._active -= 1
            self._decrement_counter(self._active_by_harness, item.harness)
            self._decrement_counter(self._active_by_client, item.client_key)
            self._retained_bytes -= item.payload_bytes
            self._completed += 1
            self._dispatch()

    @staticmethod
    def _decrement_counter(counters: dict[str, int], key: str) -> None:
        remaining = counters[key] - 1
        if remaining:
            counters[key] = remaining
        else:
            _ = counters.pop(key)


__all__ = [
    "RuntimeHookAdmission",
    "RuntimeHookAdmissionReason",
    "RuntimeHookByteReservation",
    "RuntimeHookLane",
    "RuntimeHookPermit",
    "RuntimeHookScheduler",
    "RuntimeHookSchedulerStats",
]
