from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from unittest.mock import patch

from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.store import GuardStore


def test_writer_keeps_blocked_persistence_off_submitter(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()
    recorded: list[object] = []

    def record(**kwargs: object) -> bool:
        recorded.append(kwargs["payload"])
        entered.set()
        assert release.wait(timeout=1)
        return True

    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.record_post_hook_command_activity_best_effort",
        side_effect=record,
    ):
        writer = RuntimeHookEvidenceWriter(store=GuardStore(tmp_path / "guard-home"))
        started = time.monotonic()
        metadata: dict[str, object] = {"command": "rg safe"}
        try:
            accepted = writer.submit_command_activity(
                harness="pi",
                event="PostToolUse",
                payload={"tool_name": "read", "metadata": metadata},
                succeeded=True,
            )
            metadata["command"] = "changed after submission"
            elapsed = time.monotonic() - started
            assert accepted is True
            assert elapsed < 0.1
            assert entered.wait(timeout=1)
        finally:
            release.set()
            assert writer.stop(timeout_seconds=1)

    assert writer.stats()["processed"] == 1
    assert recorded == [{"tool_name": "read", "metadata": {"command": "rg safe"}}]


def test_writer_drops_only_evidence_when_queue_is_full(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()

    def record(**_kwargs: object) -> bool:
        entered.set()
        assert release.wait(timeout=1)
        return True

    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.record_post_hook_command_activity_best_effort",
        side_effect=record,
    ):
        writer = RuntimeHookEvidenceWriter(
            store=GuardStore(tmp_path / "guard-home"),
            max_records=1,
            max_bytes=1_024,
            batch_wait_seconds=0,
        )
        try:
            assert writer.submit_command_activity(
                harness="pi",
                event="PostToolUse",
                payload={"command": "first"},
                succeeded=True,
            )
            assert entered.wait(timeout=1)
            assert writer.submit_command_activity(
                harness="pi",
                event="PostToolUse",
                payload={"command": "second"},
                succeeded=True,
            )
            assert not writer.submit_command_activity(
                harness="pi",
                event="PostToolUse",
                payload={"command": "third"},
                succeeded=True,
            )
            assert writer.stats()["dropped"] == 1
        finally:
            release.set()
            assert writer.stop(timeout_seconds=1)


def test_writer_stops_with_bounded_sqlite_contention(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    lock = sqlite3.connect(store.path)
    _ = lock.execute("begin immediate")
    writer = RuntimeHookEvidenceWriter(
        store=store,
        batch_wait_seconds=0,
    )
    try:
        assert writer.submit_command_activity(
            harness="pi",
            event="PostToolUse",
            payload={"command": "rg safe"},
            succeeded=True,
        )
        time.sleep(0.02)
        started = time.monotonic()
        assert writer.stop(timeout_seconds=1)
        assert time.monotonic() - started < 0.5
        assert writer.stats()["failures"] == 3
    finally:
        lock.rollback()
        lock.close()
