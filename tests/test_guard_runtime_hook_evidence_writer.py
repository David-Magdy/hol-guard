from __future__ import annotations

import os
import sqlite3
import threading
import time
from errno import ENOSPC
from pathlib import Path
from unittest.mock import patch

import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.store import GuardStore


def test_writer_keeps_blocked_persistence_off_submitter_without_raw_payload(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()
    recorded: list[object] = []

    def record(**kwargs: object) -> bool:
        recorded.append(kwargs["has_command"])
        entered.set()
        assert release.wait(timeout=1)
        return True

    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.persist_deferred_post_hook_command_activity",
        side_effect=record,
    ):
        writer = RuntimeHookEvidenceWriter(store=GuardStore(tmp_path / "guard-home"))
        started = time.monotonic()
        metadata: dict[str, object] = {"command": "rg safe"}
        try:
            accepted = writer.submit_command_activity(
                harness="pi",
                event="PostToolUse",
                payload={"tool_name": "read", "tool_call_id": "private-request-id", "metadata": metadata},
                succeeded=True,
            )
            metadata["command"] = "changed after submission"
            elapsed = time.monotonic() - started
            assert accepted is True
            assert elapsed < 0.1
            assert entered.wait(timeout=1)
            journal = (tmp_path / "guard-home" / "runtime-hook-evidence.jsonl").read_text(encoding="utf-8")
            assert "rg safe" not in journal
            assert "changed after submission" not in journal
            assert "private-request-id" not in journal
        finally:
            release.set()
            assert writer.stop(timeout_seconds=1)

    assert writer.stats()["processed"] == 1
    assert recorded == [False]


def test_writer_drops_only_evidence_when_queue_is_full(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()

    def record(**_kwargs: object) -> bool:
        entered.set()
        assert release.wait(timeout=1)
        return True

    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.persist_deferred_post_hook_command_activity",
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
        assert writer.stats()["durable_pending"] == 1
        assert writer.stats()["failures"] >= 1
    finally:
        lock.rollback()
        lock.close()


def test_writer_drains_accepted_records_on_shutdown(tmp_path: Path) -> None:
    recorded: list[bool] = []

    def record(**kwargs: object) -> bool:
        recorded.append(bool(kwargs["has_command"]))
        return True

    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.persist_deferred_post_hook_command_activity",
        side_effect=record,
    ):
        writer = RuntimeHookEvidenceWriter(
            store=GuardStore(tmp_path / "guard-home"),
            batch_wait_seconds=0.025,
        )
        for command in ("first", "second", "third"):
            assert writer.submit_command_activity(
                harness="pi",
                event="PostToolUse",
                payload={"command": command},
                succeeded=True,
            )
        assert writer.stop(timeout_seconds=1)

    assert recorded == [True, True, True]
    assert writer.stats()["durable_pending"] == 0


def test_writer_recovers_accepted_record_after_failed_process(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    journal = guard_home / "runtime-hook-evidence.jsonl"
    failed = threading.Event()

    def fail(**_kwargs: object) -> bool:
        failed.set()
        raise sqlite3.OperationalError("database is locked")

    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.persist_deferred_post_hook_command_activity",
        side_effect=fail,
    ):
        first = RuntimeHookEvidenceWriter(store=GuardStore(guard_home), batch_wait_seconds=0)
        assert first.submit_command_activity(
            harness="pi",
            event="PostToolUse",
            payload={"command": "recover me"},
            succeeded=True,
        )
        assert failed.wait(timeout=1)
        assert first.stop(timeout_seconds=1)
        assert first.stats()["durable_pending"] == 1
        assert journal.stat().st_mode & 0o777 == 0o600

    recorded: list[object] = []
    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.persist_deferred_post_hook_command_activity",
        side_effect=lambda **kwargs: recorded.append(kwargs["has_command"]) or True,
    ):
        recovered = RuntimeHookEvidenceWriter(store=GuardStore(guard_home), batch_wait_seconds=0)
        assert recovered.stop(timeout_seconds=1)

    assert recovered.stats()["recovered"] == 1
    assert recovered.stats()["durable_pending"] == 0
    assert recorded == [True]


def test_writer_retries_transient_partial_batch_failure_live(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    attempts: list[int] = []

    def record(**kwargs: object) -> bool:
        del kwargs
        attempts.append(len(attempts) + 1)
        if len(attempts) == 2:
            raise sqlite3.OperationalError("partial batch failure")
        return True

    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.persist_deferred_post_hook_command_activity",
        side_effect=record,
    ):
        writer = RuntimeHookEvidenceWriter(store=GuardStore(guard_home), batch_wait_seconds=0.05)
        for command in ("first", "second", "third"):
            assert writer.submit_command_activity(
                harness="pi",
                event="PostToolUse",
                payload={"command": command},
                succeeded=True,
            )
        deadline = time.monotonic() + 1
        while writer.stats()["processed"] != 3 and time.monotonic() < deadline:
            time.sleep(0.01)
        assert writer.stop(timeout_seconds=1)

    assert attempts == [1, 2, 3, 4]
    assert writer.stats()["processed"] == 3
    assert writer.stats()["durable_pending"] == 0
    journal = (guard_home / "runtime-hook-evidence.jsonl").read_text(encoding="utf-8")
    assert journal == ""
    assert "first" not in journal
    assert "second" not in journal
    assert "third" not in journal


def test_writer_rejects_record_when_durable_journal_is_full(tmp_path: Path) -> None:
    writer = RuntimeHookEvidenceWriter(
        store=GuardStore(tmp_path / "guard-home"),
        batch_wait_seconds=0,
    )
    try:
        attempted = threading.Event()

        def fail_write(*_args: object) -> int:
            attempted.set()
            raise OSError(ENOSPC, "No space left on device")

        with patch("os.write", side_effect=fail_write):
            assert writer.submit_command_activity(
                harness="pi",
                event="PostToolUse",
                payload={"command": "not accepted"},
                succeeded=True,
            )
            assert attempted.wait(timeout=1)
            deadline = time.monotonic() + 1
            while writer.stats()["dropped"] != 1 and time.monotonic() < deadline:
                time.sleep(0.01)
        stats = writer.stats()
        assert stats["accepted"] == 1
        assert stats["dropped"] == 1
        assert stats["failures"] == 1
        assert stats["degraded"] is True
    finally:
        assert writer.stop(timeout_seconds=1)


@pytest.mark.skipif(os.name == "nt", reason="unprivileged Windows runners cannot create symlinks")
def test_writer_rejects_symlinked_journal_without_modifying_target(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    victim = tmp_path / "victim.txt"
    victim.write_text("do not modify", encoding="utf-8")
    (guard_home / "runtime-hook-evidence.jsonl").symlink_to(victim)

    writer = RuntimeHookEvidenceWriter(store=GuardStore(guard_home), batch_wait_seconds=0)
    try:
        assert writer.submit_command_activity(
            harness="pi",
            event="PostToolUse",
            payload={"command": "rg safe"},
            succeeded=True,
        )
        deadline = time.monotonic() + 1
        while writer.stats()["dropped"] != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        assert writer.stop(timeout_seconds=1)

    assert victim.read_text(encoding="utf-8") == "do not modify"
    assert writer.stats()["degraded"] is True


def test_writer_bounds_oversized_journal_recovery(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "runtime-hook-evidence.jsonl").write_bytes(b"x" * 65)

    writer = RuntimeHookEvidenceWriter(store=GuardStore(guard_home), max_bytes=64)
    try:
        assert writer.stats()["recovered"] == 0
        assert writer.stats()["degraded"] is True
    finally:
        assert writer.stop(timeout_seconds=1)
