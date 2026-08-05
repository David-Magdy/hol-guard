from __future__ import annotations

from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    target = Path(path)
    source = target.read_text(encoding="utf-8")
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"expected one match in {path}, found {count}: {old[:80]!r}")
    target.write_text(source.replace(old, new, 1), encoding="utf-8")


def replace_all(path: str, old: str, new: str, expected: int) -> None:
    target = Path(path)
    source = target.read_text(encoding="utf-8")
    count = source.count(old)
    if count != expected:
        raise RuntimeError(f"expected {expected} matches in {path}, found {count}: {old[:80]!r}")
    target.write_text(source.replace(old, new), encoding="utf-8")


DISPATCH = "src/codex_plugin_scanner/guard/cli/commands_dispatch_desktop.py"
replace_once(DISPATCH, "from datetime import datetime, timezone", "from datetime import datetime, timedelta, timezone")
replace_once(DISPATCH, "_MAX_HISTORY_ITEMS = 200\n", "")
replace_once(
    DISPATCH,
    "def _app_projection(item: dict[str, object]) -> dict[str, object]:",
    "def _app_projection(item: dict[str, object], *, runtime_active: bool) -> dict[str, object]:",
)
replace_once(
    DISPATCH,
    '''    if managed and review_count == 0 and warning_count == 0:
        protection = "protected"
        detail = "Guard management is installed and the latest local check is clean."
    elif managed:
''',
    '''    if managed and not runtime_active:
        protection = "needs_repair"
        detail = "Guard management is installed, but local enforcement is unavailable until the runtime is active."
    elif managed and review_count == 0 and warning_count == 0:
        protection = "protected"
        detail = "Guard management is installed and the latest local check is clean."
    elif managed:
''',
)
replace_once(
    DISPATCH,
    '''    receipts: list[dict[str, object]],
    core_version: str,
) -> dict[str, object]:
    harness_items = status_payload.get("harnesses")
    harnesses = harness_items if isinstance(harness_items, list) else []
    apps = [_app_projection(item) for item in harnesses if isinstance(item, dict)]

    runtime_status = _text(status_payload.get("runtime_status")) or "offline"
    managed_harnesses = _int(status_payload.get("managed_harnesses"))
    pending_count = len(pending_requests)
''',
    '''    receipts: list[dict[str, object]],
    core_version: str,
    oldest_pending_at: str | None = None,
    resolved_today_count: int | None = None,
    receipt_summary: dict[str, object] | None = None,
) -> dict[str, object]:
    runtime_status = _text(status_payload.get("runtime_status")) or "offline"
    runtime_active = runtime_status == "active"
    harness_items = status_payload.get("harnesses")
    harnesses = harness_items if isinstance(harness_items, list) else []
    apps = [
        _app_projection(item, runtime_active=runtime_active)
        for item in harnesses
        if isinstance(item, dict)
    ]

    managed_harnesses = _int(status_payload.get("managed_harnesses"))
    pending_count = _int(status_payload.get("pending_approvals"), len(pending_requests))
''',
)
replace_once(
    DISPATCH,
    '''    resolved_today = sum(
        1
        for item in approval_history[:_MAX_HISTORY_ITEMS]
        if _is_today(item.get("resolved_at"), today) and item.get("status") != "pending"
    )
    oldest_pending = min(
        (created for item in pending_requests if (created := _text(item.get("created_at"))) is not None),
        default=None,
    )
    blocked_today = sum(
        1
        for item in receipts
        if _receipt_decision(item) == "blocked" and _is_today(item.get("timestamp") or item.get("created_at"), today)
    )
    approved_today = sum(
        1
        for item in receipts
        if _receipt_decision(item) == "allowed" and _is_today(item.get("timestamp") or item.get("created_at"), today)
    )
    latest_at = next(
        (
            value
            for item in receipts
            if (value := _text(item.get("timestamp")) or _text(item.get("created_at"))) is not None
        ),
        None,
    )
''',
    '''    resolved_today = (
        resolved_today_count
        if isinstance(resolved_today_count, int) and not isinstance(resolved_today_count, bool)
        else sum(
            1
            for item in approval_history
            if _is_today(item.get("resolved_at"), today) and item.get("status") != "pending"
        )
    )
    oldest_pending = oldest_pending_at or min(
        (created for item in pending_requests if (created := _text(item.get("created_at"))) is not None),
        default=None,
    )
    if isinstance(receipt_summary, dict):
        blocked_today = _int(receipt_summary.get("blocked"))
        approved_today = _int(receipt_summary.get("approved"))
        latest_at = _text(receipt_summary.get("latest_at"))
    else:
        blocked_today = sum(
            1
            for item in receipts
            if _receipt_decision(item) == "blocked"
            and _is_today(item.get("timestamp") or item.get("created_at"), today)
        )
        approved_today = sum(
            1
            for item in receipts
            if _receipt_decision(item) == "allowed"
            and _is_today(item.get("timestamp") or item.get("created_at"), today)
        )
        latest_at = next(
            (
                value
                for item in receipts
                if (value := _text(item.get("timestamp")) or _text(item.get("created_at"))) is not None
            ),
            None,
        )
''',
)
replace_once(
    DISPATCH,
    '''    pending_requests = store.list_approval_requests(status="pending", limit=_MAX_PENDING_APPROVALS)
    approval_history = store.list_approval_requests(status=None, limit=_MAX_HISTORY_ITEMS)
    receipts = store.list_receipts()
    payload = build_desktop_bootstrap_payload(
        status_payload=status_payload,
        pending_requests=pending_requests,
        approval_history=approval_history,
        receipts=receipts,
        core_version=_core_version(),
    )
''',
    '''    now = datetime.now(timezone.utc)
    day_start = datetime.combine(now.date(), datetime.min.time(), tzinfo=timezone.utc)
    day_end = day_start + timedelta(days=1)
    day_start_text = day_start.isoformat()
    day_end_text = day_end.isoformat()

    pending_requests = store.list_approval_requests(status="pending", limit=_MAX_PENDING_APPROVALS)
    oldest_pending_at = store.oldest_approval_request_created_at(status="pending")
    resolved_today_count = store.count_approval_requests(
        status="resolved",
        resolved_at_from=day_start_text,
        resolved_at_before=day_end_text,
    )
    receipts = store.list_receipts(limit=_MAX_RECENT_RECEIPTS)
    receipt_summary = store.receipt_summary_between(start_at=day_start_text, before_at=day_end_text)
    payload = build_desktop_bootstrap_payload(
        status_payload=status_payload,
        pending_requests=pending_requests,
        approval_history=[],
        receipts=receipts,
        core_version=_core_version(),
        oldest_pending_at=oldest_pending_at,
        resolved_today_count=resolved_today_count,
        receipt_summary=receipt_summary,
    )
''',
)

APPROVALS = "src/codex_plugin_scanner/guard/store_approvals.py"
replace_once(
    APPROVALS,
    '''def count_approval_requests(
    connection: sqlite3.Connection,
    *,
    status: str | None = "pending",
    harness: str | None = None,
    search: str | None = None,
) -> int:
''',
    '''def count_approval_requests(
    connection: sqlite3.Connection,
    *,
    status: str | None = "pending",
    harness: str | None = None,
    search: str | None = None,
    resolved_at_from: str | None = None,
    resolved_at_before: str | None = None,
) -> int:
''',
)
replace_once(
    APPROVALS,
    '''    if search is not None:
        search_clause, search_params = _approval_search_clause(search)
        clauses.append(search_clause)
        params.extend(search_params)
    where_clause = f"where {' and '.join(clauses)}" if clauses else ""
''',
    '''    if search is not None:
        search_clause, search_params = _approval_search_clause(search)
        clauses.append(search_clause)
        params.extend(search_params)
    if resolved_at_from is not None:
        clauses.append("resolved_at >= ?")
        params.append(resolved_at_from)
    if resolved_at_before is not None:
        clauses.append("resolved_at < ?")
        params.append(resolved_at_before)
    where_clause = f"where {' and '.join(clauses)}" if clauses else ""
''',
)

FACADE = "src/codex_plugin_scanner/guard/store_approval_facade.py"
replace_once(
    FACADE,
    '''    def count_approval_requests(
        self,
        *,
        status: str | None = "pending",
        harness: str | None = None,
        search: str | None = None,
    ) -> int:
        with self._connect() as connection:
            return count_pending_approval_requests(connection, status=status, harness=harness, search=search)

    def count_pending_requests(self, *, harness: str | None = None, search: str | None = None) -> int:
''',
    '''    def count_approval_requests(
        self,
        *,
        status: str | None = "pending",
        harness: str | None = None,
        search: str | None = None,
        resolved_at_from: str | None = None,
        resolved_at_before: str | None = None,
    ) -> int:
        with self._connect() as connection:
            return count_pending_approval_requests(
                connection,
                status=status,
                harness=harness,
                search=search,
                resolved_at_from=resolved_at_from,
                resolved_at_before=resolved_at_before,
            )

    def oldest_approval_request_created_at(self, *, status: str = "pending") -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "select min(created_at) as oldest_created_at from approval_requests where status = ?",
                (status,),
            ).fetchone()
        if row is None:
            return None
        value = row["oldest_created_at"]
        return str(value) if isinstance(value, str) and value else None

    def count_pending_requests(self, *, harness: str | None = None, search: str | None = None) -> int:
''',
)

RECEIPTS = "src/codex_plugin_scanner/guard/store_receipts.py"
replace_once(
    RECEIPTS,
    '''    def receipt_analytics(
        self,
''',
    '''    def receipt_summary_between(self, *, start_at: str, before_at: str) -> dict[str, object]:
        with self._connect() as connection:
            if receipt_rollups_need_backfill(connection):
                backfill_receipt_rollups(connection)
            else:
                reconcile_dirty_receipt_rollups(connection)
            row = connection.execute(
                """
                select
                  count(*) as total,
                  coalesce(sum(case when s.policy_decision = 'block' then 1 else 0 end), 0) as blocked,
                  coalesce(sum(case when s.policy_decision = 'allow' then 1 else 0 end), 0) as approved,
                  max(r.timestamp) as latest_at
                from runtime_receipts r
                join receipt_rollup_actions s on s.receipt_id = r.receipt_id
                where r.timestamp >= ? and r.timestamp < ?
                """,
                (start_at, before_at),
            ).fetchone()
        if row is None:
            return {"total": 0, "blocked": 0, "approved": 0, "latest_at": None}
        latest_at = row["latest_at"]
        return {
            "total": int(row["total"]),
            "blocked": int(row["blocked"]),
            "approved": int(row["approved"]),
            "latest_at": str(latest_at) if isinstance(latest_at, str) and latest_at else None,
        }

    def receipt_analytics(
        self,
''',
)

PARSER = "src/codex_plugin_scanner/guard/cli/commands_parser.py"
replace_once(PARSER, "bootstrap,desktop,detect", "bootstrap,detect")

TESTS = "tests/test_guard_desktop_contract.py"
test_path = Path(TESTS)
test_source = test_path.read_text(encoding="utf-8")
appendix = '''


def test_desktop_bootstrap_degrades_managed_app_when_runtime_is_inactive() -> None:
    payload = build_desktop_bootstrap_payload(
        status_payload=_status_payload(managed=1, runtime="offline"),
        pending_requests=[],
        approval_history=[],
        receipts=[],
        core_version="3.0.0",
    )

    assert payload["status"] == "attention_required"
    assert payload["protection"]["state"] == "degraded"
    assert payload["apps"][0]["protection"] == "needs_repair"


def test_desktop_bootstrap_uses_store_level_aggregates_beyond_preview_limits() -> None:
    pending_preview = [
        {
            "request_id": f"approval-{index}",
            "harness": "codex",
            "created_at": f"2026-08-05T12:{index:02d}:00+00:00",
        }
        for index in range(20)
    ]
    payload = build_desktop_bootstrap_payload(
        status_payload=_status_payload(managed=1, pending=21),
        pending_requests=pending_preview,
        approval_history=[],
        receipts=[],
        core_version="3.0.0",
        oldest_pending_at="2026-08-05T11:00:00+00:00",
        resolved_today_count=250,
        receipt_summary={
            "blocked": 125,
            "approved": 75,
            "latest_at": "2026-08-05T23:59:00+00:00",
        },
    )

    assert payload["approvals"] == {
        "pending": 21,
        "resolvedToday": 250,
        "oldestPendingAt": "2026-08-05T11:00:00+00:00",
    }
    assert len(payload["pendingApprovals"]) == 20
    assert payload["receipts"]["blockedToday"] == 125
    assert payload["receipts"]["approvedToday"] == 75
    assert payload["receipts"]["latestAt"] == "2026-08-05T23:59:00+00:00"


def test_desktop_command_remains_hidden_from_root_usage() -> None:
    import argparse

    from codex_plugin_scanner.guard.cli.commands_parser import add_guard_root_parser

    parser = argparse.ArgumentParser(prog="hol-guard")
    add_guard_root_parser(parser)
    assert ",desktop," not in parser.format_usage()
'''
if "test_desktop_bootstrap_degrades_managed_app_when_runtime_is_inactive" in test_source:
    raise RuntimeError("Desktop review tests are already present")
test_path.write_text(test_source.rstrip() + appendix + "\n", encoding="utf-8")

WORKFLOW = ".github/workflows/desktop-contract-ci.yml"
replace_all(
    WORKFLOW,
    "      - src/codex_plugin_scanner/guard/cli/commands_support.py\n",
    """      - src/codex_plugin_scanner/guard/cli/commands_support.py
      - src/codex_plugin_scanner/guard/cli/product.py
      - src/codex_plugin_scanner/guard/store_approvals.py
      - src/codex_plugin_scanner/guard/store_approval_facade.py
      - src/codex_plugin_scanner/guard/store_receipts.py
""",
    expected=2,
)
replace_once(
    WORKFLOW,
    "        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10\n",
    """        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10
        with:
          persist-credentials: false
""",
)

print("Applied Desktop review fixes")
