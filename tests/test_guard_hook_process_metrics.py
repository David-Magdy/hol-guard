from __future__ import annotations

from codex_plugin_scanner.guard.daemon.hook_process_metrics import increment_bounded_metric


def test_hook_process_metrics_bound_untrusted_label_cardinality() -> None:
    decisions: dict[str, int] = {}
    reason_codes: dict[str, int] = {}

    for index in range(100):
        increment_bounded_metric(decisions, f"decision_{index}")
        increment_bounded_metric(reason_codes, f"reason_{index}")
    increment_bounded_metric(decisions, "d" * 81)
    increment_bounded_metric(reason_codes, "r" * 81)

    assert len(decisions) == 32
    assert len(reason_codes) == 32
    assert sum(decisions.values()) == 101
    assert sum(reason_codes.values()) == 101
    assert decisions["unknown"] == 70
    assert reason_codes["unknown"] == 70


def test_hook_process_metrics_coalesce_prepopulated_limit_into_unknown() -> None:
    counts = {f"existing_{index}": 1 for index in range(32)}

    increment_bounded_metric(counts, "new_label")

    assert len(counts) == 32
    assert sum(counts.values()) == 33
    assert counts["unknown"] == 2
