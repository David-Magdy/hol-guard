#!/usr/bin/env python3
"""Deterministic quality gate for the scanner assurance corpus."""

from __future__ import annotations

import argparse
import json
import statistics
import tempfile
import time
from pathlib import Path

from codex_plugin_scanner.assurance import run_assurance_checks
from codex_plugin_scanner.models import SEVERITY_ORDER, Severity
from tests.assurance_corpus import ATTACK_TEXT_CASES, BENIGN_TEXT_CASES

MIN_RECALL = 0.95
MIN_PRECISION = 0.95
MIN_F1 = 0.95
MAX_MEDIAN_CASE_SECONDS = 1.5


def _rule_ids(path: Path) -> set[str]:
    checks, _integrations = run_assurance_checks(path)
    return {finding.rule_id for check in checks for finding in check.findings}


def _has_high_finding(path: Path) -> bool:
    checks, _integrations = run_assurance_checks(path)
    return any(
        SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[Severity.HIGH]
        for check in checks
        for finding in check.findings
    )


def run_benchmark() -> dict[str, object]:
    true_positive = 0
    false_negative = 0
    false_positive = 0
    true_negative = 0
    durations: list[float] = []
    misses: list[dict[str, str]] = []
    false_alarms: list[dict[str, str]] = []

    with tempfile.TemporaryDirectory(prefix="hol-guard-assurance-benchmark-") as temporary:
        root = Path(temporary)
        for index, case in enumerate(ATTACK_TEXT_CASES):
            case_root = root / f"attack-{index:03d}"
            target = case_root / case.path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(case.content, encoding="utf-8")
            started = time.perf_counter()
            rules = _rule_ids(case_root)
            durations.append(time.perf_counter() - started)
            if case.expected_rule in rules:
                true_positive += 1
            else:
                false_negative += 1
                misses.append({"case": case.name, "expected": case.expected_rule})

        for index, (relative_path, content) in enumerate(BENIGN_TEXT_CASES):
            case_root = root / f"benign-{index:03d}"
            target = case_root / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            started = time.perf_counter()
            alarm = _has_high_finding(case_root)
            durations.append(time.perf_counter() - started)
            if alarm:
                false_positive += 1
                false_alarms.append({"case": relative_path, "reason": "high-or-critical finding"})
            else:
                true_negative += 1

    recall = true_positive / max(1, true_positive + false_negative)
    precision = true_positive / max(1, true_positive + false_positive)
    f1 = 2 * precision * recall / max(1e-12, precision + recall)
    median_seconds = statistics.median(durations) if durations else 0.0
    p95_seconds = sorted(durations)[min(len(durations) - 1, int(len(durations) * 0.95))] if durations else 0.0
    return {
        "schemaVersion": "scanner-assurance-benchmark.v1",
        "attackCases": len(ATTACK_TEXT_CASES),
        "benignCases": len(BENIGN_TEXT_CASES),
        "truePositive": true_positive,
        "falseNegative": false_negative,
        "falsePositive": false_positive,
        "trueNegative": true_negative,
        "recall": round(recall, 6),
        "precision": round(precision, 6),
        "f1": round(f1, 6),
        "medianCaseSeconds": round(median_seconds, 6),
        "p95CaseSeconds": round(p95_seconds, 6),
        "misses": misses,
        "falseAlarms": false_alarms,
        "thresholds": {
            "minimumRecall": MIN_RECALL,
            "minimumPrecision": MIN_PRECISION,
            "minimumF1": MIN_F1,
            "maximumMedianCaseSeconds": MAX_MEDIAN_CASE_SECONDS,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="scanner-assurance-benchmark.json")
    args = parser.parse_args()
    result = run_benchmark()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    failed = (
        result["recall"] < MIN_RECALL
        or result["precision"] < MIN_PRECISION
        or result["f1"] < MIN_F1
        or result["medianCaseSeconds"] > MAX_MEDIAN_CASE_SECONDS
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
