"""Standalone CLI for free local leaked-secret detection."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .secret_detection import detector_version, secret_rule_catalog
from .secret_repository_scanner import (
    DEFAULT_MAX_COMMITS,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_FINDINGS,
    DEFAULT_MAX_TOTAL_BYTES,
    RepositorySecretScanResult,
    scan_repository_secrets,
)


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hol-guard-secrets",
        description=("Find leaked credentials locally. Raw secret values are never printed or sent to Guard Cloud."),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Scan a file or repository")
    scan.add_argument("target", nargs="?", default=".")
    scan.add_argument("--history", action="store_true", help="Also scan bounded Git history")
    scan.add_argument("--max-commits", type=_positive_int, default=DEFAULT_MAX_COMMITS)
    scan.add_argument("--max-files", type=_positive_int, default=DEFAULT_MAX_FILES)
    scan.add_argument("--max-file-bytes", type=_positive_int, default=DEFAULT_MAX_FILE_BYTES)
    scan.add_argument("--max-total-bytes", type=_positive_int, default=DEFAULT_MAX_TOTAL_BYTES)
    scan.add_argument("--max-findings", type=_positive_int, default=DEFAULT_MAX_FINDINGS)
    scan.add_argument("--fail-on-findings", action="store_true")
    scan.add_argument("--json", action="store_true")
    rules = subparsers.add_parser("rules", help="List built-in detector families")
    rules.add_argument("--json", action="store_true")
    return parser


def _write_scan(result: RepositorySecretScanResult, *, json_output: bool) -> None:
    public = result.to_public_dict()
    if json_output:
        print(json.dumps(public, sort_keys=True))
        return
    findings = result.findings
    print(
        f"HOL Guard Secrets: {len(findings)} finding(s), "
        f"{result.files_scanned} file version(s), "
        f"{result.commits_scanned} Git commit(s)."
    )
    for finding in findings:
        commit = f" @{finding.commit[:12]}" if finding.commit else ""
        print(
            f"- {finding.severity.upper()} {finding.family} at "
            f"{finding.path}:{finding.line}{commit} [{finding.confidence} confidence]"
        )
    if result.truncated:
        print("Scan reached a configured safety limit. Increase a bound and rescan for full coverage.")
    for error in result.errors:
        print(f"Warning: {error}", file=sys.stderr)
    print("Raw secret values are intentionally omitted.")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        rules = secret_rule_catalog()
        payload = {
            "schema": "guard-secret-rules.v1",
            "detector_version": detector_version(),
            "rules": rules,
        }
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            print(f"HOL Guard Secrets detector {payload['detector_version']}")
            for rule in rules:
                validation = str(rule["validation"])
                suffix = f", validates via {validation}" if validation != "none" else ""
                print(f"- {rule['family']} ({rule['severity']}{suffix})")
        return 0
    try:
        result = scan_repository_secrets(
            Path(args.target),
            include_history=bool(args.history),
            max_commits=args.max_commits,
            max_files=args.max_files,
            max_file_bytes=args.max_file_bytes,
            max_total_bytes=args.max_total_bytes,
            max_findings=args.max_findings,
        )
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    _write_scan(result, json_output=bool(args.json))
    return 3 if args.fail_on_findings and result.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
