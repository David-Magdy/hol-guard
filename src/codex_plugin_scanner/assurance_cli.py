"""Command-line entry point for layered scanner assurance operations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .assurance import run_assurance_checks
from .evidence_envelope import build_evidence_envelope, upload_evidence
from .runtime_assurance import SandboxPlan, run_sandbox
from .version import __version__


def _finding_payload(finding) -> dict[str, object]:
    return {
        "ruleId": finding.rule_id,
        "severity": finding.severity.value,
        "category": finding.category,
        "title": finding.title,
        "description": finding.description,
        "remediation": finding.remediation,
        "filePath": finding.file_path,
        "lineNumber": finding.line_number,
        "source": finding.source,
    }


def _scan(args: argparse.Namespace) -> int:
    root = Path(args.target).resolve()
    if not root.is_dir():
        print(f"Target is not a directory: {root}", file=sys.stderr)
        return 2
    checks, integrations = run_assurance_checks(root)
    findings = tuple(finding for check in checks for finding in check.findings)
    target_integration = next((item for item in integrations if item.name == "assurance-target"), None)
    target_digest = target_integration.metadata.get("target_digest", "") if target_integration else ""
    layers = [
        {
            "id": item.metadata.get("layer", item.name.removeprefix("assurance-")),
            "status": item.status,
            "analyzer": item.metadata.get("analyzer", "unknown"),
            "coverage": float(item.metadata.get("coverage_percent", "0")),
            "claims": {
                "findings": item.findings_count,
                "highOrCritical": int(item.metadata.get("high_or_critical", "0")),
            },
            "limitations": [
                value.strip()
                for value in item.metadata.get("limitations", "").split("|")
                if value.strip()
            ],
            "evidenceDigest": item.metadata.get("evidence_digest"),
        }
        for item in integrations
        if item.name != "assurance-target"
    ]
    envelope = build_evidence_envelope(
        target_digest=target_digest,
        scanner_version=__version__,
        layers=layers,
        findings=[_finding_payload(finding) for finding in findings],
        policy={"profile": args.profile},
        subject={"path": root.name},
    )
    output = json.dumps(envelope, indent=2)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output, encoding="utf-8")
    else:
        print(output)
    if args.upload:
        if not args.token:
            print("--token is required with --upload", file=sys.stderr)
            return 2
        receipt = upload_evidence(args.upload, envelope, token=args.token)
        print(json.dumps({"uploaded": True, "status": receipt.status_code, "digest": receipt.evidence_digest}))
    return 1 if any(finding.severity.value in {"critical", "high"} for finding in findings) else 0


def _detonate(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    output = Path(args.evidence_dir).resolve()
    command = tuple(args.command)
    if command and command[0] == "--":
        command = command[1:]
    plan = SandboxPlan(
        engine=args.engine,
        image=args.image,
        target=target,
        command=command,
        output_dir=output,
        timeout_seconds=args.timeout,
        memory_megabytes=args.memory,
        cpu_limit=args.cpus,
        pids_limit=args.pids,
        trace_syscalls=args.trace,
    )
    execution = run_sandbox(plan)
    output.mkdir(parents=True, exist_ok=True)
    evidence_path = output / "runtime-evidence.json"
    evidence_path.write_text(json.dumps(execution.evidence, indent=2), encoding="utf-8")
    print(str(evidence_path))
    outcome = execution.evidence.get("outcome", {})
    return 1 if outcome.get("timedOut") or outcome.get("returnCode") not in {0, None} else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="plugin-scanner-assure",
        description="Layered static, archive, native, provenance, and bounded runtime assurance.",
    )
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    scan = subparsers.add_parser("scan", help="Produce a layered extension-security evidence envelope.")
    scan.add_argument("target", nargs="?", default=".")
    scan.add_argument("--profile", default="consumer-install")
    scan.add_argument("--output")
    scan.add_argument("--upload", help="Credential-free HTTPS ingestion endpoint.")
    scan.add_argument("--token", help=argparse.SUPPRESS)
    scan.set_defaults(handler=_scan)

    detonate = subparsers.add_parser("detonate", help="Run an explicit command in a deny-by-default OCI sandbox.")
    detonate.add_argument("target")
    detonate.add_argument("--engine", choices=("docker", "podman"), required=True)
    detonate.add_argument("--image", required=True, help="Immutable image reference ending in @sha256:<digest>.")
    detonate.add_argument("--evidence-dir", required=True)
    detonate.add_argument("--timeout", type=int, default=20)
    detonate.add_argument("--memory", type=int, default=512)
    detonate.add_argument("--cpus", type=float, default=1.0)
    detonate.add_argument("--pids", type=int, default=64)
    detonate.add_argument("--trace", action="store_true")
    detonate.add_argument("command", nargs=argparse.REMAINDER)
    detonate.set_defaults(handler=_detonate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
