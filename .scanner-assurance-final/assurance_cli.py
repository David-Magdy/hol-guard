# pyright: basic
"""CLI for layered extension assurance, provenance, drift, and ingestion."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from .assurance.detonation import DetonationLimits, build_plan, execute_plan, load_plan, write_plan
from .assurance.drift import build_baseline, write_baseline
from .assurance.evidence import (
    build_evidence_envelope,
    parse_json_document,
    validate_assurance_payload,
    validate_evidence_envelope,
)
from .assurance.ingestion import EvidenceStore
from .assurance.inventory import build_inventory
from .assurance.limits import ScanLimits
from .assurance.models import Disposition
from .assurance.orchestrator import AssuranceOptions, scan_extension_assurance
from .assurance.policy import BUILTIN_POLICIES, load_policy
from .assurance.provenance import (
    build_artifact_statement,
    build_statement,
    generate_keypair,
    sign_statement,
    verify_envelope,
)
from .assurance.upload import SecureEvidenceUploader


EXIT_BY_DISPOSITION = {
    Disposition.ALLOW.value: 0,
    Disposition.WARN.value: 0,
    Disposition.REVIEW.value: 2,
    Disposition.BLOCK.value: 3,
    Disposition.ERROR.value: 4,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hol-guard-extension-security",
        description=(
            "Produce and consume independent security evidence for AI plugins, MCP servers, "
            "skills, and mixed extension repositories."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="Produce bounded multi-layer assurance evidence")
    scan.add_argument("target", nargs="?", default=".")
    scan.add_argument("--profile", choices=sorted(BUILTIN_POLICIES), default="balanced")
    scan.add_argument("--policy", type=Path)
    scan.add_argument("--baseline", type=Path)
    scan.add_argument("--provenance", type=Path)
    scan.add_argument("--trusted-key", type=Path, action="append", default=[])
    scan.add_argument("--detonation-plan", type=Path)
    scan.add_argument("--detonation-observation", type=Path)
    scan.add_argument("--osv", action="store_true", help="Add bounded no-redirect OSV evidence")
    scan.add_argument("--output", type=Path)

    baseline = commands.add_parser("baseline", help="Create an exact-artifact drift baseline")
    baseline.add_argument("target", nargs="?", default=".")
    baseline.add_argument("--profile", choices=sorted(BUILTIN_POLICIES), default="balanced")
    baseline.add_argument("--policy", type=Path)
    baseline.add_argument("--output", type=Path, required=True)

    keygen = commands.add_parser("keygen", help="Generate an Ed25519 provenance keypair")
    keygen.add_argument("--private-key", type=Path, required=True)
    keygen.add_argument("--public-key", type=Path, required=True)

    artifact_attest = commands.add_parser(
        "attest-artifact",
        help="Sign exact artifact provenance before scanning",
    )
    artifact_attest.add_argument("target", nargs="?", default=".")
    artifact_attest.add_argument("--private-key", type=Path, required=True)
    artifact_attest.add_argument("--output", type=Path, required=True)

    attest = commands.add_parser("attest", help="Sign an assurance report as DSSE provenance")
    attest.add_argument("report", type=Path)
    attest.add_argument("--private-key", type=Path, required=True)
    attest.add_argument("--output", type=Path, required=True)

    verify = commands.add_parser("verify-attestation", help="Verify a DSSE assurance attestation")
    verify.add_argument("attestation", type=Path)
    verify.add_argument("--public-key", type=Path, action="append", required=True)
    verify.add_argument("--artifact-digest")
    verify.add_argument("--evidence-digest")

    envelope = commands.add_parser(
        "envelope",
        help="Wrap assurance evidence for Cloud or registry ingestion",
    )
    envelope.add_argument("report", type=Path)
    envelope.add_argument("--tenant", required=True)
    envelope.add_argument("--subject", required=True)
    envelope.add_argument("--sequence", type=int, default=1)
    envelope.add_argument("--provenance", type=Path)
    envelope.add_argument("--output", type=Path, required=True)

    ingest = commands.add_parser(
        "ingest-evidence",
        help="Independently verify, accept, or quarantine evidence",
    )
    ingest.add_argument("evidence", type=Path)
    ingest.add_argument("--database", type=Path, required=True)
    ingest.add_argument("--profile", choices=sorted(BUILTIN_POLICIES), default="balanced")
    ingest.add_argument("--policy", type=Path)
    ingest.add_argument("--trusted-key", type=Path, action="append", default=[])

    latest = commands.add_parser("latest-evidence", help="Read latest evidence for a tenant subject")
    latest.add_argument("--database", type=Path, required=True)
    latest.add_argument("--tenant", required=True)
    latest.add_argument("--subject", required=True)
    latest.add_argument("--publishable-only", action="store_true")

    plan = commands.add_parser(
        "detonation-plan",
        help="Build an immutable exact-artifact no-network container plan",
    )
    plan.add_argument("target", nargs="?", default=".")
    plan.add_argument("--image", required=True)
    plan.add_argument("--runtime", choices=("docker", "podman"), default="docker")
    plan.add_argument("--timeout", type=int, default=30)
    plan.add_argument("--seccomp", type=Path)
    plan.add_argument("--gvisor", action="store_true")
    plan.add_argument("--output", type=Path, required=True)
    plan.add_argument("command_args", nargs=argparse.REMAINDER)

    detonate = commands.add_parser("detonate", help="Execute a reviewed, digest-bound plan")
    detonate.add_argument("plan", type=Path)
    detonate.add_argument("--output", type=Path, required=True)

    upload = commands.add_parser(
        "upload-evidence",
        help="Upload evidence to an explicitly allowlisted HTTPS endpoint",
    )
    upload.add_argument("evidence", type=Path)
    upload.add_argument("--endpoint", required=True)
    upload.add_argument("--allow-host", action="append", required=True)
    upload.add_argument("--token-env", default="HOL_GUARD_EVIDENCE_TOKEN")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        handlers = {
            "scan": _run_scan,
            "baseline": _run_baseline,
            "keygen": _run_keygen,
            "attest-artifact": _run_attest_artifact,
            "attest": _run_attest,
            "verify-attestation": _run_verify,
            "envelope": _run_envelope,
            "ingest-evidence": _run_ingest,
            "latest-evidence": _run_latest,
            "detonation-plan": _run_plan,
            "detonate": _run_detonate,
            "upload-evidence": _run_upload,
        }
        handler = handlers.get(args.command)
        if handler is None:
            return 4
        return handler(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4


def _run_scan(args: argparse.Namespace) -> int:
    report = scan_extension_assurance(
        args.target,
        AssuranceOptions(
            profile=args.profile,
            policy_path=args.policy,
            baseline_path=args.baseline,
            provenance_envelope_path=args.provenance,
            trusted_public_keys=tuple(args.trusted_key),
            detonation_plan_path=args.detonation_plan,
            detonation_observation_path=args.detonation_observation,
            osv=args.osv,
        ),
    )
    _emit_json(report.to_payload(), args.output)
    return EXIT_BY_DISPOSITION[report.decision.disposition.value]


def _run_baseline(args: argparse.Namespace) -> int:
    report = scan_extension_assurance(
        args.target,
        AssuranceOptions(profile=args.profile, policy_path=args.policy),
    )
    inventory = build_inventory(Path(report.artifact_root), ScanLimits())
    if inventory.limit_reached or any(entry.kind == "regular" and not entry.readable for entry in inventory.entries):
        raise ValueError("cannot create an approved baseline from incomplete inventory")
    files = tuple(
        {
            "path": entry.relative_path,
            "sha256": entry.sha256,
            "size": entry.size,
            "mode": entry.mode & 0o7777,
            "kind": entry.kind,
        }
        for entry in inventory.entries
    )
    payload = report.to_payload()
    baseline = build_baseline(
        artifact_digest=report.artifact_digest,
        files=files,
        dependencies=tuple(payload["dependencies"]),
        native_artifacts=tuple(payload["native_artifacts"]),
        capabilities=tuple(payload["capabilities"]),
        endpoints=(),
        commands=(),
        lifecycle_scripts=tuple(
            finding["fingerprint"]
            for finding in payload["findings"]
            if finding["rule_id"] == "ASSURANCE_PACKAGE_LIFECYCLE_SCRIPT"
        ),
        security_controls=(),
    )
    write_baseline(args.output, baseline)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "artifact_digest": report.artifact_digest,
                "baseline_digest": baseline["baseline_digest"],
            },
            indent=2,
        )
    )
    return EXIT_BY_DISPOSITION[report.decision.disposition.value]


def _run_keygen(args: argparse.Namespace) -> int:
    key_id = generate_keypair(args.private_key, args.public_key)
    print(json.dumps({"key_id": key_id}, indent=2))
    return 0


def _run_attest_artifact(args: argparse.Namespace) -> int:
    root = Path(args.target).resolve(strict=True)
    inventory = build_inventory(root, ScanLimits())
    if inventory.limit_reached or any(entry.kind == "regular" and not entry.readable for entry in inventory.entries):
        raise ValueError("artifact provenance requires a complete stable inventory")
    from .version import __version__

    statement = build_artifact_statement(
        artifact_digest=inventory.artifact_digest,
        scanner_version=__version__,
    )
    signed = sign_statement(statement, args.private_key)
    _emit_json(signed, args.output)
    return 0


def _run_attest(args: argparse.Namespace) -> int:
    report = parse_json_document(args.report.read_bytes())
    validated = validate_assurance_payload(report)
    statement = build_statement(
        artifact_digest=str(validated["artifact_digest"]),
        evidence_digest=str(validated["evidence_digest"]),
        scanner_version=str(validated["scanner_version"]),
        decision=str(validated["decision"]["disposition"]),
        coverage_state=str(validated["coverage"]["state"]),
        assurance_level=str(validated["assurance_level"]),
    )
    signed = sign_statement(statement, args.private_key)
    _emit_json(signed, args.output)
    return 0


def _run_verify(args: argparse.Namespace) -> int:
    envelope = parse_json_document(args.attestation.read_bytes())
    result = verify_envelope(
        envelope,
        tuple(args.public_key),
        expected_artifact_digest=args.artifact_digest,
        expected_evidence_digest=args.evidence_digest,
    )
    print(json.dumps(asdict(result), indent=2, default=str))
    return 0 if result.verified else 3


def _run_envelope(args: argparse.Namespace) -> int:
    report = validate_assurance_payload(parse_json_document(args.report.read_bytes()))
    provenance = None
    if args.provenance:
        provenance = parse_json_document(args.provenance.read_bytes())
        if not isinstance(provenance, dict):
            raise ValueError("provenance must be an object")
    envelope = build_evidence_envelope(
        report,
        tenant_id=args.tenant,
        subject_id=args.subject,
        sequence=args.sequence,
        provenance_envelope=provenance,
    )
    _emit_json(envelope, args.output)
    return 0


def _run_ingest(args: argparse.Namespace) -> int:
    envelope = parse_json_document(args.evidence.read_bytes())
    policy = load_policy(args.policy, profile=args.profile)
    result = EvidenceStore(args.database).ingest(
        envelope,
        policy=policy,
        trusted_public_keys=tuple(args.trusted_key),
    )
    print(json.dumps(result.to_payload(), indent=2))
    return 0 if result.publishable else 3


def _run_latest(args: argparse.Namespace) -> int:
    value = EvidenceStore(args.database).latest(
        args.tenant,
        args.subject,
        publishable_only=args.publishable_only,
    )
    print(json.dumps(value, indent=2))
    return 0 if value is not None else 1


def _run_plan(args: argparse.Namespace) -> int:
    command_args = tuple(item for item in args.command_args if item != "--")
    plan = build_plan(
        Path(args.target),
        image=args.image,
        command=command_args,
        runtime=args.runtime,
        limits=DetonationLimits(timeout_seconds=args.timeout),
        seccomp_profile=args.seccomp,
        use_gvisor=args.gvisor,
    )
    write_plan(args.output, plan)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "plan_digest": plan.plan_digest,
                "artifact_digest": plan.artifact_digest,
            },
            indent=2,
        )
    )
    return 0


def _run_detonate(args: argparse.Namespace) -> int:
    plan = load_plan(args.plan)
    observation = execute_plan(plan)
    _emit_json(observation.to_payload(), args.output)
    return 0 if observation.return_code == 0 and not observation.timed_out else 3


def _run_upload(args: argparse.Namespace) -> int:
    envelope = parse_json_document(args.evidence.read_bytes())
    validate_evidence_envelope(envelope)
    token = os.environ.get(args.token_env)
    response = SecureEvidenceUploader(allowed_hosts=tuple(args.allow_host)).upload(
        args.endpoint,
        envelope,
        bearer_token=token,
    )
    print(
        json.dumps(
            {
                "status": response.status,
                "body": response.body,
                "peer_ip_sha256": hashlib.sha256(response.peer_ip.encode()).hexdigest(),
            },
            indent=2,
        )
    )
    return 0


def _emit_json(payload: object, output: Path | None) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
    if output is None:
        print(rendered)
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(rendered + "\n", encoding="utf-8")
    temporary.replace(output)


if __name__ == "__main__":
    raise SystemExit(main())
