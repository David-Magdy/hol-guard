"""CLI for high-assurance extension scanning and evidence ingestion."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from .assurance.detonation import DetonationLimits, build_plan, execute_plan, write_plan
from .assurance.drift import build_baseline, validate_baseline, write_baseline
from .assurance.evidence import build_evidence_envelope, parse_json_document, validate_evidence_envelope
from .assurance.ingestion import EvidenceStore
from .assurance.models import Disposition
from .assurance.orchestrator import AssuranceOptions, scan_extension_assurance
from .assurance.policy import BUILTIN_POLICIES, load_policy
from .assurance.provenance import (
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
        description="Layered security evidence for AI plugins, MCP servers, and skills.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="Produce bounded assurance evidence")
    scan.add_argument("target", nargs="?", default=".")
    scan.add_argument("--profile", choices=sorted(BUILTIN_POLICIES), default="balanced")
    scan.add_argument("--policy", type=Path)
    scan.add_argument("--baseline", type=Path)
    scan.add_argument("--provenance", type=Path)
    scan.add_argument("--trusted-key", type=Path, action="append", default=[])
    scan.add_argument("--detonation-plan", type=Path)
    scan.add_argument("--detonation-observation", type=Path)
    scan.add_argument("--osv", action="store_true", help="Add optional bounded OSV evidence")
    scan.add_argument("--output", type=Path)

    baseline = commands.add_parser("baseline", help="Create an exact-artifact drift baseline")
    baseline.add_argument("target", nargs="?", default=".")
    baseline.add_argument("--profile", choices=sorted(BUILTIN_POLICIES), default="balanced")
    baseline.add_argument("--policy", type=Path)
    baseline.add_argument("--output", type=Path, required=True)

    keygen = commands.add_parser("keygen", help="Generate an Ed25519 provenance keypair")
    keygen.add_argument("--private-key", type=Path, required=True)
    keygen.add_argument("--public-key", type=Path, required=True)

    attest = commands.add_parser("attest", help="Sign an assurance report as DSSE provenance")
    attest.add_argument("report", type=Path)
    attest.add_argument("--private-key", type=Path, required=True)
    attest.add_argument("--output", type=Path, required=True)

    verify = commands.add_parser("verify-attestation", help="Verify a DSSE assurance attestation")
    verify.add_argument("attestation", type=Path)
    verify.add_argument("--public-key", type=Path, action="append", required=True)
    verify.add_argument("--artifact-digest")
    verify.add_argument("--evidence-digest")

    envelope = commands.add_parser("envelope", help="Wrap assurance evidence for Cloud or registry ingestion")
    envelope.add_argument("report", type=Path)
    envelope.add_argument("--tenant", required=True)
    envelope.add_argument("--subject", required=True)
    envelope.add_argument("--sequence", type=int, default=1)
    envelope.add_argument("--provenance", type=Path)
    envelope.add_argument("--output", type=Path, required=True)

    ingest = commands.add_parser("ingest-evidence", help="Verify and ingest evidence into the consuming-side store")
    ingest.add_argument("evidence", type=Path)
    ingest.add_argument("--database", type=Path, required=True)
    ingest.add_argument("--profile", choices=sorted(BUILTIN_POLICIES), default="balanced")
    ingest.add_argument("--policy", type=Path)
    ingest.add_argument("--trusted-key", type=Path, action="append", default=[])

    latest = commands.add_parser("latest-evidence", help="Read latest accepted evidence for a subject")
    latest.add_argument("--database", type=Path, required=True)
    latest.add_argument("--tenant", required=True)
    latest.add_argument("--subject", required=True)

    plan = commands.add_parser("detonation-plan", help="Build an immutable no-network container plan")
    plan.add_argument("target", nargs="?", default=".")
    plan.add_argument("--image", required=True)
    plan.add_argument("--runtime", choices=("docker", "podman"), default="docker")
    plan.add_argument("--timeout", type=int, default=30)
    plan.add_argument("--seccomp", type=Path)
    plan.add_argument("--gvisor", action="store_true")
    plan.add_argument("--output", type=Path, required=True)
    plan.add_argument("command_args", nargs=argparse.REMAINDER)

    detonate = commands.add_parser("detonate", help="Execute a reviewed detonation plan")
    detonate.add_argument("plan", type=Path)
    detonate.add_argument("--output", type=Path, required=True)

    upload = commands.add_parser("upload-evidence", help="Upload evidence to an allowlisted HTTPS endpoint")
    upload.add_argument("evidence", type=Path)
    upload.add_argument("--endpoint", required=True)
    upload.add_argument("--allow-host", action="append", required=True)
    upload.add_argument("--token-env", default="HOL_GUARD_EVIDENCE_TOKEN")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _run_scan(args)
        if args.command == "baseline":
            return _run_baseline(args)
        if args.command == "keygen":
            key_id = generate_keypair(args.private_key, args.public_key)
            print(json.dumps({"key_id": key_id}, indent=2))
            return 0
        if args.command == "attest":
            return _run_attest(args)
        if args.command == "verify-attestation":
            return _run_verify(args)
        if args.command == "envelope":
            return _run_envelope(args)
        if args.command == "ingest-evidence":
            return _run_ingest(args)
        if args.command == "latest-evidence":
            return _run_latest(args)
        if args.command == "detonation-plan":
            return _run_plan(args)
        if args.command == "detonate":
            return _run_detonate(args)
        if args.command == "upload-evidence":
            return _run_upload(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4
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
    payload = report.to_payload()
    _emit_json(payload, args.output)
    return EXIT_BY_DISPOSITION[report.decision.disposition.value]


def _run_baseline(args: argparse.Namespace) -> int:
    report = scan_extension_assurance(
        args.target,
        AssuranceOptions(profile=args.profile, policy_path=args.policy),
    )
    payload = report.to_payload()
    files = []
    root = Path(report.artifact_root)
    for path in sorted(item for item in root.rglob("*") if item.is_file() and not item.is_symlink()):
        relative = path.relative_to(root).as_posix()
        files.append(
            {
                "path": relative,
                "sha256": _sha256_file(path),
                "size": path.stat().st_size,
                "mode": path.stat().st_mode & 0o7777,
                "kind": "regular",
            }
        )
    baseline = build_baseline(
        artifact_digest=report.artifact_digest,
        files=tuple(files),
        dependencies=tuple(payload["dependencies"]),
        native_artifacts=tuple(payload["native_artifacts"]),
        capabilities=tuple(payload["capabilities"]),
    )
    write_baseline(args.output, baseline)
    print(json.dumps({"output": str(args.output), "baseline_digest": baseline["baseline_digest"]}, indent=2))
    return EXIT_BY_DISPOSITION[report.decision.disposition.value]


def _run_attest(args: argparse.Namespace) -> int:
    report = parse_json_document(args.report.read_bytes())
    if not isinstance(report, dict):
        raise ValueError("assurance report must be an object")
    statement = build_statement(
        artifact_digest=str(report["artifact_digest"]),
        evidence_digest=str(report["evidence_digest"]),
        scanner_version=str(report["scanner_version"]),
        decision=str(report["decision"]["disposition"]),
        coverage_state=str(report["coverage"]["state"]),
        assurance_level=str(report["assurance_level"]),
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
    report = parse_json_document(args.report.read_bytes())
    if not isinstance(report, dict):
        raise ValueError("assurance report must be an object")
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
    return 0


def _run_latest(args: argparse.Namespace) -> int:
    value = EvidenceStore(args.database).latest(args.tenant, args.subject)
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
    print(json.dumps({"output": str(args.output), "plan_digest": plan.plan_digest}, indent=2))
    return 0


def _run_detonate(args: argparse.Namespace) -> int:
    raw = parse_json_document(args.plan.read_bytes())
    if not isinstance(raw, dict):
        raise ValueError("detonation plan must be an object")
    limits = DetonationLimits(**raw["limits"])
    from .assurance.detonation import DetonationPlan

    plan = DetonationPlan(
        schema_version=raw["schema_version"],
        runtime=raw["runtime"],
        image=raw["image"],
        artifact_root=raw["artifact_root"],
        command=tuple(raw["command"]),
        container_arguments=tuple(raw["container_arguments"]),
        limits=limits,
        network=raw["network"],
        root_filesystem=raw["root_filesystem"],
        user=raw["user"],
        security_options=tuple(raw["security_options"]),
        plan_digest=raw["plan_digest"],
    )
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
    print(json.dumps({"status": response.status, "body": response.body, "peer_ip": response.peer_ip}, indent=2))
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


def _sha256_file(path: Path) -> str:
    import hashlib

    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
