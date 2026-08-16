# pyright: basic
"""Multi-layer extension assurance orchestration."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from codex_plugin_scanner.version import __version__

from .archive_scan import ArchiveMember, looks_like_archive, scan_archive_file
from .content_scan import RULES, SECRET_PATTERNS, TEXT_SUFFIXES, scan_text_entry
from .dependency_scan import DependencyResult, scan_dependencies
from .detonation import load_plan, validate_observation
from .drift import build_baseline, compare_baseline, load_baseline
from .inventory import InventoryResult, build_inventory
from .limits import ScanLimits
from .models import (
    AssuranceLevel,
    AssuranceReport,
    Confidence,
    CoverageGap,
    CoverageState,
    CoverageSummary,
    EvidenceLayer,
    EvidenceLocation,
    SecurityFinding,
    Severity,
)
from .native_scan import NativeResult, detect_native_format, scan_native_bytes, scan_native_file
from .policy import evaluate_decision, load_policy
from .provenance import verify_envelope
from .surface_scan import SurfaceResult, scan_surfaces


@dataclass(frozen=True, slots=True)
class AssuranceOptions:
    profile: str = "balanced"
    policy_path: Path | None = None
    limits: ScanLimits = ScanLimits()
    osv: bool = False
    baseline_path: Path | None = None
    provenance_envelope_path: Path | None = None
    trusted_public_keys: tuple[Path, ...] = ()
    detonation_plan_path: Path | None = None
    detonation_observation_path: Path | None = None


def scan_extension_assurance(
    root: str | Path,
    options: AssuranceOptions | None = None,
) -> AssuranceReport:
    options = options or AssuranceOptions()
    options.limits.validate()
    resolved = Path(root).resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"extension target is not a directory: {resolved}")
    policy = load_policy(options.policy_path, profile=options.profile)
    inventory = build_inventory(resolved, options.limits)

    findings: list[SecurityFinding] = _coverage_gap_findings(inventory.gaps)
    capabilities: set[str] = set()
    analyzed_files = 0
    analyzed_bytes = 0
    opaque_files = 0
    unreadable_files = 0
    oversized_files = 0
    archive_members: list[ArchiveMember] = []
    archive_summaries: list[dict[str, Any]] = []
    native_summaries: list[dict[str, Any]] = []
    native_count = 0
    rust_accelerated = 0
    component_complete = not inventory.limit_reached

    for entry in inventory.entries:
        if entry.kind != "regular" or not entry.readable:
            if entry.kind == "regular":
                unreadable_files += 1
            elif entry.kind in {"symlink", "special", "unreadable"}:
                opaque_files += 1
            component_complete = False
            continue
        if entry.size > options.limits.max_file_bytes:
            oversized_files += 1
        try:
            prefix = _read_prefix(entry.path, 64)
        except OSError:
            unreadable_files += 1
            component_complete = False
            findings.append(
                SecurityFinding(
                    rule_id="ASSURANCE_FILE_READ_FAILED",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="coverage",
                    title="File became unreadable during semantic analysis",
                    description="The inventory digest was produced, but semantic analysis could not reopen the file.",
                    remediation="Rerun from an immutable snapshot and investigate filesystem races.",
                    locations=(EvidenceLocation(path=entry.relative_path),),
                ).with_fingerprint()
            )
            continue

        format_name = detect_native_format(prefix)
        if format_name is not None:
            native_count += 1
            result = scan_native_file(entry.path, entry.relative_path, options.limits)
            _collect_native(result, entry.relative_path, native_summaries, findings, capabilities)
            rust_accelerated += int(result.rust_used)
            component_complete = component_complete and result.complete
            analyzed_files += 1
            analyzed_bytes += min(entry.size, options.limits.max_file_bytes)
            continue

        if looks_like_archive(entry.path, prefix):
            result = scan_archive_file(entry.path, entry.relative_path, options.limits)
            findings.extend(result.findings)
            archive_members.extend(result.members)
            component_complete = component_complete and result.complete
            analyzed_files += 1
            analyzed_bytes += min(entry.size, options.limits.max_archive_bytes)
            archive_summaries.append(
                {
                    "path": entry.relative_path,
                    "sha256": entry.sha256,
                    "members": len(result.members),
                    "expanded_bytes": result.expanded_bytes,
                    "complete": result.complete,
                }
            )
            for display_path, payload in result.native_payloads:
                native_count += 1
                native_result = scan_native_bytes(payload, display_path, options.limits)
                _collect_native(
                    native_result,
                    display_path,
                    native_summaries,
                    findings,
                    capabilities,
                )
                rust_accelerated += int(native_result.rust_used)
                component_complete = component_complete and native_result.complete
            for display_path, payload in result.text_payloads:
                nested_findings, nested_capabilities, nested_complete = _scan_text_payload(
                    payload, display_path, options.limits
                )
                findings.extend(nested_findings)
                capabilities.update(nested_capabilities)
                component_complete = component_complete and nested_complete
            continue

        text_findings, text_capabilities, read_bytes = scan_text_entry(
            entry,
            resolved,
            options.limits,
        )
        if text_findings or entry.path.suffix.lower() in TEXT_SUFFIXES:
            findings.extend(text_findings)
            capabilities.update(text_capabilities)
            analyzed_files += 1
            analyzed_bytes += read_bytes
            if entry.size > read_bytes:
                component_complete = False
                findings.append(
                    SecurityFinding(
                        rule_id="ASSURANCE_TEXT_ANALYSIS_TRUNCATED",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        category="coverage",
                        title="Text analysis was truncated",
                        description="The complete file is digest-bound, but semantic analysis reached the managed text-byte limit.",
                        remediation="Review the file independently or split generated content into auditable components.",
                        locations=(EvidenceLocation(path=entry.relative_path),),
                        metadata={"size": entry.size, "analyzed_bytes": read_bytes},
                    ).with_fingerprint()
                )
        else:
            opaque_files += 1

    dependency_result = scan_dependencies(resolved, options.limits, osv=options.osv)
    findings.extend(dependency_result.findings)
    capabilities.update(dependency_result.capabilities)
    component_complete = component_complete and dependency_result.complete

    surface_result = scan_surfaces(resolved)
    findings.extend(surface_result.findings)
    capabilities.update(surface_result.capabilities)
    component_complete = component_complete and surface_result.complete

    findings.extend(_correlate(findings, capabilities, dependency_result, surface_result))
    findings = _dedupe_sort(findings)
    if len(findings) > options.limits.max_findings:
        omitted = len(findings) - options.limits.max_findings + 1
        component_complete = False
        findings = findings[: options.limits.max_findings - 1]
        findings.append(
            SecurityFinding(
                rule_id="ASSURANCE_FINDING_LIMIT_REACHED",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="coverage",
                title="Finding limit reached",
                description="Additional findings were omitted after the managed result bound was reached.",
                remediation="Review the highest-severity findings, split the artifact, and rerun without weakening managed limits.",
                metadata={"omitted": omitted},
            ).with_fingerprint()
        )

    provenance_payload, provenance_verified = _load_and_verify_provenance(
        options,
        artifact_digest=inventory.artifact_digest,
    )
    detonation_payload, detonation_observed, plan_present = _load_detonation(
        options,
        artifact_digest=inventory.artifact_digest,
    )
    assurance_level = _assurance_level(
        provenance_verified=provenance_verified,
        plan_present=plan_present,
        detonation_observed=detonation_observed,
    )

    coverage_state = _coverage_state(
        inventory,
        component_complete=component_complete,
        opaque_files=opaque_files,
        unreadable_files=unreadable_files,
        oversized_files=oversized_files,
    )
    limitations = [
        "A clean static result is not proof that an extension is safe.",
        "Native structural parsing identifies imports, exports, sections, mitigations, and indicators; it is not complete control-flow disassembly or reachability proof.",
        "Sandbox evidence describes only the exercised command and environment, not every reachable behavior or trigger.",
        "Reputation and vulnerability feeds can be stale or incomplete and never override direct evidence.",
        "Opaque media and unsupported formats remain coverage gaps even when their exact bytes are artifact-digest-bound.",
    ]
    if native_count and rust_accelerated < native_count:
        limitations.append(
            "One or more native artifacts used the bounded Python fallback instead of the Rust structural parser."
        )
    if not provenance_verified:
        limitations.append("No trusted provenance signature was verified for this exact artifact digest.")
    if not detonation_observed:
        limitations.append("No exact-artifact-bound sandbox observation was verified for this scan.")

    gaps = list(inventory.gaps)
    if opaque_files:
        gaps.append(
            CoverageGap(
                code="OPAQUE_CONTENT",
                severity=Severity.MEDIUM,
                description="Files with unsupported or opaque content were inventoried and digest-bound but not semantically analyzed.",
                count=opaque_files,
            )
        )
    coverage = CoverageSummary(
        state=coverage_state,
        inventory_files=len(inventory.entries),
        analyzed_files=analyzed_files,
        analyzed_bytes=analyzed_bytes,
        opaque_files=opaque_files,
        unreadable_files=unreadable_files,
        oversized_files=oversized_files,
        archive_members=len(archive_members),
        native_artifacts=native_count,
        rust_accelerated_files=rust_accelerated,
        gaps=tuple(gaps),
        limitations=tuple(limitations),
    )

    decision = evaluate_decision(
        tuple(findings),
        coverage=coverage.state,
        assurance_level=assurance_level,
        capabilities=tuple(sorted(capabilities)),
        policy=policy,
        provenance_verified=provenance_verified,
        detonation_observed=detonation_observed,
        native_count=native_count,
        rust_accelerated_files=rust_accelerated,
    )

    files_payload = tuple(
        {
            "path": entry.relative_path,
            "sha256": entry.sha256,
            "size": entry.size,
            "mode": entry.mode & 0o7777,
            "kind": entry.kind,
        }
        for entry in inventory.entries
    )
    current_baseline = build_baseline(
        artifact_digest=inventory.artifact_digest,
        files=files_payload,
        dependencies=tuple(record.to_payload() for record in dependency_result.records),
        native_artifacts=tuple(native_summaries),
        capabilities=tuple(sorted(capabilities)),
        endpoints=surface_result.endpoints,
        commands=surface_result.commands,
        lifecycle_scripts=tuple(
            finding.fingerprint
            for finding in findings
            if finding.rule_id == "ASSURANCE_PACKAGE_LIFECYCLE_SCRIPT"
        ),
        security_controls=surface_result.security_controls,
    )
    drift_payload: dict[str, Any] | None = None
    if options.baseline_path is not None:
        baseline = load_baseline(options.baseline_path)
        drift_payload = compare_baseline(baseline, current_baseline)
        if drift_payload.get("requires_reapproval"):
            findings.append(
                SecurityFinding(
                    rule_id="ASSURANCE_SECURITY_RELEVANT_DRIFT",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    category="drift",
                    title="Security-relevant extension drift requires reapproval",
                    description="Capabilities, commands, dependencies, native artifacts, endpoints, executable bits, or security controls changed from the approved baseline.",
                    remediation="Review the structured drift and approve the new exact artifact digest before installation.",
                    metadata={"drift_digest": drift_payload["drift_digest"]},
                ).with_fingerprint()
            )
            findings = _dedupe_sort(findings)
            decision = evaluate_decision(
                tuple(findings),
                coverage=coverage.state,
                assurance_level=assurance_level,
                capabilities=tuple(sorted(capabilities)),
                policy=policy,
                provenance_verified=provenance_verified,
                detonation_observed=detonation_observed,
                native_count=native_count,
                rust_accelerated_files=rust_accelerated,
            )

    layers = (
        EvidenceLayer(
            name="inventory",
            status=coverage.state.value,
            summary=f"Inventoried {len(inventory.entries)} entries and digest-bound {inventory.total_bytes} regular-file bytes.",
            digest=inventory.artifact_digest,
            metadata={"complete": not inventory.limit_reached},
        ),
        EvidenceLayer(
            name="static-analysis",
            status="complete" if component_complete else "partial",
            summary=f"Produced {len(findings)} deduplicated findings across source, manifests, archives, native artifacts, and dependencies.",
            digest=_finding_set_digest(findings),
        ),
        EvidenceLayer(
            name="native-rust",
            status=(
                "complete"
                if native_count == rust_accelerated
                else "partial"
                if native_count
                else "not-applicable"
            ),
            summary=f"Rust structurally parsed {rust_accelerated} of {native_count} native or WebAssembly artifacts.",
        ),
        EvidenceLayer(
            name="dependency-intelligence",
            status="complete" if dependency_result.complete else "partial",
            summary=f"Normalized {len(dependency_result.records)} dependency records.",
            metadata=dependency_result.osv or {},
        ),
        EvidenceLayer(
            name="provenance",
            status="verified" if provenance_verified else "unverified",
            summary=(
                "Trusted exact-artifact DSSE signature verified."
                if provenance_verified
                else "No trusted exact-artifact provenance verified."
            ),
            metadata=provenance_payload or {},
        ),
        EvidenceLayer(
            name="sandbox",
            status=(
                "observed"
                if detonation_observed
                else "planned"
                if plan_present
                else "not-run"
            ),
            summary=(
                "An exact-artifact-bound sandbox observation was verified."
                if detonation_observed
                else "Sandbox behavior is not established."
            ),
            metadata=detonation_payload or {},
        ),
        EvidenceLayer(
            name="drift",
            status=(
                "changed"
                if drift_payload and drift_payload.get("changed")
                else "unchanged"
                if drift_payload
                else "no-baseline"
            ),
            summary=(
                "Compared against an approved exact-artifact baseline."
                if drift_payload
                else "No approved baseline was supplied."
            ),
            digest=drift_payload.get("drift_digest") if drift_payload else None,
        ),
    )

    return AssuranceReport(
        schema_version="hol-guard.assurance-report.v1",
        scanner_version=__version__,
        artifact_root=str(resolved),
        artifact_digest=inventory.artifact_digest,
        generated_at=datetime.now(timezone.utc).isoformat(),
        assurance_level=assurance_level,
        coverage=coverage,
        findings=tuple(findings),
        decision=decision,
        layers=layers,
        capabilities=tuple(sorted(capabilities)),
        dependencies=tuple(record.to_payload() for record in dependency_result.records),
        native_artifacts=tuple(native_summaries),
        archive_artifacts=tuple(archive_summaries),
        policy=policy.to_payload(),
        drift=drift_payload,
        provenance=provenance_payload,
        detonation=detonation_payload,
    )


def _collect_native(
    result: NativeResult,
    display_path: str,
    summaries: list[dict[str, Any]],
    findings: list[SecurityFinding],
    capabilities: set[str],
) -> None:
    summary = dict(result.summary)
    summary["path"] = display_path
    summary["rust_used"] = result.rust_used
    summary["complete"] = result.complete
    summaries.append(summary)
    findings.extend(result.findings)
    capabilities.update(result.capabilities)


def _coverage_gap_findings(gaps: tuple[CoverageGap, ...]) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    for gap in gaps:
        findings.append(
            SecurityFinding(
                rule_id=gap.code,
                severity=gap.severity,
                confidence=Confidence.HIGH,
                category="coverage",
                title="Scanner coverage gap",
                description=gap.description,
                remediation="Resolve the coverage gap or require independent review before installation.",
                locations=(EvidenceLocation(path=gap.path),) if gap.path else (),
                metadata={"count": gap.count},
            ).with_fingerprint()
        )
    return findings


def _scan_text_payload(
    payload: bytes,
    display_path: str,
    limits: ScanLimits,
) -> tuple[list[SecurityFinding], set[str], bool]:
    text = payload.decode("utf-8", errors="replace")
    findings: list[SecurityFinding] = []
    capabilities: set[str] = set()
    suffix = Path(display_path).suffix.lower()
    for rule in RULES:
        if rule.file_suffixes and suffix not in rule.file_suffixes:
            continue
        for pattern in rule.patterns:
            match = pattern.search(text)
            if match is None:
                continue
            line = text.count("\n", 0, match.start()) + 1
            findings.append(
                SecurityFinding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    category=rule.category,
                    title=rule.title,
                    description=rule.description,
                    remediation=rule.remediation,
                    locations=(
                        EvidenceLocation(
                            path=display_path,
                            start_line=line,
                            end_line=line + match.group(0).count("\n"),
                            excerpt_sha256=hashlib.sha256(match.group(0).encode()).hexdigest(),
                        ),
                    ),
                    metadata={"context": "archive-member"},
                ).with_fingerprint()
            )
            if rule.capability:
                capabilities.add(rule.capability)
            break
    for secret_kind, pattern in SECRET_PATTERNS:
        match = pattern.search(text)
        if match:
            line = text.count("\n", 0, match.start()) + 1
            findings.append(
                SecurityFinding(
                    rule_id="ASSURANCE_HARDCODED_SECRET",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    category="credential-exposure",
                    title=f"Potential {secret_kind} inside archive",
                    description="A credential-shaped value is present in an archive member. The value is omitted.",
                    remediation="Revoke and remove the credential from the distributed artifact.",
                    locations=(
                        EvidenceLocation(
                            path=display_path,
                            start_line=line,
                            end_line=line,
                            excerpt_sha256=hashlib.sha256(match.group(0).encode()).hexdigest(),
                        ),
                    ),
                ).with_fingerprint()
            )
            capabilities.add("credential-store")
    return findings, capabilities, len(payload) <= limits.max_text_bytes


def _correlate(
    findings: list[SecurityFinding],
    capabilities: set[str],
    dependencies: DependencyResult,
    surfaces: SurfaceResult,
) -> list[SecurityFinding]:
    del dependencies
    correlated: list[SecurityFinding] = []
    rule_ids = {finding.rule_id for finding in findings}
    categories = {finding.category for finding in findings}
    if "credential-store" in capabilities and "outbound-network" in capabilities:
        correlated.append(
            _correlation(
                "ASSURANCE_CORRELATION_CREDENTIAL_EGRESS",
                Severity.CRITICAL,
                "Credential access combined with outbound networking",
                "The extension can access credential material and communicate externally, creating an exfiltration path.",
                ("credential-store", "outbound-network"),
            )
        )
    if "obfuscation" in capabilities and "process-execution" in capabilities:
        correlated.append(
            _correlation(
                "ASSURANCE_CORRELATION_OBFUSCATED_EXECUTION",
                Severity.CRITICAL,
                "Obfuscation combined with process execution",
                "Packed or obfuscated content is combined with an execution surface.",
                ("obfuscation", "process-execution"),
            )
        )
    if "prompt-override" in capabilities and "credential-store" in capabilities:
        correlated.append(
            _correlation(
                "ASSURANCE_CORRELATION_PROMPT_CREDENTIAL_ACCESS",
                Severity.CRITICAL,
                "Prompt override combined with credential access",
                "Instructions that bypass controls are paired with credential-access capability.",
                ("prompt-override", "credential-store"),
            )
        )
    if "ASSURANCE_PACKAGE_LIFECYCLE_SCRIPT" in rule_ids and (
        "ASSURANCE_DOWNLOAD_EXECUTE" in rule_ids or "network" in categories
    ):
        correlated.append(
            _correlation(
                "ASSURANCE_CORRELATION_INSTALL_NETWORK_EXECUTION",
                Severity.CRITICAL,
                "Install-time execution combined with network activity",
                "An automatic lifecycle hook can retrieve or execute remote content during installation.",
                ("install-execution", "outbound-network"),
            )
        )
    if surfaces.commands and any(
        finding.rule_id
        in {"ASSURANCE_MCP_SHELL_LAUNCHER", "ASSURANCE_MCP_MUTABLE_PACKAGE_RUNNER"}
        for finding in findings
    ):
        correlated.append(
            _correlation(
                "ASSURANCE_CORRELATION_MUTABLE_MCP_EXECUTION",
                Severity.HIGH,
                "Mutable MCP execution surface",
                "An MCP command can resolve or interpret mutable content before execution.",
                ("process-execution",),
            )
        )
    return correlated


def _correlation(
    rule_id: str,
    severity: Severity,
    title: str,
    description: str,
    capabilities: tuple[str, ...],
) -> SecurityFinding:
    return SecurityFinding(
        rule_id=rule_id,
        severity=severity,
        confidence=Confidence.HIGH,
        category="correlation",
        title=title,
        description=description,
        remediation="Remove one or more contributing capabilities and require sandbox plus provenance evidence.",
        metadata={"capabilities": list(capabilities)},
    ).with_fingerprint()


def _load_and_verify_provenance(
    options: AssuranceOptions,
    *,
    artifact_digest: str,
) -> tuple[dict[str, Any] | None, bool]:
    if options.provenance_envelope_path is None:
        return None, False
    try:
        envelope = json.loads(
            options.provenance_envelope_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError):
        return {"verified": False, "reason": "provenance envelope could not be loaded"}, False
    result = verify_envelope(
        envelope,
        options.trusted_public_keys,
        expected_artifact_digest=artifact_digest,
    )
    return {
        "verified": result.verified,
        "key_id": result.key_id,
        "reason": result.reason,
    }, result.verified


def _load_detonation(
    options: AssuranceOptions,
    *,
    artifact_digest: str,
) -> tuple[dict[str, Any] | None, bool, bool]:
    if options.detonation_plan_path is None:
        return None, False, False
    try:
        plan = load_plan(options.detonation_plan_path)
    except (OSError, ValueError) as exc:
        return {
            "planned": False,
            "observed": False,
            "reason": f"detonation plan validation failed: {type(exc).__name__}",
        }, False, False
    if plan.artifact_digest != artifact_digest:
        return {
            "planned": False,
            "observed": False,
            "reason": "detonation plan is bound to a different artifact digest",
        }, False, False
    if options.detonation_observation_path is None:
        return {
            "planned": True,
            "observed": False,
            "plan_digest": plan.plan_digest,
            "artifact_digest": plan.artifact_digest,
        }, False, True
    try:
        observation = json.loads(
            options.detonation_observation_path.read_text(encoding="utf-8")
        )
        validate_observation(
            observation,
            expected_plan_digest=plan.plan_digest,
            expected_artifact_digest=artifact_digest,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return {
            "planned": True,
            "observed": False,
            "plan_digest": plan.plan_digest,
            "artifact_digest": plan.artifact_digest,
            "reason": f"observation validation failed: {type(exc).__name__}",
        }, False, True
    return {
        "planned": True,
        "observed": True,
        "plan_digest": plan.plan_digest,
        "artifact_digest": plan.artifact_digest,
        "observation_digest": observation.get("observation_digest"),
        "timed_out": observation.get("timed_out"),
        "return_code": observation.get("return_code"),
    }, True, True


def _assurance_level(
    *,
    provenance_verified: bool,
    plan_present: bool,
    detonation_observed: bool,
) -> AssuranceLevel:
    if detonation_observed:
        return AssuranceLevel.SANDBOX_OBSERVED
    if plan_present:
        return AssuranceLevel.SANDBOX_PLANNED
    if provenance_verified:
        return AssuranceLevel.PROVENANCE_VERIFIED
    return AssuranceLevel.STATIC


def _coverage_state(
    inventory: InventoryResult,
    *,
    component_complete: bool,
    opaque_files: int,
    unreadable_files: int,
    oversized_files: int,
) -> CoverageState:
    if inventory.limit_reached or unreadable_files or oversized_files:
        return CoverageState.INCOMPLETE
    if inventory.gaps or opaque_files or not component_complete:
        return CoverageState.PARTIAL
    return CoverageState.COMPLETE


def _dedupe_sort(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    severity = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.INFO: 1,
    }
    unique = {finding.fingerprint: finding for finding in findings}
    return sorted(
        unique.values(),
        key=lambda finding: (
            -severity[finding.severity],
            finding.rule_id,
            finding.locations[0].path if finding.locations and finding.locations[0].path else "",
            finding.fingerprint,
        ),
    )


def _finding_set_digest(findings: list[SecurityFinding]) -> str:
    hasher = hashlib.sha256()
    hasher.update(b"hol-guard-assurance-findings-v1\0")
    for finding in _dedupe_sort(findings):
        hasher.update(finding.fingerprint.encode("ascii"))
        hasher.update(b"\0")
    return hasher.hexdigest()


def _read_prefix(path: Path, size: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(size)
