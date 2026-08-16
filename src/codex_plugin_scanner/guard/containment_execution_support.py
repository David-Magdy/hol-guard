"""Shared proof and health helpers for execution-owned containment paths."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from .runtime.containment_contract import ContainmentRequest
from .runtime.containment_executor import ContainmentExecutionResult
from .runtime.containment_health import ContainmentHealthEvidence, contained_positive_proof
from .runtime.effect_contract import ProofRequirement
from .runtime.effect_decision import PositiveProof

_EXECUTION_PROOF_REQUIREMENTS = (
    ProofRequirement.OPERATION_AND_TARGETS,
    ProofRequirement.WORKSPACE_IDENTITY,
    ProofRequirement.WORKING_DIRECTORY_IDENTITY,
    ProofRequirement.EXECUTABLE_IDENTITY,
    ProofRequirement.LAUNCH_CHAIN,
    ProofRequirement.PARSER_CONFIDENCE,
    ProofRequirement.EXPECTED_EFFECTS,
)


def containment_positive_proof(
    result: ContainmentExecutionResult,
    request: ContainmentRequest,
    health: ContainmentHealthEvidence,
    runtime_fingerprint: str,
) -> PositiveProof:
    """Bind one successful contained execution to current daemon health."""

    return contained_positive_proof(
        result.attestation,
        request,
        health,
        requirements=_EXECUTION_PROOF_REQUIREMENTS,
        now=datetime.now(timezone.utc),
        runtime_fingerprint=runtime_fingerprint,
    )


def load_current_containment_health(guard_home: Path) -> tuple[ContainmentHealthEvidence, str]:
    """Load current daemon containment health and reject incompatible evidence."""

    from .daemon.client import load_guard_surface_daemon_client
    from .daemon.manager import current_guard_daemon_runtime_fingerprint

    client = load_guard_surface_daemon_client(guard_home.resolve(strict=True))
    evidence = ContainmentHealthEvidence.from_mapping(client.containment_health())
    runtime_fingerprint = current_guard_daemon_runtime_fingerprint()
    errors = evidence.compatibility_errors(
        now=datetime.now(timezone.utc),
        runtime_fingerprint=runtime_fingerprint,
    )
    if errors:
        raise RuntimeError(f"containment health incompatible: {errors[0]}")
    return evidence, runtime_fingerprint


__all__ = ["containment_positive_proof", "load_current_containment_health"]
