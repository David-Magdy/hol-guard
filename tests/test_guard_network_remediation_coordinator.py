from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.network_authority import (
    Ed25519NetworkSigner,
    GrantReplayLedger,
    NetworkAuthorityError,
    NetworkRuleAction,
    ProcessIdentity,
    VerifiedNetworkGrant,
    compile_network_policy,
)
from codex_plugin_scanner.guard.runtime.network_enforcement_receipts import (
    Ed25519EvidenceSigner,
    SignedEvidence,
    issue_enforcement_evidence,
    issue_observation_evidence,
)
from codex_plugin_scanner.guard.runtime.network_generation_store import NetworkGenerationStore
from codex_plugin_scanner.guard.runtime.network_remediation_coordinator import (
    NetworkLeaseLedger,
    NetworkLeasePhase,
    NetworkLeaseRequest,
    NetworkObserverProbe,
    NetworkProviderProbe,
    NetworkProviderRegistration,
    NetworkRemediationCoordinator,
)

_PROVIDER_DIGEST = "1" * 64
_OBSERVER_DIGEST = "2" * 64
_PROBE_DIGEST = "3" * 64
_BEHAVIOR_DIGEST = "4" * 64
_BOUNDARY_DIGEST = "5" * 64
_PROCESS_START = "6" * 64
_EXECUTABLE_DIGEST = "7" * 64
_APPROVAL_DIGEST = "8" * 64


def _policy() -> dict[str, object]:
    return {
        "schema": "guard.network-policy.v1",
        "emergency_deny": False,
        "layers": [
            {
                "layer": "built-in",
                "rules": [
                    {
                        "id": "allow-example",
                        "action": NetworkRuleAction.ALLOW.value,
                        "protocols": ["tcp"],
                        "domains": ["api.example.invalid"],
                        "cidrs": [],
                        "ports": [443],
                        "reason_code": "approved-example",
                    }
                ],
            }
        ],
    }


class _Provider:
    provider_id = "linux-namespace-provider"

    def __init__(self, signer: Ed25519EvidenceSigner) -> None:
        self.signer = signer
        self.policy = None
        self.process = None
        self.expires_at = 0
        self.closed: list[str] = []
        self.behavioral_test_digest: str | None = _BEHAVIOR_DIGEST

    def probe(self, *, now_epoch_s: int) -> NetworkProviderProbe:
        return NetworkProviderProbe(
            provider_id=self.provider_id,
            provider_artifact_digest=_PROVIDER_DIGEST,
            installed=True,
            verified=True,
            effective_grade="selective-egress",
            capabilities=("dns-control", "process-tree-lease", "selective-egress"),
            probe_digest=_PROBE_DIGEST,
            behavioral_test_digest=self.behavioral_test_digest,
            observed_at_epoch_s=now_epoch_s,
            valid_until_epoch_s=now_epoch_s + 60,
            reason_code="provider-ready",
        )

    def apply_generation(self, policy):  # noqa: ANN001, ANN201
        self.policy = policy
        return policy.policy_digest

    def open_lease(
        self,
        *,
        policy,
        grant: VerifiedNetworkGrant,
        required_capabilities: tuple[str, ...],
        expires_at_epoch_s: int,
    ) -> SignedEvidence:
        self.policy = policy
        self.process = grant.process
        self.expires_at = expires_at_epoch_s
        return issue_enforcement_evidence(
            self.signer,
            lease_id=grant.lease_id,
            provider_id=self.provider_id,
            provider_artifact_digest=_PROVIDER_DIGEST,
            generation=policy.generation,
            policy_digest=policy.policy_digest,
            process=grant.process,
            boundary_digest=_BOUNDARY_DIGEST,
            applied_at_epoch_s=1_900_000_000,
            expires_at_epoch_s=expires_at_epoch_s,
            capabilities=required_capabilities,
            probe_digest=_PROBE_DIGEST,
        )

    def inspect_lease(
        self,
        *,
        lease_id: str,
        policy,
        process: ProcessIdentity,
        now_epoch_s: int,
    ) -> SignedEvidence:
        return issue_enforcement_evidence(
            self.signer,
            lease_id=lease_id,
            provider_id=self.provider_id,
            provider_artifact_digest=_PROVIDER_DIGEST,
            generation=policy.generation,
            policy_digest=policy.policy_digest,
            process=process,
            boundary_digest=_BOUNDARY_DIGEST,
            applied_at_epoch_s=1_900_000_000,
            expires_at_epoch_s=self.expires_at,
            capabilities=("dns-control", "process-tree-lease", "selective-egress"),
            probe_digest=_PROBE_DIGEST,
        )

    def close_lease(self, *, lease_id: str, reason_code: str) -> None:
        self.closed.append(f"{lease_id}:{reason_code}")


class _Observer:
    observer_id = "procfs-nft-observer"

    def __init__(self, signer: Ed25519EvidenceSigner) -> None:
        self.signer = signer
        self.available = True

    def probe(self, *, now_epoch_s: int) -> NetworkObserverProbe:
        return NetworkObserverProbe(
            observer_id=self.observer_id,
            observer_artifact_digest=_OBSERVER_DIGEST,
            installed=self.available,
            verified=self.available,
            probe_digest=_PROBE_DIGEST,
            observed_at_epoch_s=now_epoch_s,
            valid_until_epoch_s=now_epoch_s + 60,
            reason_code="observer-ready" if self.available else "observer-unavailable",
        )

    def observe_lease(
        self,
        *,
        lease_id: str,
        policy,
        process: ProcessIdentity,
        provider_artifact_digest: str,
        now_epoch_s: int,
    ) -> SignedEvidence:
        return issue_observation_evidence(
            self.signer,
            lease_id=lease_id,
            observer_id=self.observer_id,
            observer_artifact_digest=_OBSERVER_DIGEST,
            observed_provider_artifact_digest=provider_artifact_digest,
            generation=policy.generation,
            policy_digest=policy.policy_digest,
            process=process,
            first_observed_at_epoch_s=now_epoch_s,
            last_observed_at_epoch_s=now_epoch_s + 5,
            sample_count=2,
            allowed_flow_count=1,
            dropped_flow_count=1,
            violation_count=0,
            probe_digest=_PROBE_DIGEST,
        )


def test_network_coordinator_requires_live_provider_and_independent_observer(tmp_path: Path) -> None:
    authority_signer = Ed25519NetworkSigner.generate(key_id="network-authority")
    provider_signer = Ed25519EvidenceSigner.generate(
        key_id="provider-receipts",
        purpose="enforcement-provider",
    )
    observer_signer = Ed25519EvidenceSigner.generate(
        key_id="observer-receipts",
        purpose="independent-observer",
    )
    provider = _Provider(provider_signer)
    observer = _Observer(observer_signer)
    generation_store = NetworkGenerationStore(
        tmp_path / "generations",
        trusted_keys={authority_signer.key_id: authority_signer.public_key_bytes()},
    )
    coordinator = NetworkRemediationCoordinator(
        generation_store=generation_store,
        grant_replay_ledger=GrantReplayLedger(tmp_path / "grants" / "replay.json"),
        grant_trusted_keys={authority_signer.key_id: authority_signer.public_key_bytes()},
        lease_ledger=NetworkLeaseLedger(
            tmp_path / "leases",
            state_hmac_key=b"l" * 32,
        ),
        registrations=(
            NetworkProviderRegistration(
                provider=provider,
                observer=observer,
                provider_keys={provider_signer.key_id: provider_signer.public_key_bytes()},
                observer_keys={observer_signer.key_id: observer_signer.public_key_bytes()},
            ),
        ),
    )

    policy = compile_network_policy(_policy(), generation=1)
    coordinator.activate_generation(
        authority_signer.sign_generation(policy),
        installed_at_epoch_s=1_900_000_000,
        now_epoch_s=1_900_000_000,
    )
    assert provider.policy is not None
    assert provider.policy.policy_digest == policy.policy_digest

    process = ProcessIdentity(
        pid=9876,
        start_token=_PROCESS_START,
        executable_digest=_EXECUTABLE_DIGEST,
    )
    grant = authority_signer.issue_grant(
        lease_id="lease-9876",
        policy_digest=policy.policy_digest,
        approval_digest=_APPROVAL_DIGEST,
        process=process,
        rule_ids=("allow-example",),
        now_epoch_s=1_900_000_001,
        ttl_seconds=60,
    )
    opened = coordinator.open_lease(
        NetworkLeaseRequest(
            lease_id="lease-9876",
            process=process,
            approval_grant=grant,
            required_capabilities=(
                "dns-control",
                "process-tree-lease",
                "selective-egress",
            ),
            expires_at_epoch_s=1_900_000_050,
        ),
        now_epoch_s=1_900_000_002,
    )
    assert opened.record.phase is NetworkLeasePhase.ACTIVE
    assert opened.record.attestation_digest == opened.attestation.attestation_digest
    assert coordinator.status(now_epoch_s=1_900_000_003)["protection_active"] is True

    refreshed = coordinator.refresh_lease("lease-9876", now_epoch_s=1_900_000_004)
    assert refreshed.record.revision == 3
    assert refreshed.record.phase is NetworkLeasePhase.ACTIVE

    closed = coordinator.close_lease(
        "lease-9876",
        reason_code="workload-complete",
        now_epoch_s=1_900_000_010,
    )
    assert closed.phase is NetworkLeasePhase.CLOSED
    assert coordinator.status(now_epoch_s=1_900_000_011)["protection_active"] is False
    assert provider.closed[-1] == "lease-9876:workload-complete"

    observer.available = False
    unavailable_grant = authority_signer.issue_grant(
        lease_id="lease-unavailable",
        policy_digest=policy.policy_digest,
        approval_digest=_APPROVAL_DIGEST,
        process=process,
        rule_ids=("allow-example",),
        now_epoch_s=1_900_000_020,
        ttl_seconds=60,
    )
    with pytest.raises(NetworkAuthorityError):
        coordinator.open_lease(
            NetworkLeaseRequest(
                lease_id="lease-unavailable",
                process=process,
                approval_grant=unavailable_grant,
                required_capabilities=("selective-egress",),
                expires_at_epoch_s=1_900_000_060,
            ),
            now_epoch_s=1_900_000_021,
        )

    observer.available = True
    provider.behavioral_test_digest = None
    unproven_grant = authority_signer.issue_grant(
        lease_id="lease-unproven",
        policy_digest=policy.policy_digest,
        approval_digest=_APPROVAL_DIGEST,
        process=process,
        rule_ids=("allow-example",),
        now_epoch_s=1_900_000_030,
        ttl_seconds=60,
    )
    with pytest.raises(NetworkAuthorityError):
        coordinator.open_lease(
            NetworkLeaseRequest(
                lease_id="lease-unproven",
                process=process,
                approval_grant=unproven_grant,
                required_capabilities=("selective-egress",),
                expires_at_epoch_s=1_900_000_070,
            ),
            now_epoch_s=1_900_000_031,
        )
