"""Daemon-owned coordinator for policy generations and process-tree network leases."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Final, Protocol, cast

from codex_plugin_scanner.guard.runtime.network_authority import (
    CompiledNetworkPolicy,
    GrantReplayLedger,
    NetworkApprovalGrant,
    NetworkAuthorityError,
    NetworkAuthorityReason,
    ProcessIdentity,
    VerifiedNetworkGrant,
    canonical_json_bytes,
    verify_process_grant,
)
from codex_plugin_scanner.guard.runtime.network_enforcement_receipts import (
    AttestedNetworkLease,
    SignedEvidence,
    verify_attested_network_lease,
)
from codex_plugin_scanner.guard.runtime.network_generation_store import (
    InstalledNetworkGeneration,
    NetworkGenerationStore,
)

_LEASE_SCHEMA: Final = "guard.network-lease-state.v1"
_MAX_LEASE_STATE_BYTES: Final = 512 * 1024
_MAX_LEASES: Final = 4096
_ID_MAX_LENGTH: Final = 128


class NetworkLeasePhase(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    DEGRADED = "degraded"
    CLOSING = "closing"
    CLOSED = "closed"
    QUARANTINED = "quarantined"


_TERMINAL_PHASES: Final = frozenset({NetworkLeasePhase.CLOSED, NetworkLeasePhase.QUARANTINED})
_ALLOWED_TRANSITIONS: Final = {
    NetworkLeasePhase.PENDING: frozenset(
        {NetworkLeasePhase.ACTIVE, NetworkLeasePhase.CLOSED, NetworkLeasePhase.QUARANTINED}
    ),
    NetworkLeasePhase.ACTIVE: frozenset(
        {NetworkLeasePhase.DEGRADED, NetworkLeasePhase.CLOSING, NetworkLeasePhase.QUARANTINED}
    ),
    NetworkLeasePhase.DEGRADED: frozenset(
        {NetworkLeasePhase.ACTIVE, NetworkLeasePhase.CLOSING, NetworkLeasePhase.QUARANTINED}
    ),
    NetworkLeasePhase.CLOSING: frozenset(
        {NetworkLeasePhase.CLOSED, NetworkLeasePhase.QUARANTINED}
    ),
    NetworkLeasePhase.CLOSED: frozenset(),
    NetworkLeasePhase.QUARANTINED: frozenset(),
}


@dataclass(frozen=True, slots=True)
class NetworkProviderProbe:
    provider_id: str
    provider_artifact_digest: str
    installed: bool
    verified: bool
    effective_grade: str
    capabilities: tuple[str, ...]
    probe_digest: str
    behavioral_test_digest: str | None
    observed_at_epoch_s: int
    valid_until_epoch_s: int
    reason_code: str

    @property
    def permits_enforcement(self) -> bool:
        return (
            self.installed
            and self.verified
            and self.effective_grade != "unavailable"
            and self.behavioral_test_digest is not None
            and self.valid_until_epoch_s > self.observed_at_epoch_s
        )


@dataclass(frozen=True, slots=True)
class NetworkObserverProbe:
    observer_id: str
    observer_artifact_digest: str
    installed: bool
    verified: bool
    probe_digest: str
    observed_at_epoch_s: int
    valid_until_epoch_s: int
    reason_code: str

    @property
    def permits_observation(self) -> bool:
        return (
            self.installed
            and self.verified
            and self.valid_until_epoch_s > self.observed_at_epoch_s
        )


@dataclass(frozen=True, slots=True)
class NetworkLeaseRequest:
    lease_id: str
    process: ProcessIdentity
    approval_grant: NetworkApprovalGrant
    required_capabilities: tuple[str, ...]
    expires_at_epoch_s: int


@dataclass(frozen=True, slots=True)
class NetworkLeaseRecord:
    revision: int
    phase: NetworkLeasePhase
    lease_id: str
    provider_id: str
    observer_id: str
    generation: int
    policy_digest: str
    process: ProcessIdentity
    required_capabilities: tuple[str, ...]
    expires_at_epoch_s: int
    enforcement_receipt: SignedEvidence | None
    observation_receipt: SignedEvidence | None
    attestation_digest: str | None
    reason_code: str
    updated_at_epoch_s: int

    def active_at(self, now_epoch_s: int) -> bool:
        return (
            self.phase is NetworkLeasePhase.ACTIVE
            and self.expires_at_epoch_s > now_epoch_s
            and self.enforcement_receipt is not None
            and self.observation_receipt is not None
            and self.attestation_digest is not None
        )


@dataclass(frozen=True, slots=True)
class CoordinatedNetworkLease:
    record: NetworkLeaseRecord
    attestation: AttestedNetworkLease


class NetworkEnforcementProvider(Protocol):
    @property
    def provider_id(self) -> str: ...

    def probe(self, *, now_epoch_s: int) -> NetworkProviderProbe: ...

    def apply_generation(self, policy: CompiledNetworkPolicy) -> str: ...

    def open_lease(
        self,
        *,
        policy: CompiledNetworkPolicy,
        grant: VerifiedNetworkGrant,
        required_capabilities: tuple[str, ...],
        expires_at_epoch_s: int,
    ) -> SignedEvidence: ...

    def inspect_lease(
        self,
        *,
        lease_id: str,
        policy: CompiledNetworkPolicy,
        process: ProcessIdentity,
        now_epoch_s: int,
    ) -> SignedEvidence: ...

    def close_lease(self, *, lease_id: str, reason_code: str) -> None: ...


class NetworkIndependentObserver(Protocol):
    @property
    def observer_id(self) -> str: ...

    def probe(self, *, now_epoch_s: int) -> NetworkObserverProbe: ...

    def observe_lease(
        self,
        *,
        lease_id: str,
        policy: CompiledNetworkPolicy,
        process: ProcessIdentity,
        provider_artifact_digest: str,
        now_epoch_s: int,
    ) -> SignedEvidence: ...


@dataclass(frozen=True, slots=True)
class NetworkProviderRegistration:
    provider: NetworkEnforcementProvider
    observer: NetworkIndependentObserver
    provider_keys: Mapping[str, bytes]
    observer_keys: Mapping[str, bytes]


class NetworkRemediationCoordinator:
    """Single daemon authority for installed network generations and leases."""

    def __init__(
        self,
        *,
        generation_store: NetworkGenerationStore,
        grant_replay_ledger: GrantReplayLedger,
        grant_trusted_keys: Mapping[str, bytes],
        lease_ledger: NetworkLeaseLedger,
        registrations: Sequence[NetworkProviderRegistration],
    ) -> None:
        self.generation_store = generation_store
        self.grant_replay_ledger = grant_replay_ledger
        self.grant_trusted_keys = dict(grant_trusted_keys)
        self.lease_ledger = lease_ledger
        self.registrations = tuple(registrations)
        self._mutex = threading.RLock()
        provider_ids = [registration.provider.provider_id for registration in self.registrations]
        observer_ids = [registration.observer.observer_id for registration in self.registrations]
        if len(provider_ids) != len(set(provider_ids)) or len(observer_ids) != len(set(observer_ids)):
            raise NetworkAuthorityError(
                NetworkAuthorityReason.INVALID_VALUE,
                "network provider and observer registrations must use unique identities",
            )
        if set(provider_ids) & set(observer_ids):
            raise NetworkAuthorityError(
                NetworkAuthorityReason.INVALID_VALUE,
                "network providers and independent observers cannot share identities",
            )

    def activate_generation(
        self,
        envelope: object,
        *,
        installed_at_epoch_s: int | None = None,
        now_epoch_s: int | None = None,
    ) -> InstalledNetworkGeneration:
        now = int(time.time()) if now_epoch_s is None else now_epoch_s
        with self._mutex:
            installed = self.generation_store.install(
                cast(object, envelope),
                installed_at_epoch_s=installed_at_epoch_s,
            )
            applied_provider_count = 0
            for registration in self.registrations:
                provider_probe, observer_probe = self._probe_registration(registration, now_epoch_s=now)
                if not provider_probe.permits_enforcement or not observer_probe.permits_observation:
                    continue
                applied_digest = registration.provider.apply_generation(installed.policy)
                _require_digest(applied_digest, field="applied_generation_digest")
                if not hmac.compare_digest(applied_digest, installed.policy.policy_digest):
                    raise NetworkAuthorityError(
                        NetworkAuthorityReason.STATE_UNSAFE,
                        "network provider applied a generation with the wrong policy digest",
                    )
                applied_provider_count += 1
            if self.registrations and applied_provider_count == 0:
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.STATE_UNSAFE,
                    "no installed provider and independent observer pair accepted the generation",
                )
            return installed

    def open_lease(
        self,
        request: NetworkLeaseRequest,
        *,
        now_epoch_s: int | None = None,
    ) -> CoordinatedNetworkLease:
        now = int(time.time()) if now_epoch_s is None else now_epoch_s
        _require_identifier(request.lease_id, field="lease_id")
        required_capabilities = tuple(
            sorted({_require_identifier(value, field="required_capability") for value in request.required_capabilities})
        )
        if not required_capabilities:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.INVALID_VALUE,
                "network leases require at least one achieved capability",
            )
        if request.expires_at_epoch_s <= now:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.GRANT_EXPIRED,
                "network lease expiry must be in the future",
            )
        with self._mutex:
            current = self.generation_store.load_current()
            if current is None:
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.STATE_UNSAFE,
                    "network lease cannot open without an installed generation",
                )
            grant = verify_process_grant(
                request.approval_grant,
                trusted_keys=self.grant_trusted_keys,
                expected_process=request.process,
                expected_lease_id=request.lease_id,
                expected_policy_digest=current.policy.policy_digest,
                replay_ledger=self.grant_replay_ledger,
                now_epoch_s=now,
            )
            registration, provider_probe, _observer_probe = self._select_registration(
                required_capabilities=required_capabilities,
                now_epoch_s=now,
            )
            pending = NetworkLeaseRecord(
                revision=1,
                phase=NetworkLeasePhase.PENDING,
                lease_id=request.lease_id,
                provider_id=provider_probe.provider_id,
                observer_id=registration.observer.observer_id,
                generation=current.policy.generation,
                policy_digest=current.policy.policy_digest,
                process=request.process,
                required_capabilities=required_capabilities,
                expires_at_epoch_s=request.expires_at_epoch_s,
                enforcement_receipt=None,
                observation_receipt=None,
                attestation_digest=None,
                reason_code="lease-opening",
                updated_at_epoch_s=now,
            )
            self.lease_ledger.create(pending)
            try:
                enforcement_receipt = registration.provider.open_lease(
                    policy=current.policy,
                    grant=grant,
                    required_capabilities=required_capabilities,
                    expires_at_epoch_s=request.expires_at_epoch_s,
                )
                observation_receipt = registration.observer.observe_lease(
                    lease_id=request.lease_id,
                    policy=current.policy,
                    process=request.process,
                    provider_artifact_digest=provider_probe.provider_artifact_digest,
                    now_epoch_s=now,
                )
                attestation = verify_attested_network_lease(
                    enforcement=enforcement_receipt,
                    observation=observation_receipt,
                    provider_keys=registration.provider_keys,
                    observer_keys=registration.observer_keys,
                )
                self._validate_attestation(
                    attestation,
                    request=request,
                    policy=current.policy,
                    required_capabilities=required_capabilities,
                    provider_probe=provider_probe,
                )
            except Exception:
                self._best_effort_close(registration.provider, request.lease_id, "lease-open-failed")
                quarantined = _transition_record(
                    pending,
                    phase=NetworkLeasePhase.QUARANTINED,
                    reason_code="lease-open-failed",
                    now_epoch_s=now,
                )
                self.lease_ledger.replace(quarantined, expected_revision=pending.revision)
                raise
            active = NetworkLeaseRecord(
                revision=pending.revision + 1,
                phase=NetworkLeasePhase.ACTIVE,
                lease_id=pending.lease_id,
                provider_id=pending.provider_id,
                observer_id=pending.observer_id,
                generation=pending.generation,
                policy_digest=pending.policy_digest,
                process=pending.process,
                required_capabilities=pending.required_capabilities,
                expires_at_epoch_s=pending.expires_at_epoch_s,
                enforcement_receipt=enforcement_receipt,
                observation_receipt=observation_receipt,
                attestation_digest=attestation.attestation_digest,
                reason_code="independently-observed-enforcement",
                updated_at_epoch_s=now,
            )
            self.lease_ledger.replace(active, expected_revision=pending.revision)
            return CoordinatedNetworkLease(record=active, attestation=attestation)

    def refresh_lease(
        self,
        lease_id: str,
        *,
        now_epoch_s: int | None = None,
    ) -> CoordinatedNetworkLease:
        now = int(time.time()) if now_epoch_s is None else now_epoch_s
        with self._mutex:
            record = self.lease_ledger.load(lease_id)
            if record is None or record.phase in _TERMINAL_PHASES:
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.STATE_UNSAFE,
                    "network lease is missing or terminal",
                )
            current = self.generation_store.load_current()
            if current is None or current.policy.policy_digest != record.policy_digest:
                return self._quarantine(record, reason_code="lease-generation-stale", now_epoch_s=now)
            registration = self._registration_for(record.provider_id, record.observer_id)
            provider_probe, observer_probe = self._probe_registration(registration, now_epoch_s=now)
            if not provider_probe.permits_enforcement or not observer_probe.permits_observation:
                return self._quarantine(record, reason_code="lease-provider-unhealthy", now_epoch_s=now)
            try:
                enforcement_receipt = registration.provider.inspect_lease(
                    lease_id=record.lease_id,
                    policy=current.policy,
                    process=record.process,
                    now_epoch_s=now,
                )
                observation_receipt = registration.observer.observe_lease(
                    lease_id=record.lease_id,
                    policy=current.policy,
                    process=record.process,
                    provider_artifact_digest=provider_probe.provider_artifact_digest,
                    now_epoch_s=now,
                )
                attestation = verify_attested_network_lease(
                    enforcement=enforcement_receipt,
                    observation=observation_receipt,
                    provider_keys=registration.provider_keys,
                    observer_keys=registration.observer_keys,
                )
                request = NetworkLeaseRequest(
                    lease_id=record.lease_id,
                    process=record.process,
                    approval_grant=cast(NetworkApprovalGrant, object()),
                    required_capabilities=record.required_capabilities,
                    expires_at_epoch_s=record.expires_at_epoch_s,
                )
                self._validate_attestation(
                    attestation,
                    request=request,
                    policy=current.policy,
                    required_capabilities=record.required_capabilities,
                    provider_probe=provider_probe,
                )
            except Exception:
                return self._quarantine(record, reason_code="lease-observation-failed", now_epoch_s=now)
            refreshed = NetworkLeaseRecord(
                revision=record.revision + 1,
                phase=NetworkLeasePhase.ACTIVE,
                lease_id=record.lease_id,
                provider_id=record.provider_id,
                observer_id=record.observer_id,
                generation=record.generation,
                policy_digest=record.policy_digest,
                process=record.process,
                required_capabilities=record.required_capabilities,
                expires_at_epoch_s=record.expires_at_epoch_s,
                enforcement_receipt=enforcement_receipt,
                observation_receipt=observation_receipt,
                attestation_digest=attestation.attestation_digest,
                reason_code="independently-observed-enforcement",
                updated_at_epoch_s=now,
            )
            self.lease_ledger.replace(refreshed, expected_revision=record.revision)
            return CoordinatedNetworkLease(record=refreshed, attestation=attestation)

    def close_lease(
        self,
        lease_id: str,
        *,
        reason_code: str = "lease-closed",
        now_epoch_s: int | None = None,
    ) -> NetworkLeaseRecord:
        now = int(time.time()) if now_epoch_s is None else now_epoch_s
        reason = _require_identifier(reason_code, field="reason_code")
        with self._mutex:
            record = self.lease_ledger.load(lease_id)
            if record is None:
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.STATE_UNSAFE,
                    "network lease does not exist",
                )
            if record.phase in _TERMINAL_PHASES:
                return record
            registration = self._registration_for(record.provider_id, record.observer_id)
            closing = _transition_record(
                record,
                phase=NetworkLeasePhase.CLOSING,
                reason_code=reason,
                now_epoch_s=now,
            )
            self.lease_ledger.replace(closing, expected_revision=record.revision)
            try:
                registration.provider.close_lease(lease_id=lease_id, reason_code=reason)
            except Exception:
                quarantined = _transition_record(
                    closing,
                    phase=NetworkLeasePhase.QUARANTINED,
                    reason_code="lease-close-unverified",
                    now_epoch_s=now,
                )
                self.lease_ledger.replace(quarantined, expected_revision=closing.revision)
                raise
            closed = _transition_record(
                closing,
                phase=NetworkLeasePhase.CLOSED,
                reason_code=reason,
                now_epoch_s=now,
            )
            self.lease_ledger.replace(closed, expected_revision=closing.revision)
            return closed

    def status(self, *, now_epoch_s: int | None = None) -> dict[str, object]:
        now = int(time.time()) if now_epoch_s is None else now_epoch_s
        active: list[dict[str, object]] = []
        degraded: list[dict[str, object]] = []
        for record in self.lease_ledger.list_records():
            projected = {
                "lease_id_digest": hashlib.sha256(record.lease_id.encode("utf-8")).hexdigest(),
                "phase": record.phase.value,
                "provider_id": record.provider_id,
                "observer_id": record.observer_id,
                "generation": record.generation,
                "policy_digest": record.policy_digest,
                "expires_at_epoch_s": record.expires_at_epoch_s,
                "reason_code": record.reason_code,
                "independently_observed": record.attestation_digest is not None,
            }
            if record.active_at(now):
                active.append(projected)
            elif record.phase not in _TERMINAL_PHASES:
                degraded.append(projected)
        return {
            "schema": "guard.network-coordinator-status.v1",
            "protection_active": bool(active),
            "independently_observed": bool(active),
            "active_lease_count": len(active),
            "degraded_lease_count": len(degraded),
            "active_leases": active,
            "degraded_leases": degraded,
        }

    def recover(self, *, now_epoch_s: int | None = None) -> tuple[NetworkLeaseRecord, ...]:
        now = int(time.time()) if now_epoch_s is None else now_epoch_s
        recovered: list[NetworkLeaseRecord] = []
        for record in self.lease_ledger.list_records():
            if record.phase in _TERMINAL_PHASES:
                continue
            if record.expires_at_epoch_s <= now:
                try:
                    recovered.append(
                        self.close_lease(
                            record.lease_id,
                            reason_code="lease-expired",
                            now_epoch_s=now,
                        )
                    )
                except Exception:
                    latest = self.lease_ledger.load(record.lease_id)
                    if latest is not None:
                        recovered.append(latest)
                continue
            try:
                recovered.append(self.refresh_lease(record.lease_id, now_epoch_s=now).record)
            except Exception:
                latest = self.lease_ledger.load(record.lease_id)
                if latest is not None:
                    recovered.append(latest)
        return tuple(recovered)

    def _select_registration(
        self,
        *,
        required_capabilities: tuple[str, ...],
        now_epoch_s: int,
    ) -> tuple[NetworkProviderRegistration, NetworkProviderProbe, NetworkObserverProbe]:
        candidates: list[
            tuple[NetworkProviderRegistration, NetworkProviderProbe, NetworkObserverProbe]
        ] = []
        required = set(required_capabilities)
        for registration in self.registrations:
            provider_probe, observer_probe = self._probe_registration(
                registration, now_epoch_s=now_epoch_s
            )
            if (
                provider_probe.permits_enforcement
                and observer_probe.permits_observation
                and required <= set(provider_probe.capabilities)
                and provider_probe.valid_until_epoch_s > now_epoch_s
                and observer_probe.valid_until_epoch_s > now_epoch_s
            ):
                candidates.append((registration, provider_probe, observer_probe))
        if not candidates:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "no installed and independently observable provider satisfies the lease",
            )
        candidates.sort(key=lambda item: item[1].provider_id)
        return candidates[0]

    def _probe_registration(
        self,
        registration: NetworkProviderRegistration,
        *,
        now_epoch_s: int,
    ) -> tuple[NetworkProviderProbe, NetworkObserverProbe]:
        provider_probe = registration.provider.probe(now_epoch_s=now_epoch_s)
        observer_probe = registration.observer.probe(now_epoch_s=now_epoch_s)
        _validate_provider_probe(provider_probe, now_epoch_s=now_epoch_s)
        _validate_observer_probe(observer_probe, now_epoch_s=now_epoch_s)
        if provider_probe.provider_id != registration.provider.provider_id:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network provider probe identity does not match its registration",
            )
        if observer_probe.observer_id != registration.observer.observer_id:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network observer probe identity does not match its registration",
            )
        if hmac.compare_digest(
            provider_probe.provider_artifact_digest,
            observer_probe.observer_artifact_digest,
        ):
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network enforcement and observation cannot use the same artifact",
            )
        return provider_probe, observer_probe

    def _registration_for(
        self, provider_id: str, observer_id: str
    ) -> NetworkProviderRegistration:
        for registration in self.registrations:
            if (
                registration.provider.provider_id == provider_id
                and registration.observer.observer_id == observer_id
            ):
                return registration
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network lease references an unregistered provider or observer",
        )

    def _validate_attestation(
        self,
        attestation: AttestedNetworkLease,
        *,
        request: NetworkLeaseRequest,
        policy: CompiledNetworkPolicy,
        required_capabilities: tuple[str, ...],
        provider_probe: NetworkProviderProbe,
    ) -> None:
        evidence = attestation.enforcement
        if (
            evidence.lease_id != request.lease_id
            or evidence.process != request.process
            or evidence.generation != policy.generation
            or not hmac.compare_digest(evidence.policy_digest, policy.policy_digest)
            or not hmac.compare_digest(
                evidence.provider_artifact_digest,
                provider_probe.provider_artifact_digest,
            )
            or not set(required_capabilities) <= set(evidence.capabilities)
            or evidence.expires_at_epoch_s < request.expires_at_epoch_s
        ):
            raise NetworkAuthorityError(
                NetworkAuthorityReason.SIGNATURE_INVALID,
                "network lease attestation does not satisfy the requested process lease",
            )

    def _quarantine(
        self,
        record: NetworkLeaseRecord,
        *,
        reason_code: str,
        now_epoch_s: int,
    ) -> CoordinatedNetworkLease:
        registration = self._registration_for(record.provider_id, record.observer_id)
        self._best_effort_close(registration.provider, record.lease_id, reason_code)
        quarantined = _transition_record(
            record,
            phase=NetworkLeasePhase.QUARANTINED,
            reason_code=reason_code,
            now_epoch_s=now_epoch_s,
        )
        self.lease_ledger.replace(quarantined, expected_revision=record.revision)
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network lease was quarantined because enforcement could not be re-verified",
        )

    @staticmethod
    def _best_effort_close(
        provider: NetworkEnforcementProvider,
        lease_id: str,
        reason_code: str,
    ) -> None:
        try:
            provider.close_lease(lease_id=lease_id, reason_code=reason_code)
        except Exception:
            return


class NetworkLeaseLedger:
    """HMAC-bound, crash-safe daemon lease state without raw command material."""

    def __init__(self, root: Path, *, state_hmac_key: bytes) -> None:
        if len(state_hmac_key) < 32:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.SIGNING_KEY_INVALID,
                "network lease state key must contain at least 32 bytes",
            )
        self.root = root
        self._state_hmac_key = bytes(state_hmac_key)
        self._mutex = threading.RLock()

    def create(self, record: NetworkLeaseRecord) -> None:
        if record.revision != 1 or record.phase is not NetworkLeasePhase.PENDING:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.INVALID_VALUE,
                "new network leases must begin in pending revision one",
            )
        with self._mutex:
            self._prepare_root()
            path = self._path(record.lease_id)
            if path.exists():
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.STATE_UNSAFE,
                    "network lease ID already exists",
                )
            self._write(path, record)

    def replace(self, record: NetworkLeaseRecord, *, expected_revision: int) -> None:
        with self._mutex:
            current = self.load(record.lease_id)
            if current is None or current.revision != expected_revision:
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.STATE_UNSAFE,
                    "network lease revision changed concurrently",
                )
            if record.revision != expected_revision + 1 or record.phase not in _ALLOWED_TRANSITIONS[current.phase]:
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.STATE_UNSAFE,
                    "network lease state transition is invalid",
                )
            self._write(self._path(record.lease_id), record)

    def load(self, lease_id: str) -> NetworkLeaseRecord | None:
        with self._mutex:
            self._prepare_root()
            path = self._path(lease_id)
            if not path.exists():
                return None
            return self._decode(_read_private(path))

    def list_records(self) -> tuple[NetworkLeaseRecord, ...]:
        with self._mutex:
            self._prepare_root()
            paths = sorted(self.root.glob("*.json"))
            if len(paths) > _MAX_LEASES:
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.STATE_UNSAFE,
                    "network lease ledger exceeds its entry ceiling",
                )
            records = [self._decode(_read_private(path)) for path in paths]
            return tuple(sorted(records, key=lambda record: record.lease_id))

    def _prepare_root(self) -> None:
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        _assert_private_directory(self.root)

    def _path(self, lease_id: str) -> Path:
        _require_identifier(lease_id, field="lease_id")
        return self.root / f"{hashlib.sha256(lease_id.encode('utf-8')).hexdigest()}.json"

    def _write(self, path: Path, record: NetworkLeaseRecord) -> None:
        payload = _record_payload(record)
        envelope = {
            "schema": _LEASE_SCHEMA,
            "payload": payload,
            "state_mac": hmac.new(
                self._state_hmac_key,
                canonical_json_bytes(payload),
                hashlib.sha256,
            ).hexdigest(),
        }
        _atomic_private(path, canonical_json_bytes(envelope))

    def _decode(self, raw: bytes) -> NetworkLeaseRecord:
        try:
            envelope = json.loads(raw)
        except (UnicodeDecodeError, ValueError) as exc:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network lease state is not valid JSON",
            ) from exc
        if not isinstance(envelope, dict) or set(envelope) != {"schema", "payload", "state_mac"}:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network lease state envelope fields are invalid",
            )
        if envelope.get("schema") != _LEASE_SCHEMA or not isinstance(envelope.get("payload"), dict):
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network lease state schema is invalid",
            )
        payload = cast(dict[str, object], envelope["payload"])
        state_mac = _require_digest(envelope.get("state_mac"), field="state_mac")
        expected_mac = hmac.new(
            self._state_hmac_key,
            canonical_json_bytes(payload),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(state_mac, expected_mac):
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network lease state authentication failed",
            )
        return _record_from_payload(payload)


def _record_payload(record: NetworkLeaseRecord) -> dict[str, object]:
    return {
        "revision": record.revision,
        "phase": record.phase.value,
        "lease_id": record.lease_id,
        "provider_id": record.provider_id,
        "observer_id": record.observer_id,
        "generation": record.generation,
        "policy_digest": record.policy_digest,
        "process": record.process.to_json(),
        "required_capabilities": list(record.required_capabilities),
        "expires_at_epoch_s": record.expires_at_epoch_s,
        "enforcement_receipt": (
            record.enforcement_receipt.to_json() if record.enforcement_receipt is not None else None
        ),
        "observation_receipt": (
            record.observation_receipt.to_json() if record.observation_receipt is not None else None
        ),
        "attestation_digest": record.attestation_digest,
        "reason_code": record.reason_code,
        "updated_at_epoch_s": record.updated_at_epoch_s,
    }


def _record_from_payload(payload: Mapping[str, object]) -> NetworkLeaseRecord:
    expected = {
        "revision",
        "phase",
        "lease_id",
        "provider_id",
        "observer_id",
        "generation",
        "policy_digest",
        "process",
        "required_capabilities",
        "expires_at_epoch_s",
        "enforcement_receipt",
        "observation_receipt",
        "attestation_digest",
        "reason_code",
        "updated_at_epoch_s",
    }
    if set(payload) != expected:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network lease state fields do not match the schema",
        )
    phase_value = payload.get("phase")
    try:
        phase = NetworkLeasePhase(phase_value)
    except (TypeError, ValueError) as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network lease phase is invalid",
        ) from exc
    process_value = payload.get("process")
    if not isinstance(process_value, Mapping) or set(process_value) != {
        "pid",
        "start_token",
        "executable_digest",
    }:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network lease process identity is invalid",
        )
    process = ProcessIdentity(
        pid=_require_positive_int(process_value.get("pid"), field="pid"),
        start_token=_require_digest(process_value.get("start_token"), field="start_token"),
        executable_digest=_require_digest(
            process_value.get("executable_digest"), field="executable_digest"
        ),
    )
    capabilities_value = payload.get("required_capabilities")
    if not isinstance(capabilities_value, list):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network lease capabilities must be a list",
        )
    capabilities = tuple(
        _require_identifier(value, field="required_capability") for value in capabilities_value
    )
    if not capabilities or tuple(sorted(set(capabilities))) != capabilities:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network lease capabilities must be unique and sorted",
        )
    enforcement_value = payload.get("enforcement_receipt")
    observation_value = payload.get("observation_receipt")
    enforcement = SignedEvidence.from_json(enforcement_value) if isinstance(enforcement_value, Mapping) else None
    observation = SignedEvidence.from_json(observation_value) if isinstance(observation_value, Mapping) else None
    attestation_value = payload.get("attestation_digest")
    attestation_digest = (
        _require_digest(attestation_value, field="attestation_digest")
        if attestation_value is not None
        else None
    )
    return NetworkLeaseRecord(
        revision=_require_positive_int(payload.get("revision"), field="revision"),
        phase=phase,
        lease_id=_require_identifier(payload.get("lease_id"), field="lease_id"),
        provider_id=_require_identifier(payload.get("provider_id"), field="provider_id"),
        observer_id=_require_identifier(payload.get("observer_id"), field="observer_id"),
        generation=_require_positive_int(payload.get("generation"), field="generation"),
        policy_digest=_require_digest(payload.get("policy_digest"), field="policy_digest"),
        process=process,
        required_capabilities=capabilities,
        expires_at_epoch_s=_require_positive_int(
            payload.get("expires_at_epoch_s"), field="expires_at_epoch_s"
        ),
        enforcement_receipt=enforcement,
        observation_receipt=observation,
        attestation_digest=attestation_digest,
        reason_code=_require_identifier(payload.get("reason_code"), field="reason_code"),
        updated_at_epoch_s=_require_nonnegative_int(
            payload.get("updated_at_epoch_s"), field="updated_at_epoch_s"
        ),
    )


def _transition_record(
    record: NetworkLeaseRecord,
    *,
    phase: NetworkLeasePhase,
    reason_code: str,
    now_epoch_s: int,
) -> NetworkLeaseRecord:
    if phase not in _ALLOWED_TRANSITIONS[record.phase]:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network lease state transition is invalid",
        )
    return NetworkLeaseRecord(
        revision=record.revision + 1,
        phase=phase,
        lease_id=record.lease_id,
        provider_id=record.provider_id,
        observer_id=record.observer_id,
        generation=record.generation,
        policy_digest=record.policy_digest,
        process=record.process,
        required_capabilities=record.required_capabilities,
        expires_at_epoch_s=record.expires_at_epoch_s,
        enforcement_receipt=record.enforcement_receipt,
        observation_receipt=record.observation_receipt,
        attestation_digest=record.attestation_digest,
        reason_code=_require_identifier(reason_code, field="reason_code"),
        updated_at_epoch_s=now_epoch_s,
    )


def _validate_provider_probe(probe: NetworkProviderProbe, *, now_epoch_s: int) -> None:
    _require_identifier(probe.provider_id, field="provider_id")
    _require_digest(probe.provider_artifact_digest, field="provider_artifact_digest")
    _require_digest(probe.probe_digest, field="probe_digest")
    if probe.behavioral_test_digest is not None:
        _require_digest(probe.behavioral_test_digest, field="behavioral_test_digest")
    if (
        tuple(sorted(set(probe.capabilities))) != probe.capabilities
        or any(not value for value in probe.capabilities)
        or probe.observed_at_epoch_s > now_epoch_s + 30
    ):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network provider probe is malformed or future-dated",
        )
    for capability in probe.capabilities:
        _require_identifier(capability, field="capability")


def _validate_observer_probe(probe: NetworkObserverProbe, *, now_epoch_s: int) -> None:
    _require_identifier(probe.observer_id, field="observer_id")
    _require_digest(probe.observer_artifact_digest, field="observer_artifact_digest")
    _require_digest(probe.probe_digest, field="probe_digest")
    if probe.observed_at_epoch_s > now_epoch_s + 30:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network observer probe is future-dated",
        )


def _atomic_private(path: Path, content: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        fchmod = getattr(os, "fchmod", None)
        if fchmod is not None:
            fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            directory_descriptor = os.open(
                path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _read_private(path: Path) -> bytes:
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network lease state cannot be inspected",
        ) from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or path.is_symlink()
        or _wrong_owner(info)
        or _permissive_mode(info)
    ):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network lease state must be private and owner-controlled",
        )
    raw = path.read_bytes()
    if len(raw) > _MAX_LEASE_STATE_BYTES:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network lease state exceeds its byte ceiling",
        )
    return raw


def _assert_private_directory(path: Path) -> None:
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or _wrong_owner(info) or _permissive_mode(info):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network lease directory must be private and owner-controlled",
        )


def _wrong_owner(info: os.stat_result) -> bool:
    getuid = getattr(os, "getuid", None)
    return getuid is not None and info.st_uid != getuid()


def _permissive_mode(info: os.stat_result) -> bool:
    return os.name != "nt" and bool(info.st_mode & 0o077)


def _require_identifier(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _ID_MAX_LENGTH
        or any(not (character.isalnum() or character in "._:-") for character in value)
    ):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"network coordinator {field} has invalid identifier syntax",
        )
    return value


def _require_digest(value: object, *, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"network coordinator {field} must be a SHA-256 digest",
        )
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"network coordinator {field} must be a SHA-256 digest",
        ) from exc
    if raw.hex() != value:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"network coordinator {field} must be a lowercase SHA-256 digest",
        )
    return value


def _require_positive_int(value: object, *, field: str) -> int:
    if type(value) is not int or cast(int, value) <= 0:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"network coordinator {field} must be a positive integer",
        )
    return cast(int, value)


def _require_nonnegative_int(value: object, *, field: str) -> int:
    if type(value) is not int or cast(int, value) < 0:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"network coordinator {field} must be a non-negative integer",
        )
    return cast(int, value)


__all__: Sequence[str] = (
    "CoordinatedNetworkLease",
    "NetworkEnforcementProvider",
    "NetworkIndependentObserver",
    "NetworkLeaseLedger",
    "NetworkLeasePhase",
    "NetworkLeaseRecord",
    "NetworkLeaseRequest",
    "NetworkObserverProbe",
    "NetworkProviderProbe",
    "NetworkProviderRegistration",
    "NetworkRemediationCoordinator",
)
