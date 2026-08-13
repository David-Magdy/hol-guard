"""Dual-authority receipts for installed network enforcement and observation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, cast

from codex_plugin_scanner.guard.runtime.network_authority import (
    NetworkAuthorityError,
    NetworkAuthorityReason,
    ProcessIdentity,
    canonical_json_bytes,
)

_ENFORCEMENT_SCHEMA: Final = "guard.network-enforcement-evidence.v1"
_OBSERVATION_SCHEMA: Final = "guard.network-observation-evidence.v1"
_ATTESTATION_SCHEMA: Final = "guard.network-lease-attestation.v1"
_ID_RE: Final = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")
_MAX_RECEIPT_BYTES: Final = 128 * 1024


@dataclass(frozen=True, slots=True)
class SignedEvidence:
    schema: str
    key_id: str
    payload: bytes
    signature: bytes

    def to_json(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "key_id": self.key_id,
            "payload": _b64url_encode(self.payload),
            "signature": _b64url_encode(self.signature),
        }

    @classmethod
    def from_json(cls, raw: bytes | str | Mapping[str, object]) -> SignedEvidence:
        value = _parse_object(raw)
        _exact_fields(value, {"schema", "key_id", "payload", "signature"})
        schema = _identifier(value.get("schema"), field="schema")
        if schema not in {_ENFORCEMENT_SCHEMA, _OBSERVATION_SCHEMA}:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.INVALID_SCHEMA,
                "network evidence schema is unsupported",
            )
        return cls(
            schema=schema,
            key_id=_identifier(value.get("key_id"), field="key_id"),
            payload=_b64url_decode(value.get("payload"), field="payload"),
            signature=_b64url_decode(value.get("signature"), field="signature"),
        )


@dataclass(frozen=True, slots=True)
class EnforcementEvidence:
    lease_id: str
    provider_id: str
    provider_artifact_digest: str
    generation: int
    policy_digest: str
    process: ProcessIdentity
    boundary_digest: str
    applied_at_epoch_s: int
    expires_at_epoch_s: int
    capabilities: tuple[str, ...]
    probe_digest: str
    receipt_digest: str


@dataclass(frozen=True, slots=True)
class ObservationEvidence:
    lease_id: str
    observer_id: str
    observer_artifact_digest: str
    observed_provider_artifact_digest: str
    generation: int
    policy_digest: str
    process: ProcessIdentity
    first_observed_at_epoch_s: int
    last_observed_at_epoch_s: int
    sample_count: int
    allowed_flow_count: int
    dropped_flow_count: int
    violation_count: int
    probe_digest: str
    receipt_digest: str


@dataclass(frozen=True, slots=True)
class AttestedNetworkLease:
    enforcement: EnforcementEvidence
    observation: ObservationEvidence
    provider_key_id: str
    observer_key_id: str
    attestation_digest: str

    def to_json(self) -> dict[str, object]:
        return {
            "schema": _ATTESTATION_SCHEMA,
            "lease_id": self.enforcement.lease_id,
            "generation": self.enforcement.generation,
            "policy_digest": self.enforcement.policy_digest,
            "provider_id": self.enforcement.provider_id,
            "provider_artifact_digest": self.enforcement.provider_artifact_digest,
            "provider_key_id": self.provider_key_id,
            "provider_receipt_digest": self.enforcement.receipt_digest,
            "observer_id": self.observation.observer_id,
            "observer_artifact_digest": self.observation.observer_artifact_digest,
            "observer_key_id": self.observer_key_id,
            "observer_receipt_digest": self.observation.receipt_digest,
            "process": self.enforcement.process.to_json(),
            "effective_from_epoch_s": max(
                self.enforcement.applied_at_epoch_s,
                self.observation.first_observed_at_epoch_s,
            ),
            "effective_until_epoch_s": min(
                self.enforcement.expires_at_epoch_s,
                self.observation.last_observed_at_epoch_s,
            ),
            "attestation_digest": self.attestation_digest,
        }


class Ed25519EvidenceSigner:
    """Purpose-bound Ed25519 signer for provider or observer evidence."""

    def __init__(self, *, key_id: str, private_key: bytes, purpose: str) -> None:
        self.key_id = _identifier(key_id, field="key_id")
        self.purpose = _identifier(purpose, field="purpose")
        if len(private_key) != 32:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.SIGNING_KEY_INVALID,
                "network evidence Ed25519 keys must contain exactly 32 seed bytes",
            )
        self._private_key = bytes(private_key)

    @classmethod
    def generate(cls, *, key_id: str, purpose: str) -> Ed25519EvidenceSigner:
        return cls(key_id=key_id, private_key=secrets.token_bytes(32), purpose=purpose)

    def public_key_bytes(self) -> bytes:
        serialization = _serialization()
        return cast(
            bytes,
            _private_key(self._private_key).public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
        )

    def sign(self, *, schema: str, payload: Mapping[str, object]) -> SignedEvidence:
        if schema not in {_ENFORCEMENT_SCHEMA, _OBSERVATION_SCHEMA}:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.INVALID_SCHEMA,
                "network evidence signer received an unsupported schema",
            )
        bounded = {
            **payload,
            "schema": schema,
            "signing_purpose": self.purpose,
        }
        encoded = canonical_json_bytes(bounded)
        if len(encoded) > _MAX_RECEIPT_BYTES:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.POLICY_TOO_LARGE,
                "network evidence exceeds the receipt byte ceiling",
            )
        signature = cast(bytes, _private_key(self._private_key).sign(encoded))
        return SignedEvidence(schema=schema, key_id=self.key_id, payload=encoded, signature=signature)


def issue_enforcement_evidence(
    signer: Ed25519EvidenceSigner,
    *,
    lease_id: str,
    provider_id: str,
    provider_artifact_digest: str,
    generation: int,
    policy_digest: str,
    process: ProcessIdentity,
    boundary_digest: str,
    applied_at_epoch_s: int,
    expires_at_epoch_s: int,
    capabilities: Sequence[str],
    probe_digest: str,
) -> SignedEvidence:
    normalized_capabilities = tuple(sorted({_identifier(value, field="capability") for value in capabilities}))
    if not normalized_capabilities:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network enforcement evidence requires at least one achieved capability",
        )
    if expires_at_epoch_s <= applied_at_epoch_s:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network enforcement evidence expiry must follow application time",
        )
    return signer.sign(
        schema=_ENFORCEMENT_SCHEMA,
        payload={
            "lease_id": _identifier(lease_id, field="lease_id"),
            "provider_id": _identifier(provider_id, field="provider_id"),
            "provider_artifact_digest": _digest(
                provider_artifact_digest, field="provider_artifact_digest"
            ),
            "generation": _positive_int(generation, field="generation"),
            "policy_digest": _digest(policy_digest, field="policy_digest"),
            "process": process.to_json(),
            "boundary_digest": _digest(boundary_digest, field="boundary_digest"),
            "applied_at_epoch_s": _nonnegative_int(
                applied_at_epoch_s, field="applied_at_epoch_s"
            ),
            "expires_at_epoch_s": _positive_int(
                expires_at_epoch_s, field="expires_at_epoch_s"
            ),
            "capabilities": list(normalized_capabilities),
            "probe_digest": _digest(probe_digest, field="probe_digest"),
        },
    )


def issue_observation_evidence(
    signer: Ed25519EvidenceSigner,
    *,
    lease_id: str,
    observer_id: str,
    observer_artifact_digest: str,
    observed_provider_artifact_digest: str,
    generation: int,
    policy_digest: str,
    process: ProcessIdentity,
    first_observed_at_epoch_s: int,
    last_observed_at_epoch_s: int,
    sample_count: int,
    allowed_flow_count: int,
    dropped_flow_count: int,
    violation_count: int,
    probe_digest: str,
) -> SignedEvidence:
    if last_observed_at_epoch_s < first_observed_at_epoch_s:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network observation evidence time range is reversed",
        )
    counts = (sample_count, allowed_flow_count, dropped_flow_count, violation_count)
    if any(type(value) is not int or value < 0 for value in counts):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network observation evidence counts must be non-negative integers",
        )
    if allowed_flow_count + dropped_flow_count > sample_count:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network observation flow counts cannot exceed the sample count",
        )
    return signer.sign(
        schema=_OBSERVATION_SCHEMA,
        payload={
            "lease_id": _identifier(lease_id, field="lease_id"),
            "observer_id": _identifier(observer_id, field="observer_id"),
            "observer_artifact_digest": _digest(
                observer_artifact_digest, field="observer_artifact_digest"
            ),
            "observed_provider_artifact_digest": _digest(
                observed_provider_artifact_digest,
                field="observed_provider_artifact_digest",
            ),
            "generation": _positive_int(generation, field="generation"),
            "policy_digest": _digest(policy_digest, field="policy_digest"),
            "process": process.to_json(),
            "first_observed_at_epoch_s": _nonnegative_int(
                first_observed_at_epoch_s,
                field="first_observed_at_epoch_s",
            ),
            "last_observed_at_epoch_s": _nonnegative_int(
                last_observed_at_epoch_s,
                field="last_observed_at_epoch_s",
            ),
            "sample_count": sample_count,
            "allowed_flow_count": allowed_flow_count,
            "dropped_flow_count": dropped_flow_count,
            "violation_count": violation_count,
            "probe_digest": _digest(probe_digest, field="probe_digest"),
        },
    )


def verify_attested_network_lease(
    *,
    enforcement: SignedEvidence | bytes | str | Mapping[str, object],
    observation: SignedEvidence | bytes | str | Mapping[str, object],
    provider_keys: Mapping[str, bytes],
    observer_keys: Mapping[str, bytes],
    minimum_observation_samples: int = 1,
) -> AttestedNetworkLease:
    """Verify separate provider and observer authorities for one active lease."""

    provider_receipt = enforcement if isinstance(enforcement, SignedEvidence) else SignedEvidence.from_json(enforcement)
    observer_receipt = observation if isinstance(observation, SignedEvidence) else SignedEvidence.from_json(observation)
    if provider_receipt.schema != _ENFORCEMENT_SCHEMA or observer_receipt.schema != _OBSERVATION_SCHEMA:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_SCHEMA,
            "network lease evidence uses the wrong receipt schema",
        )
    if provider_receipt.key_id == observer_receipt.key_id:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNATURE_INVALID,
            "network enforcement and observation must use separate signing authorities",
        )
    provider_payload = _verify_receipt(provider_receipt, trusted_keys=provider_keys)
    observer_payload = _verify_receipt(observer_receipt, trusted_keys=observer_keys)
    enforcement_evidence = _parse_enforcement(provider_payload, provider_receipt)
    observation_evidence = _parse_observation(observer_payload, observer_receipt)
    if enforcement_evidence.provider_id == observation_evidence.observer_id:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNATURE_INVALID,
            "network observer identity must be independent from the enforcement provider",
        )
    if (
        enforcement_evidence.lease_id != observation_evidence.lease_id
        or enforcement_evidence.generation != observation_evidence.generation
        or not hmac.compare_digest(
            enforcement_evidence.policy_digest,
            observation_evidence.policy_digest,
        )
        or enforcement_evidence.process != observation_evidence.process
        or not hmac.compare_digest(
            enforcement_evidence.provider_artifact_digest,
            observation_evidence.observed_provider_artifact_digest,
        )
    ):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNATURE_INVALID,
            "network enforcement and observation receipts do not describe the same lease",
        )
    if observation_evidence.sample_count < minimum_observation_samples:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network observation evidence does not meet the sample floor",
        )
    effective_from = max(
        enforcement_evidence.applied_at_epoch_s,
        observation_evidence.first_observed_at_epoch_s,
    )
    effective_until = min(
        enforcement_evidence.expires_at_epoch_s,
        observation_evidence.last_observed_at_epoch_s,
    )
    if effective_until < effective_from:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNATURE_INVALID,
            "network enforcement and observation windows do not overlap",
        )
    attestation_without_digest = {
        "schema": _ATTESTATION_SCHEMA,
        "lease_id": enforcement_evidence.lease_id,
        "generation": enforcement_evidence.generation,
        "policy_digest": enforcement_evidence.policy_digest,
        "provider_receipt_digest": enforcement_evidence.receipt_digest,
        "observer_receipt_digest": observation_evidence.receipt_digest,
        "effective_from_epoch_s": effective_from,
        "effective_until_epoch_s": effective_until,
    }
    return AttestedNetworkLease(
        enforcement=enforcement_evidence,
        observation=observation_evidence,
        provider_key_id=provider_receipt.key_id,
        observer_key_id=observer_receipt.key_id,
        attestation_digest=hashlib.sha256(
            canonical_json_bytes(attestation_without_digest)
        ).hexdigest(),
    )


def _verify_receipt(receipt: SignedEvidence, *, trusted_keys: Mapping[str, bytes]) -> dict[str, object]:
    public_key = trusted_keys.get(receipt.key_id)
    if public_key is None or len(public_key) != 32:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNING_KEY_INVALID,
            "network evidence signing key is not trusted",
        )
    try:
        _public_key(public_key).verify(receipt.signature, receipt.payload)
    except Exception as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNATURE_INVALID,
            "network evidence signature is invalid",
        ) from exc
    payload = _parse_object(receipt.payload)
    if receipt.payload != canonical_json_bytes(payload) or payload.get("schema") != receipt.schema:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNATURE_INVALID,
            "network evidence payload is not canonical or schema-bound",
        )
    return payload


def _parse_enforcement(payload: Mapping[str, object], receipt: SignedEvidence) -> EnforcementEvidence:
    _exact_fields(
        payload,
        {
            "schema",
            "signing_purpose",
            "lease_id",
            "provider_id",
            "provider_artifact_digest",
            "generation",
            "policy_digest",
            "process",
            "boundary_digest",
            "applied_at_epoch_s",
            "expires_at_epoch_s",
            "capabilities",
            "probe_digest",
        },
    )
    if payload.get("schema") != _ENFORCEMENT_SCHEMA:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_SCHEMA,
            "network enforcement evidence schema is invalid",
        )
    capabilities_raw = payload.get("capabilities")
    if not isinstance(capabilities_raw, list):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network enforcement capabilities must be a list",
        )
    capabilities = tuple(_identifier(value, field="capability") for value in capabilities_raw)
    if not capabilities or tuple(sorted(set(capabilities))) != capabilities:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network enforcement capabilities must be unique and sorted",
        )
    applied_at = _nonnegative_int(payload.get("applied_at_epoch_s"), field="applied_at_epoch_s")
    expires_at = _positive_int(payload.get("expires_at_epoch_s"), field="expires_at_epoch_s")
    if expires_at <= applied_at:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network enforcement evidence has an invalid validity window",
        )
    return EnforcementEvidence(
        lease_id=_identifier(payload.get("lease_id"), field="lease_id"),
        provider_id=_identifier(payload.get("provider_id"), field="provider_id"),
        provider_artifact_digest=_digest(
            payload.get("provider_artifact_digest"), field="provider_artifact_digest"
        ),
        generation=_positive_int(payload.get("generation"), field="generation"),
        policy_digest=_digest(payload.get("policy_digest"), field="policy_digest"),
        process=_process(payload.get("process")),
        boundary_digest=_digest(payload.get("boundary_digest"), field="boundary_digest"),
        applied_at_epoch_s=applied_at,
        expires_at_epoch_s=expires_at,
        capabilities=capabilities,
        probe_digest=_digest(payload.get("probe_digest"), field="probe_digest"),
        receipt_digest=hashlib.sha256(canonical_json_bytes(receipt.to_json())).hexdigest(),
    )


def _parse_observation(payload: Mapping[str, object], receipt: SignedEvidence) -> ObservationEvidence:
    _exact_fields(
        payload,
        {
            "schema",
            "signing_purpose",
            "lease_id",
            "observer_id",
            "observer_artifact_digest",
            "observed_provider_artifact_digest",
            "generation",
            "policy_digest",
            "process",
            "first_observed_at_epoch_s",
            "last_observed_at_epoch_s",
            "sample_count",
            "allowed_flow_count",
            "dropped_flow_count",
            "violation_count",
            "probe_digest",
        },
    )
    if payload.get("schema") != _OBSERVATION_SCHEMA:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_SCHEMA,
            "network observation evidence schema is invalid",
        )
    first = _nonnegative_int(
        payload.get("first_observed_at_epoch_s"), field="first_observed_at_epoch_s"
    )
    last = _nonnegative_int(
        payload.get("last_observed_at_epoch_s"), field="last_observed_at_epoch_s"
    )
    sample_count = _nonnegative_int(payload.get("sample_count"), field="sample_count")
    allowed = _nonnegative_int(
        payload.get("allowed_flow_count"), field="allowed_flow_count"
    )
    dropped = _nonnegative_int(
        payload.get("dropped_flow_count"), field="dropped_flow_count"
    )
    violations = _nonnegative_int(
        payload.get("violation_count"), field="violation_count"
    )
    if last < first or allowed + dropped > sample_count:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network observation evidence has inconsistent time or count fields",
        )
    return ObservationEvidence(
        lease_id=_identifier(payload.get("lease_id"), field="lease_id"),
        observer_id=_identifier(payload.get("observer_id"), field="observer_id"),
        observer_artifact_digest=_digest(
            payload.get("observer_artifact_digest"), field="observer_artifact_digest"
        ),
        observed_provider_artifact_digest=_digest(
            payload.get("observed_provider_artifact_digest"),
            field="observed_provider_artifact_digest",
        ),
        generation=_positive_int(payload.get("generation"), field="generation"),
        policy_digest=_digest(payload.get("policy_digest"), field="policy_digest"),
        process=_process(payload.get("process")),
        first_observed_at_epoch_s=first,
        last_observed_at_epoch_s=last,
        sample_count=sample_count,
        allowed_flow_count=allowed,
        dropped_flow_count=dropped,
        violation_count=violations,
        probe_digest=_digest(payload.get("probe_digest"), field="probe_digest"),
        receipt_digest=hashlib.sha256(canonical_json_bytes(receipt.to_json())).hexdigest(),
    )


def _process(value: object) -> ProcessIdentity:
    if not isinstance(value, Mapping):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network evidence process identity must be an object",
        )
    process = cast(Mapping[str, object], value)
    _exact_fields(process, {"pid", "start_token", "executable_digest"})
    return ProcessIdentity(
        pid=_positive_int(process.get("pid"), field="pid"),
        start_token=_digest(process.get("start_token"), field="start_token"),
        executable_digest=_digest(
            process.get("executable_digest"), field="executable_digest"
        ),
    )


def _parse_object(raw: bytes | str | Mapping[str, object]) -> dict[str, object]:
    if isinstance(raw, Mapping):
        return dict(raw)
    if isinstance(raw, bytes):
        if len(raw) > _MAX_RECEIPT_BYTES:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.POLICY_TOO_LARGE,
                "network evidence exceeds the receipt byte ceiling",
            )
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.INVALID_JSON,
                "network evidence must be UTF-8 JSON",
            ) from exc
    elif isinstance(raw, str):
        text = raw
        if len(text.encode("utf-8")) > _MAX_RECEIPT_BYTES:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.POLICY_TOO_LARGE,
                "network evidence exceeds the receipt byte ceiling",
            )
    else:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_JSON,
            "network evidence must be a JSON object",
        )

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.INVALID_JSON,
                    "network evidence contains duplicate JSON keys",
                )
            result[key] = value
        return result

    try:
        parsed = json.loads(text, object_pairs_hook=reject_duplicates)
    except NetworkAuthorityError:
        raise
    except ValueError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_JSON,
            "network evidence is not valid JSON",
        ) from exc
    if not isinstance(parsed, dict):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_JSON,
            "network evidence must be a JSON object",
        )
    return cast(dict[str, object], parsed)


def _exact_fields(value: Mapping[str, object], expected: set[str]) -> None:
    if set(value) != expected:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.UNKNOWN_FIELD,
            "network evidence fields do not match the schema",
        )


def _identifier(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"network evidence {field} has invalid identifier syntax",
        )
    return value


def _digest(value: object, *, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"network evidence {field} must be a SHA-256 digest",
        )
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"network evidence {field} must be a SHA-256 digest",
        ) from exc
    if raw.hex() != value:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"network evidence {field} must be a lowercase SHA-256 digest",
        )
    return value


def _positive_int(value: object, *, field: str) -> int:
    if type(value) is not int or cast(int, value) <= 0:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"network evidence {field} must be a positive integer",
        )
    return cast(int, value)


def _nonnegative_int(value: object, *, field: str) -> int:
    if type(value) is not int or cast(int, value) < 0:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"network evidence {field} must be a non-negative integer",
        )
    return cast(int, value)


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: object, *, field: str) -> bytes:
    if not isinstance(value, str) or not value or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"network evidence {field} must be unpadded base64url",
        )
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (TypeError, ValueError) as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"network evidence {field} must be unpadded base64url",
        ) from exc


def _private_key(seed: bytes) -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNING_KEY_INVALID,
            "Ed25519 support is unavailable",
        ) from exc
    return Ed25519PrivateKey.from_private_bytes(seed)


def _public_key(raw: bytes) -> Any:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNING_KEY_INVALID,
            "Ed25519 support is unavailable",
        ) from exc
    return Ed25519PublicKey.from_public_bytes(raw)


def _serialization() -> Any:
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNING_KEY_INVALID,
            "Ed25519 serialization support is unavailable",
        ) from exc
    return serialization


__all__: Sequence[str] = (
    "AttestedNetworkLease",
    "Ed25519EvidenceSigner",
    "EnforcementEvidence",
    "ObservationEvidence",
    "SignedEvidence",
    "issue_enforcement_evidence",
    "issue_observation_evidence",
    "verify_attested_network_lease",
)
