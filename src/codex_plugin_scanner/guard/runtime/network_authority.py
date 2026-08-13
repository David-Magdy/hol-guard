"""Canonical network-policy authority, signed generations, and process-bound grants.

This module is deliberately backend-neutral. It owns the policy bytes that an
installed provider may enforce, but it never treats compilation or signing as
evidence that traffic is currently mediated.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import stat
import tempfile
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Final, cast

_NETWORK_POLICY_SCHEMA: Final = "guard.network-policy.v1"
_NETWORK_GENERATION_SCHEMA: Final = "guard.network-generation.v1"
_NETWORK_GRANT_SCHEMA: Final = "guard.network-approval-grant.v1"
_MAX_POLICY_BYTES: Final = 256 * 1024
_MAX_RULES: Final = 512
_MAX_DESTINATIONS_PER_RULE: Final = 256
_MAX_GRANT_TTL_SECONDS: Final = 300
_RULE_ID_RE: Final = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
_KEY_ID_RE: Final = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$")


class NetworkAuthorityReason(str, Enum):
    INVALID_JSON = "network-authority-invalid-json"
    INVALID_SCHEMA = "network-authority-invalid-schema"
    UNKNOWN_FIELD = "network-authority-unknown-field"
    INVALID_VALUE = "network-authority-invalid-value"
    POLICY_TOO_LARGE = "network-authority-policy-too-large"
    TOO_MANY_RULES = "network-authority-too-many-rules"
    TOO_MANY_DESTINATIONS = "network-authority-too-many-destinations"
    GENERATION_ROLLBACK = "network-authority-generation-rollback"
    GENERATION_CHAIN_MISMATCH = "network-authority-generation-chain-mismatch"
    MANAGED_FLOOR_WEAKENED = "network-authority-managed-floor-weakened"
    SIGNATURE_INVALID = "network-authority-signature-invalid"
    SIGNING_KEY_INVALID = "network-authority-signing-key-invalid"
    GRANT_EXPIRED = "network-authority-grant-expired"
    GRANT_PROCESS_MISMATCH = "network-authority-grant-process-mismatch"
    GRANT_POLICY_MISMATCH = "network-authority-grant-policy-mismatch"
    GRANT_REPLAY = "network-authority-grant-replay"
    STATE_UNSAFE = "network-authority-state-unsafe"


class NetworkAuthorityError(ValueError):
    """Fail-closed network authority error with a stable public reason code."""

    def __init__(self, reason: NetworkAuthorityReason, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason


class NetworkRuleAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class NetworkProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    DNS = "dns"


class NetworkPolicyLayer(str, Enum):
    BUILT_IN = "built-in"
    ORGANIZATION = "organization"
    DEVICE = "device"
    WORKSPACE = "workspace"
    GRANT = "grant"


_LAYER_ORDER: Final = {
    NetworkPolicyLayer.BUILT_IN: 0,
    NetworkPolicyLayer.ORGANIZATION: 1,
    NetworkPolicyLayer.DEVICE: 2,
    NetworkPolicyLayer.WORKSPACE: 3,
    NetworkPolicyLayer.GRANT: 4,
}


@dataclass(frozen=True, slots=True, order=True)
class PortRange:
    start: int
    end: int

    def __post_init__(self) -> None:
        if not 1 <= self.start <= self.end <= 65535:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.INVALID_VALUE,
                "network port ranges must remain within 1..65535",
            )

    def to_json(self) -> int | str:
        if self.start == self.end:
            return self.start
        return f"{self.start}-{self.end}"

    def contains(self, port: int) -> bool:
        return self.start <= port <= self.end


@dataclass(frozen=True, slots=True)
class NetworkRule:
    rule_id: str
    layer: NetworkPolicyLayer
    action: NetworkRuleAction
    protocols: tuple[NetworkProtocol, ...]
    domains: tuple[str, ...]
    cidrs: tuple[str, ...]
    ports: tuple[PortRange, ...]
    reason_code: str

    def to_json(self) -> dict[str, object]:
        return {
            "id": self.rule_id,
            "layer": self.layer.value,
            "action": self.action.value,
            "protocols": [protocol.value for protocol in self.protocols],
            "domains": list(self.domains),
            "cidrs": list(self.cidrs),
            "ports": [port.to_json() for port in self.ports],
            "reason_code": self.reason_code,
        }

    def matches(self, *, protocol: NetworkProtocol, host: str, port: int) -> bool:
        if protocol not in self.protocols:
            return False
        if self.ports and not any(candidate.contains(port) for candidate in self.ports):
            return False
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            normalized_host = _normalize_domain(host, allow_wildcard=False)
            return any(_domain_matches(pattern, normalized_host) for pattern in self.domains)
        return any(address in ipaddress.ip_network(cidr, strict=True) for cidr in self.cidrs)


@dataclass(frozen=True, slots=True)
class CompiledNetworkPolicy:
    generation: int
    previous_generation_digest: str | None
    emergency_deny: bool
    rules: tuple[NetworkRule, ...]
    policy_digest: str
    authority_digest: str
    canonical_bytes: bytes

    def to_json(self) -> dict[str, object]:
        return cast(dict[str, object], json.loads(self.canonical_bytes))

    def decide(self, *, protocol: NetworkProtocol, host: str, port: int) -> NetworkRuleAction:
        """Evaluate the deterministic restrictive-layer policy for one flow."""

        if self.emergency_deny:
            return NetworkRuleAction.DENY
        matching = [rule for rule in self.rules if rule.matches(protocol=protocol, host=host, port=port)]
        if any(rule.action is NetworkRuleAction.DENY for rule in matching):
            return NetworkRuleAction.DENY

        layers_with_allows = {
            rule.layer for rule in self.rules if rule.action is NetworkRuleAction.ALLOW
        }
        matching_allow_layers = {
            rule.layer for rule in matching if rule.action is NetworkRuleAction.ALLOW
        }
        if layers_with_allows and layers_with_allows <= matching_allow_layers:
            return NetworkRuleAction.ALLOW
        return NetworkRuleAction.DENY


@dataclass(frozen=True, slots=True)
class SignedNetworkGeneration:
    key_id: str
    payload: bytes
    signature: bytes

    def to_json(self) -> dict[str, object]:
        return {
            "schema": _NETWORK_GENERATION_SCHEMA,
            "key_id": self.key_id,
            "payload": _b64url_encode(self.payload),
            "signature": _b64url_encode(self.signature),
        }

    @classmethod
    def from_json(cls, raw: bytes | str | Mapping[str, object]) -> SignedNetworkGeneration:
        parsed = _parse_object(raw)
        _require_exact_fields(parsed, {"schema", "key_id", "payload", "signature"})
        if parsed.get("schema") != _NETWORK_GENERATION_SCHEMA:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.INVALID_SCHEMA,
                "network generation schema is unsupported",
            )
        key_id = _require_key_id(parsed.get("key_id"))
        payload = _b64url_decode(parsed.get("payload"), field="payload")
        signature = _b64url_decode(parsed.get("signature"), field="signature")
        return cls(key_id=key_id, payload=payload, signature=signature)


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    pid: int
    start_token: str
    executable_digest: str

    def __post_init__(self) -> None:
        if self.pid <= 0:
            raise NetworkAuthorityError(NetworkAuthorityReason.INVALID_VALUE, "process pid must be positive")
        _require_digest(self.start_token, field="process start token")
        _require_digest(self.executable_digest, field="executable digest")

    def to_json(self) -> dict[str, object]:
        return {
            "pid": self.pid,
            "start_token": self.start_token,
            "executable_digest": self.executable_digest,
        }


@dataclass(frozen=True, slots=True)
class NetworkApprovalGrant:
    key_id: str
    payload: bytes
    signature: bytes

    def to_json(self) -> dict[str, object]:
        return {
            "schema": _NETWORK_GRANT_SCHEMA,
            "key_id": self.key_id,
            "payload": _b64url_encode(self.payload),
            "signature": _b64url_encode(self.signature),
        }

    @classmethod
    def from_json(cls, raw: bytes | str | Mapping[str, object]) -> NetworkApprovalGrant:
        parsed = _parse_object(raw)
        _require_exact_fields(parsed, {"schema", "key_id", "payload", "signature"})
        if parsed.get("schema") != _NETWORK_GRANT_SCHEMA:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.INVALID_SCHEMA,
                "network approval grant schema is unsupported",
            )
        return cls(
            key_id=_require_key_id(parsed.get("key_id")),
            payload=_b64url_decode(parsed.get("payload"), field="payload"),
            signature=_b64url_decode(parsed.get("signature"), field="signature"),
        )


@dataclass(frozen=True, slots=True)
class VerifiedNetworkGrant:
    grant_id: str
    lease_id: str
    policy_digest: str
    approval_digest: str
    process: ProcessIdentity
    issued_at_epoch_s: int
    expires_at_epoch_s: int
    rule_ids: tuple[str, ...]
    nonce_digest: str


class Ed25519NetworkSigner:
    """Small Ed25519 boundary used for generations and approval grants."""

    def __init__(self, *, key_id: str, private_key: bytes) -> None:
        self.key_id = _require_key_id(key_id)
        if len(private_key) != 32:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.SIGNING_KEY_INVALID,
                "Ed25519 private keys must contain exactly 32 seed bytes",
            )
        self._private_key = bytes(private_key)

    @classmethod
    def generate(cls, *, key_id: str) -> Ed25519NetworkSigner:
        return cls(key_id=key_id, private_key=secrets.token_bytes(32))

    def public_key_bytes(self) -> bytes:
        private_key = _ed25519_private_key(self._private_key)
        serialization = _cryptography_serialization()
        return cast(
            bytes,
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
        )

    def sign_generation(self, policy: CompiledNetworkPolicy) -> SignedNetworkGeneration:
        payload = canonical_json_bytes(
            {
                "schema": _NETWORK_GENERATION_SCHEMA,
                "generation": policy.generation,
                "previous_generation_digest": policy.previous_generation_digest,
                "policy_digest": policy.policy_digest,
                "authority_digest": policy.authority_digest,
                "policy": policy.to_json(),
            }
        )
        signature = cast(bytes, _ed25519_private_key(self._private_key).sign(payload))
        return SignedNetworkGeneration(key_id=self.key_id, payload=payload, signature=signature)

    def issue_grant(
        self,
        *,
        lease_id: str,
        policy_digest: str,
        approval_digest: str,
        process: ProcessIdentity,
        rule_ids: Iterable[str],
        now_epoch_s: int | None = None,
        ttl_seconds: int = 60,
    ) -> NetworkApprovalGrant:
        now = int(time.time()) if now_epoch_s is None else now_epoch_s
        if not 1 <= ttl_seconds <= _MAX_GRANT_TTL_SECONDS:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.INVALID_VALUE,
                "network grant TTL exceeds the bounded approval window",
            )
        normalized_rules = tuple(sorted({_require_rule_id(rule_id) for rule_id in rule_ids}))
        if not normalized_rules:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.INVALID_VALUE,
                "network grants require at least one approved rule",
            )
        _require_identifier(lease_id, field="lease_id")
        _require_digest(policy_digest, field="policy_digest")
        _require_digest(approval_digest, field="approval_digest")
        nonce = secrets.token_bytes(32)
        payload = canonical_json_bytes(
            {
                "schema": _NETWORK_GRANT_SCHEMA,
                "grant_id": hashlib.sha256(nonce + lease_id.encode("utf-8")).hexdigest(),
                "lease_id": lease_id,
                "policy_digest": policy_digest,
                "approval_digest": approval_digest,
                "process": process.to_json(),
                "issued_at_epoch_s": now,
                "expires_at_epoch_s": now + ttl_seconds,
                "rule_ids": list(normalized_rules),
                "nonce": _b64url_encode(nonce),
            }
        )
        signature = cast(bytes, _ed25519_private_key(self._private_key).sign(payload))
        return NetworkApprovalGrant(key_id=self.key_id, payload=payload, signature=signature)


def canonical_json_bytes(value: object) -> bytes:
    """Serialize one bounded JSON value in the canonical Guard representation."""

    _validate_json_value(value, depth=0)
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > _MAX_POLICY_BYTES:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.POLICY_TOO_LARGE,
            "network authority payload exceeds the configured byte ceiling",
        )
    return encoded


def compile_network_policy(
    raw: bytes | str | Mapping[str, object],
    *,
    generation: int,
    previous: CompiledNetworkPolicy | None = None,
    managed_floor: CompiledNetworkPolicy | None = None,
) -> CompiledNetworkPolicy:
    """Compile a strict GuardPolicy network extension into deterministic bytes."""

    if generation <= 0:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network policy generation must be positive",
        )
    if previous is not None and generation <= previous.generation:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.GENERATION_ROLLBACK,
            "network policy generation must advance monotonically",
        )

    parsed = _parse_object(raw)
    _require_exact_fields(parsed, {"schema", "emergency_deny", "layers"})
    if parsed.get("schema") != _NETWORK_POLICY_SCHEMA:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_SCHEMA,
            "network policy schema is unsupported",
        )
    emergency_deny = _require_bool(parsed.get("emergency_deny"), field="emergency_deny")
    layers = _require_list(parsed.get("layers"), field="layers")

    seen_layers: set[NetworkPolicyLayer] = set()
    rules: list[NetworkRule] = []
    for raw_layer in layers:
        layer_object = _require_mapping(raw_layer, field="layer")
        _require_exact_fields(layer_object, {"layer", "rules"})
        layer = _require_enum(NetworkPolicyLayer, layer_object.get("layer"), field="layer")
        if layer in seen_layers:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.INVALID_VALUE,
                "network policy layers must be unique",
            )
        seen_layers.add(layer)
        raw_rules = _require_list(layer_object.get("rules"), field="rules")
        for raw_rule in raw_rules:
            rules.append(_compile_rule(raw_rule, layer=layer))
            if len(rules) > _MAX_RULES:
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.TOO_MANY_RULES,
                    "network policy exceeds the rule ceiling",
                )

    if NetworkPolicyLayer.GRANT in seen_layers:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "durable policy documents cannot contain transient grant-layer rules",
        )
    if len({rule.rule_id for rule in rules}) != len(rules):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network rule IDs must be unique across every authority layer",
        )

    ordered_rules = tuple(
        sorted(
            rules,
            key=lambda rule: (
                _LAYER_ORDER[rule.layer],
                rule.rule_id,
                rule.action.value,
                tuple(protocol.value for protocol in rule.protocols),
                rule.domains,
                rule.cidrs,
                rule.ports,
            ),
        )
    )
    previous_digest = previous.policy_digest if previous is not None else None
    canonical_without_digest = {
        "schema": _NETWORK_POLICY_SCHEMA,
        "generation": generation,
        "previous_generation_digest": previous_digest,
        "emergency_deny": emergency_deny,
        "default_action": NetworkRuleAction.DENY.value,
        "rules": [rule.to_json() for rule in ordered_rules],
    }
    policy_digest = hashlib.sha256(canonical_json_bytes(canonical_without_digest)).hexdigest()
    authority_digest = _authority_digest(ordered_rules, emergency_deny=emergency_deny)
    canonical = canonical_json_bytes(
        {
            **canonical_without_digest,
            "policy_digest": policy_digest,
            "authority_digest": authority_digest,
        }
    )
    compiled = CompiledNetworkPolicy(
        generation=generation,
        previous_generation_digest=previous_digest,
        emergency_deny=emergency_deny,
        rules=ordered_rules,
        policy_digest=policy_digest,
        authority_digest=authority_digest,
        canonical_bytes=canonical,
    )
    if managed_floor is not None:
        _assert_managed_floor(compiled, managed_floor)
    return compiled


def verify_signed_generation(
    envelope: SignedNetworkGeneration | bytes | str | Mapping[str, object],
    *,
    trusted_keys: Mapping[str, bytes],
    minimum_generation: int = 0,
    expected_previous_digest: str | None = None,
) -> CompiledNetworkPolicy:
    """Verify signature, canonical policy bytes, monotonicity, and chain binding."""

    signed = envelope if isinstance(envelope, SignedNetworkGeneration) else SignedNetworkGeneration.from_json(envelope)
    public_key_bytes = trusted_keys.get(signed.key_id)
    if public_key_bytes is None or len(public_key_bytes) != 32:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNING_KEY_INVALID,
            "network generation signing key is not trusted",
        )
    try:
        _ed25519_public_key(public_key_bytes).verify(signed.signature, signed.payload)
    except Exception as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNATURE_INVALID,
            "network generation signature is invalid",
        ) from exc

    payload = _parse_object(signed.payload)
    _require_exact_fields(
        payload,
        {
            "schema",
            "generation",
            "previous_generation_digest",
            "policy_digest",
            "authority_digest",
            "policy",
        },
    )
    if payload.get("schema") != _NETWORK_GENERATION_SCHEMA:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_SCHEMA,
            "signed network generation schema is unsupported",
        )
    generation = _require_int(payload.get("generation"), field="generation", minimum=1)
    if generation <= minimum_generation:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.GENERATION_ROLLBACK,
            "signed network generation does not advance the installed generation",
        )
    previous_digest = _optional_digest(payload.get("previous_generation_digest"), field="previous_generation_digest")
    if expected_previous_digest is not None and not hmac.compare_digest(
        previous_digest or "", expected_previous_digest
    ):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.GENERATION_CHAIN_MISMATCH,
            "signed network generation does not extend the installed chain",
        )

    policy_object = _require_mapping(payload.get("policy"), field="policy")
    _require_exact_fields(
        policy_object,
        {
            "schema",
            "generation",
            "previous_generation_digest",
            "emergency_deny",
            "default_action",
            "rules",
            "policy_digest",
            "authority_digest",
        },
    )
    compiled = _compiled_from_canonical_policy(policy_object)
    declared_policy_digest = _require_digest(payload.get("policy_digest"), field="policy_digest")
    declared_authority_digest = _require_digest(payload.get("authority_digest"), field="authority_digest")
    if not hmac.compare_digest(compiled.policy_digest, declared_policy_digest):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNATURE_INVALID,
            "signed generation policy digest does not match its canonical policy",
        )
    if not hmac.compare_digest(compiled.authority_digest, declared_authority_digest):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNATURE_INVALID,
            "signed generation authority digest does not match its canonical policy",
        )
    if compiled.generation != generation or compiled.previous_generation_digest != previous_digest:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.GENERATION_CHAIN_MISMATCH,
            "signed generation metadata disagrees with its canonical policy",
        )
    return compiled


def verify_process_grant(
    grant: NetworkApprovalGrant | bytes | str | Mapping[str, object],
    *,
    trusted_keys: Mapping[str, bytes],
    expected_process: ProcessIdentity,
    expected_lease_id: str,
    expected_policy_digest: str,
    replay_ledger: GrantReplayLedger,
    now_epoch_s: int | None = None,
) -> VerifiedNetworkGrant:
    """Verify and consume one process-bound approval grant exactly once."""

    signed = grant if isinstance(grant, NetworkApprovalGrant) else NetworkApprovalGrant.from_json(grant)
    public_key_bytes = trusted_keys.get(signed.key_id)
    if public_key_bytes is None or len(public_key_bytes) != 32:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNING_KEY_INVALID,
            "network grant signing key is not trusted",
        )
    try:
        _ed25519_public_key(public_key_bytes).verify(signed.signature, signed.payload)
    except Exception as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNATURE_INVALID,
            "network approval grant signature is invalid",
        ) from exc

    payload = _parse_object(signed.payload)
    _require_exact_fields(
        payload,
        {
            "schema",
            "grant_id",
            "lease_id",
            "policy_digest",
            "approval_digest",
            "process",
            "issued_at_epoch_s",
            "expires_at_epoch_s",
            "rule_ids",
            "nonce",
        },
    )
    if payload.get("schema") != _NETWORK_GRANT_SCHEMA:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_SCHEMA,
            "network grant payload schema is unsupported",
        )
    grant_id = _require_digest(payload.get("grant_id"), field="grant_id")
    lease_id = _require_identifier(payload.get("lease_id"), field="lease_id")
    policy_digest = _require_digest(payload.get("policy_digest"), field="policy_digest")
    approval_digest = _require_digest(payload.get("approval_digest"), field="approval_digest")
    process_object = _require_mapping(payload.get("process"), field="process")
    _require_exact_fields(process_object, {"pid", "start_token", "executable_digest"})
    process = ProcessIdentity(
        pid=_require_int(process_object.get("pid"), field="pid", minimum=1),
        start_token=_require_digest(process_object.get("start_token"), field="start_token"),
        executable_digest=_require_digest(
            process_object.get("executable_digest"), field="executable_digest"
        ),
    )
    issued_at = _require_int(payload.get("issued_at_epoch_s"), field="issued_at_epoch_s", minimum=0)
    expires_at = _require_int(payload.get("expires_at_epoch_s"), field="expires_at_epoch_s", minimum=1)
    now = int(time.time()) if now_epoch_s is None else now_epoch_s
    if expires_at <= now or expires_at - issued_at > _MAX_GRANT_TTL_SECONDS or issued_at > now + 30:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.GRANT_EXPIRED,
            "network approval grant is outside its bounded validity window",
        )
    if process != expected_process:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.GRANT_PROCESS_MISMATCH,
            "network approval grant does not match the current process identity",
        )
    if not hmac.compare_digest(lease_id, expected_lease_id):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.GRANT_PROCESS_MISMATCH,
            "network approval grant does not match the requested lease",
        )
    if not hmac.compare_digest(policy_digest, expected_policy_digest):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.GRANT_POLICY_MISMATCH,
            "network approval grant does not match the active policy generation",
        )
    raw_rule_ids = _require_list(payload.get("rule_ids"), field="rule_ids")
    rule_ids = tuple(_require_rule_id(item) for item in raw_rule_ids)
    if not rule_ids or tuple(sorted(set(rule_ids))) != rule_ids:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network approval grant rule IDs must be unique and sorted",
        )
    nonce = _b64url_decode(payload.get("nonce"), field="nonce")
    if len(nonce) != 32:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network approval grant nonce has an invalid size",
        )
    nonce_digest = hashlib.sha256(nonce).hexdigest()
    replay_ledger.consume(nonce_digest=nonce_digest, expires_at_epoch_s=expires_at, now_epoch_s=now)
    return VerifiedNetworkGrant(
        grant_id=grant_id,
        lease_id=lease_id,
        policy_digest=policy_digest,
        approval_digest=approval_digest,
        process=process,
        issued_at_epoch_s=issued_at,
        expires_at_epoch_s=expires_at,
        rule_ids=rule_ids,
        nonce_digest=nonce_digest,
    )


class GrantReplayLedger:
    """Crash-safe local ledger preventing approval-grant replay."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def consume(self, *, nonce_digest: str, expires_at_epoch_s: int, now_epoch_s: int) -> None:
        _require_digest(nonce_digest, field="nonce_digest")
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _assert_private_directory(self.path.parent)
        entries = self._read()
        live_entries = {
            digest: expiry for digest, expiry in entries.items() if expiry > now_epoch_s
        }
        if nonce_digest in live_entries:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.GRANT_REPLAY,
                "network approval grant has already been consumed",
            )
        live_entries[nonce_digest] = expires_at_epoch_s
        _atomic_private_json_write(self.path, live_entries)

    def _read(self) -> dict[str, int]:
        if not self.path.exists():
            return {}
        _assert_private_regular_file(self.path)
        try:
            parsed = _parse_object(self.path.read_bytes())
        except OSError as exc:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.STATE_UNSAFE,
                "network grant replay state could not be read",
            ) from exc
        result: dict[str, int] = {}
        for raw_digest, raw_expiry in parsed.items():
            digest = _require_digest(raw_digest, field="nonce_digest")
            result[digest] = _require_int(raw_expiry, field="expires_at_epoch_s", minimum=0)
        return result


def _compile_rule(raw: object, *, layer: NetworkPolicyLayer) -> NetworkRule:
    rule = _require_mapping(raw, field="rule")
    _require_exact_fields(
        rule,
        {"id", "action", "protocols", "domains", "cidrs", "ports", "reason_code"},
    )
    rule_id = _require_rule_id(rule.get("id"))
    action = _require_enum(NetworkRuleAction, rule.get("action"), field="action")
    protocols = tuple(
        sorted(
            {
                _require_enum(NetworkProtocol, value, field="protocol")
                for value in _require_list(rule.get("protocols"), field="protocols")
            },
            key=lambda value: value.value,
        )
    )
    if not protocols:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network rules require at least one protocol",
        )
    domains = tuple(
        sorted(
            {
                _normalize_domain(value, allow_wildcard=True)
                for value in _require_list(rule.get("domains"), field="domains")
            }
        )
    )
    cidrs = tuple(
        sorted(
            {
                _normalize_cidr(value)
                for value in _require_list(rule.get("cidrs"), field="cidrs")
            }
        )
    )
    ports = tuple(
        sorted(
            {
                _normalize_port(value)
                for value in _require_list(rule.get("ports"), field="ports")
            }
        )
    )
    destination_count = len(domains) + len(cidrs) + len(ports)
    if destination_count == 0:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network rules require a destination or port constraint",
        )
    if destination_count > _MAX_DESTINATIONS_PER_RULE:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.TOO_MANY_DESTINATIONS,
            "network rule exceeds the destination ceiling",
        )
    if NetworkProtocol.DNS in protocols and ports and ports != (PortRange(53, 53),):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "DNS rules may constrain only port 53",
        )
    reason_code = _require_identifier(rule.get("reason_code"), field="reason_code")
    return NetworkRule(
        rule_id=rule_id,
        layer=layer,
        action=action,
        protocols=protocols,
        domains=domains,
        cidrs=cidrs,
        ports=ports,
        reason_code=reason_code,
    )


def _compiled_from_canonical_policy(policy: Mapping[str, object]) -> CompiledNetworkPolicy:
    generation = _require_int(policy.get("generation"), field="generation", minimum=1)
    previous_digest = _optional_digest(
        policy.get("previous_generation_digest"), field="previous_generation_digest"
    )
    emergency_deny = _require_bool(policy.get("emergency_deny"), field="emergency_deny")
    if policy.get("schema") != _NETWORK_POLICY_SCHEMA or policy.get("default_action") != "deny":
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_SCHEMA,
            "canonical network policy has an unsupported schema or default action",
        )
    raw_rules = _require_list(policy.get("rules"), field="rules")
    rules: list[NetworkRule] = []
    for raw_rule in raw_rules:
        rule_object = _require_mapping(raw_rule, field="rule")
        layer = _require_enum(NetworkPolicyLayer, rule_object.get("layer"), field="layer")
        rules.append(_compile_rule(rule_object, layer=layer))
    ordered_rules = tuple(rules)
    canonical_without_digest = {
        "schema": _NETWORK_POLICY_SCHEMA,
        "generation": generation,
        "previous_generation_digest": previous_digest,
        "emergency_deny": emergency_deny,
        "default_action": "deny",
        "rules": [rule.to_json() for rule in ordered_rules],
    }
    policy_digest = hashlib.sha256(canonical_json_bytes(canonical_without_digest)).hexdigest()
    authority_digest = _authority_digest(ordered_rules, emergency_deny=emergency_deny)
    declared_policy_digest = _require_digest(policy.get("policy_digest"), field="policy_digest")
    declared_authority_digest = _require_digest(
        policy.get("authority_digest"), field="authority_digest"
    )
    if not hmac.compare_digest(policy_digest, declared_policy_digest):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNATURE_INVALID,
            "canonical network policy digest is invalid",
        )
    if not hmac.compare_digest(authority_digest, declared_authority_digest):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNATURE_INVALID,
            "canonical network authority digest is invalid",
        )
    canonical = canonical_json_bytes(
        {
            **canonical_without_digest,
            "policy_digest": policy_digest,
            "authority_digest": authority_digest,
        }
    )
    if canonical != canonical_json_bytes(policy):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNATURE_INVALID,
            "network policy payload is not canonical",
        )
    return CompiledNetworkPolicy(
        generation=generation,
        previous_generation_digest=previous_digest,
        emergency_deny=emergency_deny,
        rules=ordered_rules,
        policy_digest=policy_digest,
        authority_digest=authority_digest,
        canonical_bytes=canonical,
    )


def _assert_managed_floor(candidate: CompiledNetworkPolicy, floor: CompiledNetworkPolicy) -> None:
    floor_denies = {
        canonical_json_bytes(rule.to_json())
        for rule in floor.rules
        if rule.layer in {NetworkPolicyLayer.BUILT_IN, NetworkPolicyLayer.ORGANIZATION}
        and rule.action is NetworkRuleAction.DENY
    }
    candidate_denies = {
        canonical_json_bytes(rule.to_json())
        for rule in candidate.rules
        if rule.layer in {NetworkPolicyLayer.BUILT_IN, NetworkPolicyLayer.ORGANIZATION}
        and rule.action is NetworkRuleAction.DENY
    }
    if not floor_denies <= candidate_denies:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.MANAGED_FLOOR_WEAKENED,
            "network policy removes a built-in or organization-managed deny rule",
        )
    if floor.emergency_deny and not candidate.emergency_deny:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.MANAGED_FLOOR_WEAKENED,
            "network policy attempts to clear an organization emergency deny",
        )


def _authority_digest(rules: Sequence[NetworkRule], *, emergency_deny: bool) -> str:
    authority = {
        "emergency_deny": emergency_deny,
        "managed_denies": [
            rule.to_json()
            for rule in rules
            if rule.layer in {NetworkPolicyLayer.BUILT_IN, NetworkPolicyLayer.ORGANIZATION}
            and rule.action is NetworkRuleAction.DENY
        ],
    }
    return hashlib.sha256(canonical_json_bytes(authority)).hexdigest()


def _parse_object(raw: bytes | str | Mapping[str, object]) -> dict[str, object]:
    if isinstance(raw, Mapping):
        return dict(raw)
    if isinstance(raw, bytes):
        if len(raw) > _MAX_POLICY_BYTES:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.POLICY_TOO_LARGE,
                "network authority payload exceeds the configured byte ceiling",
            )
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.INVALID_JSON,
                "network authority payload must be UTF-8 JSON",
            ) from exc
    elif isinstance(raw, str):
        text = raw
        if len(text.encode("utf-8")) > _MAX_POLICY_BYTES:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.POLICY_TOO_LARGE,
                "network authority payload exceeds the configured byte ceiling",
            )
    else:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_JSON,
            "network authority payload must be a JSON object",
        )

    def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.INVALID_JSON,
                    "network authority JSON contains a duplicate object key",
                )
            result[key] = value
        return result

    try:
        parsed = json.loads(text, object_pairs_hook=reject_duplicate_pairs)
    except NetworkAuthorityError:
        raise
    except (TypeError, ValueError) as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_JSON,
            "network authority payload is not valid JSON",
        ) from exc
    if not isinstance(parsed, dict):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_JSON,
            "network authority payload must be a JSON object",
        )
    return cast(dict[str, object], parsed)


def _validate_json_value(value: object, *, depth: int) -> None:
    if depth > 32:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network authority JSON exceeds the depth ceiling",
        )
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network authority JSON cannot contain floating-point values",
        )
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise NetworkAuthorityError(
                    NetworkAuthorityReason.INVALID_VALUE,
                    "network authority JSON object keys must be strings",
                )
            _validate_json_value(child, depth=depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for child in value:
            _validate_json_value(child, depth=depth + 1)
        return
    raise NetworkAuthorityError(
        NetworkAuthorityReason.INVALID_VALUE,
        "network authority JSON contains an unsupported value type",
    )


def _require_exact_fields(value: Mapping[str, object], expected: set[str]) -> None:
    actual = set(value)
    if actual != expected:
        unknown = sorted(actual - expected)
        missing = sorted(expected - actual)
        detail = "network authority object fields do not match the schema"
        if unknown:
            detail = f"{detail}; unknown={','.join(unknown)}"
        if missing:
            detail = f"{detail}; missing={','.join(missing)}"
        raise NetworkAuthorityError(NetworkAuthorityReason.UNKNOWN_FIELD, detail)


def _require_mapping(value: object, *, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"{field} must be an object",
        )
    return cast(Mapping[str, object], value)


def _require_list(value: object, *, field: str) -> list[object]:
    if not isinstance(value, list):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"{field} must be a list",
        )
    return cast(list[object], value)


def _require_bool(value: object, *, field: str) -> bool:
    if type(value) is not bool:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"{field} must be a boolean",
        )
    return cast(bool, value)


def _require_int(value: object, *, field: str, minimum: int) -> int:
    if type(value) is not int or cast(int, value) < minimum:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"{field} must be an integer greater than or equal to {minimum}",
        )
    return cast(int, value)


def _require_enum[T: Enum](enum_type: type[T], value: object, *, field: str) -> T:
    if not isinstance(value, str):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"{field} must be a string",
        )
    try:
        return enum_type(value)
    except ValueError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"{field} has an unsupported value",
        ) from exc


def _require_rule_id(value: object) -> str:
    if not isinstance(value, str) or _RULE_ID_RE.fullmatch(value) is None:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network rule IDs must use lowercase stable identifier syntax",
        )
    return value


def _require_key_id(value: object) -> str:
    if not isinstance(value, str) or _KEY_ID_RE.fullmatch(value) is None:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNING_KEY_INVALID,
            "network signing key ID has invalid syntax",
        )
    return value


def _require_identifier(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _KEY_ID_RE.fullmatch(value) is None:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"{field} has invalid identifier syntax",
        )
    return value


def _require_digest(value: object, *, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"{field} must be a lowercase SHA-256 digest",
        )
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"{field} must be a lowercase SHA-256 digest",
        ) from exc
    if decoded.hex() != value:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"{field} must be a lowercase SHA-256 digest",
        )
    return value


def _optional_digest(value: object, *, field: str) -> str | None:
    if value is None:
        return None
    return _require_digest(value, field=field)


def _normalize_domain(value: object, *, allow_wildcard: bool) -> str:
    if not isinstance(value, str) or not value or len(value) > 253:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network domains must be non-empty bounded strings",
        )
    candidate = value.rstrip(".").lower()
    wildcard = candidate.startswith("*.")
    if wildcard:
        if not allow_wildcard:
            raise NetworkAuthorityError(
                NetworkAuthorityReason.INVALID_VALUE,
                "wildcard domains are not valid flow destinations",
            )
        candidate = candidate[2:]
    if any(marker in candidate for marker in ("://", "/", "@", "?", "#", "\x00")):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network domain contains URL or control syntax",
        )
    try:
        ascii_domain = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network domain cannot be normalized with IDNA",
        ) from exc
    labels = ascii_domain.split(".")
    if len(labels) < 2 or any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or re.fullmatch(r"[a-z0-9-]+", label) is None
        for label in labels
    ):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network domain has invalid DNS label syntax",
        )
    return f"*.{ascii_domain}" if wildcard else ascii_domain


def _domain_matches(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and host != pattern[2:]
    return hmac.compare_digest(pattern, host)


def _normalize_cidr(value: object) -> str:
    if not isinstance(value, str):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network CIDRs must be strings",
        )
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network CIDR must use a canonical network address",
        ) from exc
    return network.compressed


def _normalize_port(value: object) -> PortRange:
    if type(value) is int:
        return PortRange(cast(int, value), cast(int, value))
    if not isinstance(value, str) or re.fullmatch(r"[0-9]{1,5}-[0-9]{1,5}", value) is None:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            "network ports must be integers or canonical start-end ranges",
        )
    start_text, end_text = value.split("-", maxsplit=1)
    return PortRange(int(start_text), int(end_text))


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: object, *, field: str) -> bytes:
    if not isinstance(value, str) or not value or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"{field} must be unpadded base64url",
        )
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.INVALID_VALUE,
            f"{field} must be unpadded base64url",
        ) from exc


def _ed25519_private_key(seed: bytes) -> object:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNING_KEY_INVALID,
            "Ed25519 support is unavailable",
        ) from exc
    return Ed25519PrivateKey.from_private_bytes(seed)


def _ed25519_public_key(raw: bytes) -> object:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNING_KEY_INVALID,
            "Ed25519 support is unavailable",
        ) from exc
    return Ed25519PublicKey.from_public_bytes(raw)


def _cryptography_serialization() -> object:
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.SIGNING_KEY_INVALID,
            "Ed25519 serialization support is unavailable",
        ) from exc
    return serialization


def _assert_private_directory(path: Path) -> None:
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network authority state directory cannot be inspected",
        ) from exc
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network authority state directory must be private and owner-controlled",
        )


def _assert_private_regular_file(path: Path) -> None:
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network authority state file cannot be inspected",
        ) from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
        or path.is_symlink()
    ):
        raise NetworkAuthorityError(
            NetworkAuthorityReason.STATE_UNSAFE,
            "network authority state file must be private, regular, and owner-controlled",
        )


def _atomic_private_json_write(path: Path, value: Mapping[str, int]) -> None:
    encoded = canonical_json_bytes(value)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


__all__: Sequence[str] = (
    "CompiledNetworkPolicy",
    "Ed25519NetworkSigner",
    "GrantReplayLedger",
    "NetworkApprovalGrant",
    "NetworkAuthorityError",
    "NetworkAuthorityReason",
    "NetworkPolicyLayer",
    "NetworkProtocol",
    "NetworkRule",
    "NetworkRuleAction",
    "PortRange",
    "ProcessIdentity",
    "SignedNetworkGeneration",
    "VerifiedNetworkGrant",
    "canonical_json_bytes",
    "compile_network_policy",
    "verify_process_grant",
    "verify_signed_generation",
)
