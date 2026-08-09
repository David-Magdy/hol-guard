"""Privacy-safe receipts for locally verified Guard outcomes.

These receipts intentionally carry only outcome metadata and a SHA-256 evidence
digest. They never serialize prompts, source code, findings, file paths, commands,
secrets, tokens, usernames, hostnames, or report bodies.

A receipt is *operational evidence*, not a self-authenticating remote attestation:
- ``local_install_verified`` is valid only when tied to a server-issued handoff
  whose installer flow reached binary verification (or product corroboration).
- ``first_local_proof_generated`` records a digest of an already-produced local
  proof and its proof kind. The proof itself remains local unless the user
  explicitly shares it through another product flow.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Literal

SCHEMA_VERSION = "1"
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

Outcome = Literal["local_install_verified", "first_local_proof_generated"]
Verification = Literal[
    "binary_verified_handoff",
    "product_corroborated_handoff",
    "privacy_safe_local_receipt",
]

_FORBIDDEN_KEYS = frozenset(
    {
        "prompt",
        "raw_prompt",
        "path",
        "file",
        "filename",
        "command",
        "secret",
        "token",
        "finding",
        "source_code",
        "hostname",
        "username",
        "report_body",
    }
)


@dataclass(frozen=True, slots=True)
class GuardOutcomeReceipt:
    schema_version: Literal["1"]
    outcome: Outcome
    occurred_at: str
    hol_guard_version: str
    verification: Verification
    evidence_digest: str
    handoff_id: str | None
    proof_kind: str | None
    sensitive_content_included: Literal[False] = False

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def sha256_digest(data: bytes) -> str:
    """Hash local evidence without returning or retaining the evidence bytes."""
    return hashlib.sha256(data).hexdigest()


def _iso_utc(value: datetime | None) -> str:
    current = value or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("occurred_at must be timezone-aware")
    return current.astimezone(UTC).isoformat().replace("+00:00", "Z")


def build_outcome_receipt(
    *,
    outcome: Outcome,
    hol_guard_version: str,
    verification: Verification,
    evidence_digest: str,
    handoff_id: str | None = None,
    proof_kind: str | None = None,
    occurred_at: datetime | None = None,
) -> GuardOutcomeReceipt:
    """Build a versioned receipt after an authoritative local outcome occurs."""
    if not hol_guard_version or len(hol_guard_version) > 64:
        raise ValueError("hol_guard_version must be 1..64 characters")
    if not _SHA256_RE.fullmatch(evidence_digest):
        raise ValueError("evidence_digest must be a lowercase SHA-256 digest")
    if handoff_id is not None and not (1 <= len(handoff_id) <= 128):
        raise ValueError("handoff_id must be 1..128 characters when present")
    if proof_kind is not None and not (1 <= len(proof_kind) <= 64):
        raise ValueError("proof_kind must be 1..64 characters when present")

    if outcome == "local_install_verified":
        if verification not in {"binary_verified_handoff", "product_corroborated_handoff"}:
            raise ValueError("local install requires verified handoff evidence")
        if not handoff_id:
            raise ValueError("local install verification requires handoff_id")
        if proof_kind is not None:
            raise ValueError("local install receipt must not include proof_kind")
    elif outcome == "first_local_proof_generated":
        if verification != "privacy_safe_local_receipt":
            raise ValueError("first local proof requires privacy_safe_local_receipt verification")
        if not proof_kind:
            raise ValueError("first local proof requires proof_kind")
    else:  # pragma: no cover - protected by the type contract at static call sites
        raise ValueError("unsupported outcome")

    receipt = GuardOutcomeReceipt(
        schema_version=SCHEMA_VERSION,
        outcome=outcome,
        occurred_at=_iso_utc(occurred_at),
        hol_guard_version=hol_guard_version,
        verification=verification,
        evidence_digest=evidence_digest,
        handoff_id=handoff_id,
        proof_kind=proof_kind,
    )
    assert_privacy_safe_receipt(receipt.to_dict())
    return receipt


def assert_privacy_safe_receipt(payload: dict[str, object]) -> None:
    """Reject receipt-shaped payloads that add sensitive-content fields."""
    allowed = {
        "schema_version",
        "outcome",
        "occurred_at",
        "hol_guard_version",
        "verification",
        "evidence_digest",
        "handoff_id",
        "proof_kind",
        "sensitive_content_included",
    }
    extras = set(payload) - allowed
    if extras:
        raise ValueError(f"outcome receipt has unsupported fields: {sorted(extras)!r}")
    for key in payload:
        normalized = key.lower()
        if normalized in _FORBIDDEN_KEYS:
            raise ValueError(f"outcome receipt contains forbidden field: {key}")
    if payload.get("sensitive_content_included") is not False:
        raise ValueError("outcome receipts must not include sensitive content")


def canonical_receipt_bytes(receipt: GuardOutcomeReceipt) -> bytes:
    """Return deterministic JSON bytes for transport/idempotency hashing."""
    return json.dumps(receipt.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")


def receipt_digest(receipt: GuardOutcomeReceipt) -> str:
    """Digest the safe receipt itself; this is an integrity/idempotency key."""
    return sha256_digest(canonical_receipt_bytes(receipt))
