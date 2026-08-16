"""Receiving-side persistence and authentication for extension evidence.

The repository is intentionally independent from FastAPI so the same contract
can be mounted in HOL Guard Cloud, a registry service, or a local evaluator.
The SQLite implementation is a production-safe single-node reference with
transactional idempotency and an append-only audit trail.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
from collections import defaultdict, deque
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .evidence_envelope import EVIDENCE_SCHEMA, canonical_json_bytes, validate_evidence_envelope

MAX_TENANTS = 10_000
MAX_TOKEN_BYTES = 8192
DEFAULT_RETENTION_DAYS = 90


class EvidenceRepositoryError(RuntimeError):
    """Base class for receiving-side evidence failures."""


class EvidenceConflict(EvidenceRepositoryError):
    """Raised when an idempotency key maps to different canonical content."""


class EvidenceNotFound(EvidenceRepositoryError):
    """Raised when tenant-scoped evidence is absent."""


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    tenant_id: str
    evidence_digest: str
    target_digest: str
    schema_version: str
    generated_at: str
    received_at: str
    expires_at: str | None
    envelope: dict[str, Any]


@dataclass(frozen=True, slots=True)
class EvidenceSummary:
    evidence_digest: str
    target_digest: str
    generated_at: str
    received_at: str
    expires_at: str | None
    layers: tuple[tuple[str, str], ...]


def hash_bearer_token(token: str) -> str:
    """Return the configured non-reversible token representation."""

    if not token or len(token.encode("utf-8")) > MAX_TOKEN_BYTES or "\x00" in token:
        raise ValueError("bearer token is missing or exceeds the supported size")
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class TenantTokenRegistry:
    """Constant-time bearer-token to tenant mapping using SHA-256 token hashes."""

    def __init__(self, tenant_hashes: dict[str, str]) -> None:
        if not tenant_hashes or len(tenant_hashes) > MAX_TENANTS:
            raise ValueError("tenant token registry is empty or exceeds its supported size")
        by_hash: dict[str, str] = {}
        for tenant_id, configured in tenant_hashes.items():
            tenant = tenant_id.strip()
            value = configured.removeprefix("sha256:").lower()
            if not tenant or len(tenant) > 160 or any(character.isspace() for character in tenant):
                raise ValueError("tenant identifiers must be bounded non-whitespace strings")
            if len(value) != 64:
                raise ValueError("tenant bearer tokens must be configured as SHA-256 hashes")
            try:
                int(value, 16)
            except ValueError as exc:
                raise ValueError("tenant bearer-token hash is invalid") from exc
            if value in by_hash:
                raise ValueError("bearer-token hashes must be unique across tenants")
            by_hash[value] = tenant
        self._by_hash = by_hash

    @classmethod
    def from_json(cls, value: str) -> TenantTokenRegistry:
        try:
            payload = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("tenant token registry is not valid JSON") from exc
        if not isinstance(payload, dict) or not all(
            isinstance(key, str) and isinstance(item, str) for key, item in payload.items()
        ):
            raise ValueError("tenant token registry must be an object of string hashes")
        return cls(payload)

    def authenticate(self, token: str) -> str | None:
        try:
            candidate = hash_bearer_token(token)
        except ValueError:
            return None
        matched: str | None = None
        for configured, tenant in self._by_hash.items():
            if hmac.compare_digest(candidate, configured):
                matched = tenant
        return matched


class FixedWindowRateLimiter:
    """Bounded in-process limiter for the reference receiver.

    Distributed deployments should replace this with a shared limiter while
    retaining the same ``allow`` contract.
    """

    def __init__(self, max_requests: int = 120, window_seconds: int = 60) -> None:
        if not 1 <= max_requests <= 100_000 or not 1 <= window_seconds <= 3600:
            raise ValueError("rate-limiter settings are outside the supported range")
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> tuple[bool, int]:
        timestamp = time.monotonic() if now is None else now
        cutoff = timestamp - self._window_seconds
        with self._lock:
            events = self._events[key]
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= self._max_requests:
                retry = max(1, int(self._window_seconds - (timestamp - events[0])))
                return False, retry
            events.append(timestamp)
            if not events:
                self._events.pop(key, None)
            return True, 0


class SqliteEvidenceRepository:
    """Immutable tenant-scoped evidence store with transactional audit events."""

    def __init__(self, path: str | Path, *, retention_days: int = DEFAULT_RETENTION_DAYS) -> None:
        if not 1 <= retention_days <= 3650:
            raise ValueError("retention_days must be between 1 and 3650")
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.retention_days = retention_days
        self._initialize()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA trusted_schema = OFF")
        return connection

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS extension_evidence (
                    tenant_id TEXT NOT NULL,
                    evidence_digest TEXT NOT NULL,
                    target_digest TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    expires_at TEXT,
                    canonical_json BLOB NOT NULL,
                    PRIMARY KEY (tenant_id, evidence_digest)
                ) WITHOUT ROWID;

                CREATE INDEX IF NOT EXISTS extension_evidence_target_idx
                    ON extension_evidence (tenant_id, target_digest, received_at DESC);

                CREATE TABLE IF NOT EXISTS extension_evidence_audit (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    evidence_digest TEXT,
                    action TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    occurred_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS extension_evidence_audit_tenant_idx
                    ON extension_evidence_audit (tenant_id, occurred_at DESC);
                """
            )

    @staticmethod
    def _record(row: sqlite3.Row) -> EvidenceRecord:
        envelope = json.loads(bytes(row["canonical_json"]).decode("utf-8"))
        if not isinstance(envelope, dict):
            raise EvidenceRepositoryError("stored evidence is not a JSON object")
        return EvidenceRecord(
            tenant_id=str(row["tenant_id"]),
            evidence_digest=str(row["evidence_digest"]),
            target_digest=str(row["target_digest"]),
            schema_version=str(row["schema_version"]),
            generated_at=str(row["generated_at"]),
            received_at=str(row["received_at"]),
            expires_at=str(row["expires_at"]) if row["expires_at"] else None,
            envelope=envelope,
        )

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        *,
        tenant_id: str,
        evidence_digest: str | None,
        action: str,
        outcome: str,
        occurred_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO extension_evidence_audit
                (tenant_id, evidence_digest, action, outcome, occurred_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (tenant_id, evidence_digest, action, outcome, occurred_at),
        )

    def ingest(
        self,
        tenant_id: str,
        envelope: dict[str, Any],
        *,
        received_at: datetime | None = None,
    ) -> tuple[EvidenceRecord, bool]:
        validated = validate_evidence_envelope(envelope)
        canonical = canonical_json_bytes(validated)
        digest = str(validated["evidenceDigest"]["value"])
        target = str(validated["target"]["digest"]["value"])
        generated = str(validated["generatedAt"])
        received = (received_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
        received_value = received.isoformat()
        expires_value = (received + timedelta(days=self.retention_days)).isoformat()
        tenant = tenant_id.strip()
        if not tenant or len(tenant) > 160:
            raise ValueError("tenant identifier is invalid")

        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    """
                    SELECT * FROM extension_evidence
                    WHERE tenant_id = ? AND evidence_digest = ?
                    """,
                    (tenant, digest),
                ).fetchone()
                if existing is not None:
                    stored = bytes(existing["canonical_json"])
                    if not hmac.compare_digest(stored, canonical):
                        self._audit(
                            connection,
                            tenant_id=tenant,
                            evidence_digest=digest,
                            action="ingest",
                            outcome="conflict",
                            occurred_at=received_value,
                        )
                        connection.execute("COMMIT")
                        raise EvidenceConflict("digest already exists with different canonical content")
                    self._audit(
                        connection,
                        tenant_id=tenant,
                        evidence_digest=digest,
                        action="ingest",
                        outcome="replay",
                        occurred_at=received_value,
                    )
                    connection.execute("COMMIT")
                    return self._record(existing), False

                connection.execute(
                    """
                    INSERT INTO extension_evidence (
                        tenant_id,
                        evidence_digest,
                        target_digest,
                        schema_version,
                        generated_at,
                        received_at,
                        expires_at,
                        canonical_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        tenant,
                        digest,
                        target,
                        EVIDENCE_SCHEMA,
                        generated,
                        received_value,
                        expires_value,
                        canonical,
                    ),
                )
                self._audit(
                    connection,
                    tenant_id=tenant,
                    evidence_digest=digest,
                    action="ingest",
                    outcome="created",
                    occurred_at=received_value,
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return self.get(tenant, digest), True

    def get(self, tenant_id: str, evidence_digest: str) -> EvidenceRecord:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT * FROM extension_evidence
                WHERE tenant_id = ? AND evidence_digest = ?
                """,
                (tenant_id, evidence_digest),
            ).fetchone()
            if row is None:
                self._audit(
                    connection,
                    tenant_id=tenant_id,
                    evidence_digest=evidence_digest,
                    action="read",
                    outcome="not-found",
                    occurred_at=datetime.now(timezone.utc).isoformat(),
                )
                raise EvidenceNotFound("evidence was not found")
            self._audit(
                connection,
                tenant_id=tenant_id,
                evidence_digest=evidence_digest,
                action="read",
                outcome="found",
                occurred_at=datetime.now(timezone.utc).isoformat(),
            )
            return self._record(row)

    def list_summaries(self, tenant_id: str, *, limit: int = 50) -> tuple[EvidenceSummary, ...]:
        bounded_limit = max(1, min(int(limit), 200))
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT * FROM extension_evidence
                WHERE tenant_id = ?
                ORDER BY received_at DESC, evidence_digest ASC
                LIMIT ?
                """,
                (tenant_id, bounded_limit),
            ).fetchall()
        summaries: list[EvidenceSummary] = []
        for row in rows:
            record = self._record(row)
            layers_payload = record.envelope.get("layers", [])
            layers = tuple(
                (str(item.get("id", "unknown")), str(item.get("status", "unknown")))
                for item in layers_payload
                if isinstance(item, dict)
            )
            summaries.append(
                EvidenceSummary(
                    evidence_digest=record.evidence_digest,
                    target_digest=record.target_digest,
                    generated_at=record.generated_at,
                    received_at=record.received_at,
                    expires_at=record.expires_at,
                    layers=layers,
                )
            )
        return tuple(summaries)

    def purge_expired(self, *, now: datetime | None = None) -> int:
        timestamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                rows = connection.execute(
                    """
                    SELECT tenant_id, evidence_digest
                    FROM extension_evidence
                    WHERE expires_at IS NOT NULL AND expires_at <= ?
                    """,
                    (timestamp,),
                ).fetchall()
                for row in rows:
                    self._audit(
                        connection,
                        tenant_id=str(row["tenant_id"]),
                        evidence_digest=str(row["evidence_digest"]),
                        action="retention-purge",
                        outcome="deleted",
                        occurred_at=timestamp,
                    )
                connection.execute(
                    "DELETE FROM extension_evidence WHERE expires_at IS NOT NULL AND expires_at <= ?",
                    (timestamp,),
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return len(rows)

    def audit_events(self, tenant_id: str, *, limit: int = 100) -> tuple[dict[str, str | int | None], ...]:
        bounded_limit = max(1, min(int(limit), 1000))
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT event_id, tenant_id, evidence_digest, action, outcome, occurred_at
                FROM extension_evidence_audit
                WHERE tenant_id = ?
                ORDER BY event_id DESC
                LIMIT ?
                """,
                (tenant_id, bounded_limit),
            ).fetchall()
        return tuple(dict(row) for row in rows)
