"""Consuming-side evidence verification and append-only SQLite ingestion."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .evidence import EvidenceError, validate_evidence_envelope
from .models import canonical_json_bytes
from .policy import AssurancePolicy, Disposition, DISPOSITION_ORDER
from .provenance import VerificationResult, verify_envelope


class IngestionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class IngestionResult:
    status: str
    evidence_id: str
    evidence_digest: str
    tenant_id: str
    subject_id: str
    sequence: int
    disposition: str
    provenance_verified: bool
    signer_key_id: str | None
    idempotent: bool
    stored_at: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "evidence_id": self.evidence_id,
            "evidence_digest": self.evidence_digest,
            "tenant_id": self.tenant_id,
            "subject_id": self.subject_id,
            "sequence": self.sequence,
            "disposition": self.disposition,
            "provenance_verified": self.provenance_verified,
            "signer_key_id": self.signer_key_id,
            "idempotent": self.idempotent,
            "stored_at": self.stored_at,
        }


class EvidenceStore:
    """Tenant-scoped evidence store with replay, ordering, and downgrade controls."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def ingest(
        self,
        envelope: object,
        *,
        policy: AssurancePolicy,
        trusted_public_keys: tuple[Path, ...] = (),
        now: datetime | None = None,
    ) -> IngestionResult:
        try:
            validated = validate_evidence_envelope(envelope)
        except EvidenceError as exc:
            raise IngestionError(str(exc)) from exc
        observed_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        created_at = _parse_time(str(validated["created_at"]))
        age = observed_now - created_at
        if age < -timedelta(seconds=policy.maximum_clock_skew_seconds):
            raise IngestionError("evidence creation time is too far in the future")
        if age > timedelta(seconds=policy.maximum_evidence_age_seconds):
            raise IngestionError("evidence is older than the managed acceptance window")

        assurance = validated["assurance"]
        disposition = str(assurance["decision"]["disposition"])
        if disposition in {"block", "error"}:
            raise IngestionError(f"evidence decision is not ingestible: {disposition}")
        if disposition == "review" and policy.name in {"consumer-install", "enterprise-strict"}:
            raise IngestionError("managed policy does not accept review-state evidence")
        if assurance["coverage"]["state"] != "complete" and policy.incomplete_coverage in {
            Disposition.BLOCK,
            Disposition.ERROR,
        }:
            raise IngestionError("managed policy requires complete scan coverage")

        provenance_result = VerificationResult(False, None, "provenance not provided")
        provenance = validated.get("provenance")
        if provenance is not None:
            provenance_result = verify_envelope(
                provenance,
                trusted_public_keys,
                expected_artifact_digest=str(validated["artifact_digest"]),
                expected_evidence_digest=str(validated["assurance_evidence_digest"]),
            )
        if policy.require_provenance and not provenance_result.verified:
            raise IngestionError(f"trusted provenance is required: {provenance_result.reason}")
        if policy.trusted_signers:
            if not provenance_result.verified or provenance_result.key_id not in set(policy.trusted_signers):
                raise IngestionError("evidence was not signed by a managed trusted signer")

        tenant_id = str(validated["tenant_id"])
        subject_id = str(validated["subject_id"])
        evidence_id = str(validated["evidence_id"])
        evidence_digest = str(validated["evidence_digest"])
        sequence = int(validated["sequence"])
        stored_at = observed_now.isoformat()
        serialized = json.dumps(validated, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT evidence_digest, stored_at FROM evidence WHERE tenant_id=? AND evidence_id=?",
                (tenant_id, evidence_id),
            ).fetchone()
            if existing is not None:
                if existing[0] != evidence_digest:
                    raise IngestionError("evidence_id replayed with different content")
                connection.commit()
                return IngestionResult(
                    status="accepted",
                    evidence_id=evidence_id,
                    evidence_digest=evidence_digest,
                    tenant_id=tenant_id,
                    subject_id=subject_id,
                    sequence=sequence,
                    disposition=disposition,
                    provenance_verified=provenance_result.verified,
                    signer_key_id=provenance_result.key_id,
                    idempotent=True,
                    stored_at=str(existing[1]),
                )

            latest = connection.execute(
                """
                SELECT sequence, disposition, artifact_digest, evidence_digest
                FROM evidence
                WHERE tenant_id=? AND subject_id=?
                ORDER BY sequence DESC, rowid DESC
                LIMIT 1
                """,
                (tenant_id, subject_id),
            ).fetchone()
            if latest is not None:
                latest_sequence = int(latest[0])
                if sequence <= latest_sequence:
                    raise IngestionError("evidence sequence is not strictly increasing")
                if _is_decision_downgrade(str(latest[1]), disposition):
                    raise IngestionError("new evidence weakens the previously accepted disposition")

            sequence_collision = connection.execute(
                "SELECT evidence_id FROM evidence WHERE tenant_id=? AND subject_id=? AND sequence=?",
                (tenant_id, subject_id, sequence),
            ).fetchone()
            if sequence_collision is not None:
                raise IngestionError("evidence sequence already exists for this subject")

            connection.execute(
                """
                INSERT INTO evidence (
                    tenant_id, subject_id, evidence_id, sequence, evidence_digest,
                    assurance_evidence_digest, artifact_digest, disposition,
                    coverage_state, assurance_level, provenance_verified,
                    signer_key_id, created_at, stored_at, envelope_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    subject_id,
                    evidence_id,
                    sequence,
                    evidence_digest,
                    str(validated["assurance_evidence_digest"]),
                    str(validated["artifact_digest"]),
                    disposition,
                    str(assurance["coverage"]["state"]),
                    str(assurance["assurance_level"]),
                    1 if provenance_result.verified else 0,
                    provenance_result.key_id,
                    str(validated["created_at"]),
                    stored_at,
                    serialized,
                ),
            )
            audit_payload = {
                "event": "evidence.accepted",
                "tenant_id": tenant_id,
                "subject_id": subject_id,
                "evidence_id": evidence_id,
                "evidence_digest": evidence_digest,
                "sequence": sequence,
                "stored_at": stored_at,
            }
            connection.execute(
                "INSERT INTO audit_log (tenant_id, subject_id, event_type, event_digest, event_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    tenant_id,
                    subject_id,
                    "evidence.accepted",
                    hashlib.sha256(canonical_json_bytes(audit_payload)).hexdigest(),
                    json.dumps(audit_payload, sort_keys=True, separators=(",", ":")),
                    stored_at,
                ),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

        return IngestionResult(
            status="accepted",
            evidence_id=evidence_id,
            evidence_digest=evidence_digest,
            tenant_id=tenant_id,
            subject_id=subject_id,
            sequence=sequence,
            disposition=disposition,
            provenance_verified=provenance_result.verified,
            signer_key_id=provenance_result.key_id,
            idempotent=False,
            stored_at=stored_at,
        )

    def latest(self, tenant_id: str, subject_id: str) -> dict[str, Any] | None:
        connection = self._connect(read_only=True)
        try:
            row = connection.execute(
                "SELECT envelope_json FROM evidence WHERE tenant_id=? AND subject_id=? ORDER BY sequence DESC LIMIT 1",
                (tenant_id, subject_id),
            ).fetchone()
        finally:
            connection.close()
        return json.loads(row[0]) if row is not None else None

    def audit_chain(self, tenant_id: str, subject_id: str) -> tuple[dict[str, Any], ...]:
        connection = self._connect(read_only=True)
        try:
            rows = connection.execute(
                "SELECT event_json FROM audit_log WHERE tenant_id=? AND subject_id=? ORDER BY rowid",
                (tenant_id, subject_id),
            ).fetchall()
        finally:
            connection.close()
        return tuple(json.loads(row[0]) for row in rows)

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;
                CREATE TABLE IF NOT EXISTS evidence (
                    tenant_id TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL CHECK(sequence > 0),
                    evidence_digest TEXT NOT NULL,
                    assurance_evidence_digest TEXT NOT NULL,
                    artifact_digest TEXT NOT NULL,
                    disposition TEXT NOT NULL,
                    coverage_state TEXT NOT NULL,
                    assurance_level TEXT NOT NULL,
                    provenance_verified INTEGER NOT NULL CHECK(provenance_verified IN (0, 1)),
                    signer_key_id TEXT,
                    created_at TEXT NOT NULL,
                    stored_at TEXT NOT NULL,
                    envelope_json TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, evidence_id),
                    UNIQUE (tenant_id, subject_id, sequence),
                    UNIQUE (tenant_id, evidence_digest)
                );
                CREATE INDEX IF NOT EXISTS evidence_subject_latest
                    ON evidence (tenant_id, subject_id, sequence DESC);
                CREATE TABLE IF NOT EXISTS audit_log (
                    tenant_id TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_digest TEXT NOT NULL,
                    event_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE (tenant_id, event_digest)
                );
                """
            )
            connection.commit()
        finally:
            connection.close()

    def _connect(self, *, read_only: bool = False) -> sqlite3.Connection:
        if read_only:
            connection = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True, timeout=10.0)
        else:
            connection = sqlite3.connect(self.path, timeout=10.0, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=10000")
        return connection


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise IngestionError("evidence timestamp lacks timezone")
    return parsed.astimezone(timezone.utc)


def _is_decision_downgrade(previous: str, current: str) -> bool:
    try:
        previous_value = Disposition(previous)
        current_value = Disposition(current)
    except ValueError as exc:
        raise IngestionError("unknown assurance disposition") from exc
    # Once a subject is accepted at a stricter state, a less restrictive state must be
    # backed by an explicit administrative reapproval rather than silent evidence drift.
    return DISPOSITION_ORDER[current_value] < DISPOSITION_ORDER[previous_value]
