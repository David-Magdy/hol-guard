# pyright: basic
"""Consuming-side verification, quarantine, and tenant-scoped evidence storage."""

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
from .policy import (
    ASSURANCE_ORDER,
    CONFIDENCE_ORDER,
    DISPOSITION_ORDER,
    SEVERITY_ORDER,
    AssuranceLevel,
    AssurancePolicy,
    Confidence,
    Disposition,
    Severity,
)
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
    publishable: bool
    policy_reason: str
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
            "publishable": self.publishable,
            "policy_reason": self.policy_reason,
            "idempotent": self.idempotent,
            "stored_at": self.stored_at,
        }


class EvidenceStore:
    """Append-only evidence store with independent consumer-side policy evaluation."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.is_symlink():
            raise IngestionError("evidence database path must not be a symlink")
        self._initialize()

    def ingest(
        self,
        envelope: object,
        *,
        policy: AssurancePolicy,
        trusted_public_keys: tuple[Path, ...] = (),
        now: datetime | None = None,
    ) -> IngestionResult:
        policy.validate()
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

        provenance_result = VerificationResult(False, None, "provenance not provided")
        provenance = validated.get("provenance")
        if provenance is not None:
            provenance_result = verify_envelope(
                provenance,
                trusted_public_keys,
                expected_artifact_digest=str(validated["artifact_digest"]),
                expected_evidence_digest=str(validated["assurance_evidence_digest"]),
            )
        if policy.trusted_signers and (
            not provenance_result.verified
            or provenance_result.key_id not in set(policy.trusted_signers)
        ):
            provenance_result = VerificationResult(
                False,
                provenance_result.key_id,
                "evidence was not signed by a managed trusted signer",
                provenance_result.statement,
            )

        assurance = validated["assurance"]
        if not isinstance(assurance, dict):
            raise IngestionError("assurance evidence must be an object")
        effective_disposition, policy_reason = _evaluate_consumer_policy(
            assurance,
            policy=policy,
            provenance_verified=provenance_result.verified,
        )
        publishable = effective_disposition in {Disposition.ALLOW, Disposition.WARN}
        status = "accepted" if publishable else "quarantined"

        tenant_id = str(validated["tenant_id"])
        subject_id = str(validated["subject_id"])
        evidence_id = str(validated["evidence_id"])
        evidence_digest = str(validated["evidence_digest"])
        sequence = int(validated["sequence"])
        stored_at = observed_now.isoformat()
        serialized = json.dumps(
            validated,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT evidence_digest, stored_at, ingestion_status, disposition,
                       provenance_verified, signer_key_id, publishable, policy_reason
                FROM evidence
                WHERE tenant_id=? AND evidence_id=?
                """,
                (tenant_id, evidence_id),
            ).fetchone()
            if existing is not None:
                if existing[0] != evidence_digest:
                    raise IngestionError("evidence_id replayed with different content")
                connection.commit()
                return IngestionResult(
                    status=str(existing[2]),
                    evidence_id=evidence_id,
                    evidence_digest=evidence_digest,
                    tenant_id=tenant_id,
                    subject_id=subject_id,
                    sequence=sequence,
                    disposition=str(existing[3]),
                    provenance_verified=bool(existing[4]),
                    signer_key_id=str(existing[5]) if existing[5] is not None else None,
                    publishable=bool(existing[6]),
                    policy_reason=str(existing[7]),
                    idempotent=True,
                    stored_at=str(existing[1]),
                )

            latest = connection.execute(
                """
                SELECT sequence, disposition, artifact_digest
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
                if (
                    str(latest[2]) == str(validated["artifact_digest"])
                    and _is_decision_downgrade(str(latest[1]), effective_disposition.value)
                ):
                    raise IngestionError(
                        "the same artifact digest cannot silently weaken its prior disposition"
                    )

            collision = connection.execute(
                "SELECT evidence_id FROM evidence WHERE tenant_id=? AND subject_id=? AND sequence=?",
                (tenant_id, subject_id, sequence),
            ).fetchone()
            if collision is not None:
                raise IngestionError("evidence sequence already exists for this subject")

            coverage = assurance.get("coverage")
            coverage_state = str(coverage.get("state")) if isinstance(coverage, dict) else "error"
            assurance_level = str(assurance.get("assurance_level", "static"))
            connection.execute(
                """
                INSERT INTO evidence (
                    tenant_id, subject_id, evidence_id, sequence, evidence_digest,
                    assurance_evidence_digest, artifact_digest, disposition,
                    coverage_state, assurance_level, provenance_verified,
                    signer_key_id, created_at, stored_at, envelope_json,
                    ingestion_status, publishable, policy_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    subject_id,
                    evidence_id,
                    sequence,
                    evidence_digest,
                    str(validated["assurance_evidence_digest"]),
                    str(validated["artifact_digest"]),
                    effective_disposition.value,
                    coverage_state,
                    assurance_level,
                    1 if provenance_result.verified else 0,
                    provenance_result.key_id,
                    str(validated["created_at"]),
                    stored_at,
                    serialized,
                    status,
                    1 if publishable else 0,
                    policy_reason,
                ),
            )
            audit_payload = {
                "event": f"evidence.{status}",
                "tenant_id": tenant_id,
                "subject_id": subject_id,
                "evidence_id": evidence_id,
                "evidence_digest": evidence_digest,
                "sequence": sequence,
                "disposition": effective_disposition.value,
                "publishable": publishable,
                "stored_at": stored_at,
            }
            connection.execute(
                """
                INSERT INTO audit_log (
                    tenant_id, subject_id, event_type, event_digest, event_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    subject_id,
                    f"evidence.{status}",
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
            status=status,
            evidence_id=evidence_id,
            evidence_digest=evidence_digest,
            tenant_id=tenant_id,
            subject_id=subject_id,
            sequence=sequence,
            disposition=effective_disposition.value,
            provenance_verified=provenance_result.verified,
            signer_key_id=provenance_result.key_id,
            publishable=publishable,
            policy_reason=policy_reason,
            idempotent=False,
            stored_at=stored_at,
        )

    def latest(
        self,
        tenant_id: str,
        subject_id: str,
        *,
        publishable_only: bool = False,
    ) -> dict[str, Any] | None:
        connection = self._connect(read_only=True)
        try:
            if publishable_only:
                row = connection.execute(
                    """
                    SELECT envelope_json FROM evidence
                    WHERE tenant_id=? AND subject_id=? AND publishable=1
                    ORDER BY sequence DESC LIMIT 1
                    """,
                    (tenant_id, subject_id),
                ).fetchone()
            else:
                row = connection.execute(
                    """
                    SELECT envelope_json FROM evidence
                    WHERE tenant_id=? AND subject_id=?
                    ORDER BY sequence DESC LIMIT 1
                    """,
                    (tenant_id, subject_id),
                ).fetchone()
        finally:
            connection.close()
        return json.loads(row[0]) if row is not None else None

    def audit_chain(self, tenant_id: str, subject_id: str) -> tuple[dict[str, Any], ...]:
        connection = self._connect(read_only=True)
        try:
            rows = connection.execute(
                """
                SELECT event_json FROM audit_log
                WHERE tenant_id=? AND subject_id=? ORDER BY rowid
                """,
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
                    ingestion_status TEXT NOT NULL DEFAULT 'accepted',
                    publishable INTEGER NOT NULL DEFAULT 1 CHECK(publishable IN (0, 1)),
                    policy_reason TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (tenant_id, evidence_id),
                    UNIQUE (tenant_id, subject_id, sequence),
                    UNIQUE (tenant_id, evidence_digest)
                );
                CREATE INDEX IF NOT EXISTS evidence_subject_latest
                    ON evidence (tenant_id, subject_id, sequence DESC);
                CREATE INDEX IF NOT EXISTS evidence_publishable_latest
                    ON evidence (tenant_id, subject_id, publishable, sequence DESC);
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
            _ensure_column(connection, "evidence", "ingestion_status", "TEXT NOT NULL DEFAULT 'accepted'")
            _ensure_column(connection, "evidence", "publishable", "INTEGER NOT NULL DEFAULT 1")
            _ensure_column(connection, "evidence", "policy_reason", "TEXT NOT NULL DEFAULT ''")
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
        connection.execute("PRAGMA trusted_schema=OFF")
        return connection


def _evaluate_consumer_policy(
    assurance: dict[str, Any],
    *,
    policy: AssurancePolicy,
    provenance_verified: bool,
) -> tuple[Disposition, str]:
    producer = _parse_disposition(
        assurance.get("decision", {}).get("disposition")
        if isinstance(assurance.get("decision"), dict)
        else None
    )
    consumer = Disposition.ALLOW
    reasons: list[str] = []
    findings = assurance.get("findings")
    if not isinstance(findings, list):
        return Disposition.ERROR, "assurance findings are malformed"
    if len(findings) > policy.maximum_findings:
        return Disposition.ERROR, "assurance finding count exceeds managed limit"
    for item in findings:
        if not isinstance(item, dict):
            return Disposition.ERROR, "assurance contains a malformed finding"
        try:
            severity = Severity(str(item.get("severity")))
            confidence = Confidence(str(item.get("confidence")))
        except ValueError:
            return Disposition.ERROR, "assurance contains an unknown severity or confidence"
        if CONFIDENCE_ORDER[confidence] < CONFIDENCE_ORDER[policy.minimum_confidence]:
            continue
        if SEVERITY_ORDER[severity] >= SEVERITY_ORDER[policy.block_at]:
            consumer = _more_restrictive(consumer, Disposition.BLOCK)
        elif SEVERITY_ORDER[severity] >= SEVERITY_ORDER[policy.review_at]:
            consumer = _more_restrictive(consumer, Disposition.REVIEW)
        elif SEVERITY_ORDER[severity] >= SEVERITY_ORDER[policy.warn_at]:
            consumer = _more_restrictive(consumer, Disposition.WARN)

    capabilities = assurance.get("capabilities")
    if not isinstance(capabilities, list) or any(not isinstance(item, str) for item in capabilities):
        return Disposition.ERROR, "assurance capabilities are malformed"
    denied = sorted(set(capabilities) & set(policy.deny_capabilities))
    if denied:
        consumer = _more_restrictive(consumer, Disposition.BLOCK)
        reasons.append(f"managed policy denies capabilities: {', '.join(denied)}")

    coverage = assurance.get("coverage")
    if not isinstance(coverage, dict):
        return Disposition.ERROR, "assurance coverage is malformed"
    coverage_state = str(coverage.get("state"))
    if coverage_state in {"partial", "incomplete"}:
        consumer = _more_restrictive(consumer, policy.incomplete_coverage)
        reasons.append(f"coverage is {coverage_state}")
    elif coverage_state == "error":
        consumer = _more_restrictive(consumer, policy.error_coverage)
        reasons.append("coverage failed")
    elif coverage_state != "complete":
        return Disposition.ERROR, "assurance coverage state is unknown"

    try:
        assurance_level = AssuranceLevel(str(assurance.get("assurance_level")))
    except ValueError:
        return Disposition.ERROR, "assurance level is unknown"
    if ASSURANCE_ORDER[assurance_level] < ASSURANCE_ORDER[policy.minimum_assurance]:
        consumer = _more_restrictive(consumer, Disposition.BLOCK)
        reasons.append("assurance level is below the managed minimum")
    if policy.require_provenance and not provenance_verified:
        consumer = _more_restrictive(consumer, Disposition.BLOCK)
        reasons.append("trusted exact-digest provenance is required")

    detonation = assurance.get("detonation")
    detonation_observed = isinstance(detonation, dict) and detonation.get("observed") is True
    if policy.require_detonation and not detonation_observed:
        consumer = _more_restrictive(consumer, Disposition.BLOCK)
        reasons.append("an exact-artifact-bound sandbox observation is required")

    native_count = coverage.get("native_artifacts")
    rust_count = coverage.get("rust_accelerated_files")
    if not isinstance(native_count, int) or not isinstance(rust_count, int):
        return Disposition.ERROR, "native coverage counters are malformed"
    if policy.require_rust_for_native and native_count > rust_count:
        consumer = _more_restrictive(consumer, Disposition.BLOCK)
        reasons.append("not all native artifacts were structurally parsed by Rust")

    effective = _more_restrictive(producer, consumer)
    if DISPOSITION_ORDER[consumer] > DISPOSITION_ORDER[producer]:
        reasons.append(
            f"consumer policy raised producer disposition from {producer.value} to {consumer.value}"
        )
    if not reasons:
        reasons.append("evidence passed independent consuming-side policy evaluation")
    return effective, "; ".join(reasons)


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise IngestionError("evidence timestamp lacks timezone")
    return parsed.astimezone(timezone.utc)


def _parse_disposition(value: object) -> Disposition:
    try:
        return Disposition(str(value))
    except ValueError:
        return Disposition.ERROR


def _more_restrictive(left: Disposition, right: Disposition) -> Disposition:
    return left if DISPOSITION_ORDER[left] >= DISPOSITION_ORDER[right] else right


def _is_decision_downgrade(previous: str, current: str) -> bool:
    return DISPOSITION_ORDER[_parse_disposition(current)] < DISPOSITION_ORDER[
        _parse_disposition(previous)
    ]


def _ensure_column(
    connection: sqlite3.Connection,
    table: str,
    column: str,
    definition: str,
) -> None:
    existing = {
        str(row[1])
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()  # noqa: S608
    }
    if column not in existing:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")  # noqa: S608
