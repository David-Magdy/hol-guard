# pyright: basic
"""Authenticated Cloud/registry ingestion service for extension evidence."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .evidence import EvidenceError, parse_json_document
from .ingestion import EvidenceStore, IngestionError
from .policy import AssurancePolicy, BUILTIN_POLICIES


IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


@dataclass(frozen=True, slots=True)
class TenantCredential:
    tenant_id: str
    token_sha256: str
    profile: str = "balanced"
    allow_quarantine_read: bool = False

    @classmethod
    def from_token(
        cls,
        tenant_id: str,
        token: str,
        *,
        profile: str = "balanced",
        allow_quarantine_read: bool = False,
    ) -> TenantCredential:
        if not token or len(token) > 16_384:
            raise ValueError("tenant token is invalid")
        return cls(
            tenant_id=tenant_id,
            token_sha256=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            profile=profile,
            allow_quarantine_read=allow_quarantine_read,
        )

    def validate(self) -> None:
        if not IDENTIFIER_RE.fullmatch(self.tenant_id):
            raise ValueError("tenant_id is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.token_sha256):
            raise ValueError("token_sha256 is invalid")
        if self.profile not in BUILTIN_POLICIES:
            raise ValueError("unknown tenant assurance profile")


def create_evidence_ingestion_app(
    *,
    database_path: Path,
    credentials: tuple[TenantCredential, ...],
    trusted_public_keys: tuple[Path, ...] = (),
    policies: dict[str, AssurancePolicy] | None = None,
    maximum_body_bytes: int = 32 * 1024 * 1024,
) -> FastAPI:
    """Create a tenant-isolated evidence ingestion API.

    The authenticated tenant, not the submitted envelope, selects policy and storage
    scope.  Blocking evidence is retained as quarantined and is hidden from the default
    latest-evidence endpoint.
    """

    if maximum_body_bytes <= 0 or maximum_body_bytes > 128 * 1024 * 1024:
        raise ValueError("maximum_body_bytes is outside the allowed range")
    policy_map = policies or BUILTIN_POLICIES
    credentials_by_digest: dict[str, TenantCredential] = {}
    for credential in credentials:
        credential.validate()
        if credential.profile not in policy_map:
            raise ValueError(f"policy profile is not configured: {credential.profile}")
        if credential.token_sha256 in credentials_by_digest:
            raise ValueError("duplicate tenant credential digest")
        credentials_by_digest[credential.token_sha256] = credential
    if not credentials_by_digest:
        raise ValueError("at least one tenant credential is required")

    store = EvidenceStore(database_path)
    app = FastAPI(
        title="HOL Guard Extension Evidence Ingestion",
        version="1",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/evidence")
    async def ingest(request: Request) -> JSONResponse:
        credential = _authenticate(request, credentials_by_digest)
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise HTTPException(status_code=415, detail="application/json is required")
        raw = await _read_body_bounded(request, maximum_body_bytes)
        try:
            envelope = parse_json_document(raw, maximum_bytes=maximum_body_bytes)
        except EvidenceError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not isinstance(envelope, dict) or envelope.get("tenant_id") != credential.tenant_id:
            raise HTTPException(status_code=403, detail="evidence tenant does not match authentication")
        try:
            result = store.ingest(
                envelope,
                policy=policy_map[credential.profile],
                trusted_public_keys=trusted_public_keys,
            )
        except IngestionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        status_code = 200 if result.idempotent else 201 if result.publishable else 202
        return JSONResponse(result.to_payload(), status_code=status_code)

    @app.get("/v1/evidence/{subject_id}")
    async def latest(subject_id: str, request: Request, include_quarantined: bool = False) -> JSONResponse:
        credential = _authenticate(request, credentials_by_digest)
        if not IDENTIFIER_RE.fullmatch(subject_id):
            raise HTTPException(status_code=400, detail="subject_id is invalid")
        if include_quarantined and not credential.allow_quarantine_read:
            raise HTTPException(status_code=403, detail="quarantine access is not permitted")
        payload = store.latest(
            credential.tenant_id,
            subject_id,
            publishable_only=not include_quarantined,
        )
        if payload is None:
            raise HTTPException(status_code=404, detail="evidence not found")
        return JSONResponse(payload)

    @app.get("/v1/evidence/{subject_id}/audit")
    async def audit(subject_id: str, request: Request) -> JSONResponse:
        credential = _authenticate(request, credentials_by_digest)
        if not credential.allow_quarantine_read:
            raise HTTPException(status_code=403, detail="audit access is not permitted")
        if not IDENTIFIER_RE.fullmatch(subject_id):
            raise HTTPException(status_code=400, detail="subject_id is invalid")
        return JSONResponse({"events": store.audit_chain(credential.tenant_id, subject_id)})

    return app


def _authenticate(
    request: Request,
    credentials_by_digest: dict[str, TenantCredential],
) -> TenantCredential:
    authorization = request.headers.get("authorization", "")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="bearer authentication is required")
    token = authorization[7:]
    if not token or len(token) > 16_384 or "\r" in token or "\n" in token:
        raise HTTPException(status_code=401, detail="bearer token is invalid")
    candidate = hashlib.sha256(token.encode("utf-8")).hexdigest()
    matched: TenantCredential | None = None
    for digest, credential in credentials_by_digest.items():
        if hmac.compare_digest(candidate, digest):
            matched = credential
    if matched is None:
        raise HTTPException(status_code=401, detail="bearer token is invalid")
    return matched


async def _read_body_bounded(request: Request, maximum_body_bytes: int) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Content-Length is invalid") from exc
        if declared < 0 or declared > maximum_body_bytes:
            raise HTTPException(status_code=413, detail="request body exceeds size limit")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > maximum_body_bytes:
            raise HTTPException(status_code=413, detail="request body exceeds size limit")
    return bytes(body)
