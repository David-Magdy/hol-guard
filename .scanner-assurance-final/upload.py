# pyright: basic
"""SSRF-resistant HTTPS evidence uploader with DNS and peer pinning."""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable

from .evidence import validate_evidence_envelope


class UploadError(ValueError):
    pass


Resolver = Callable[..., list[tuple[Any, ...]]]


@dataclass(frozen=True, slots=True)
class UploadResponse:
    status: int
    body: dict[str, Any]
    peer_ip: str


class SecureEvidenceUploader:
    def __init__(
        self,
        *,
        allowed_hosts: tuple[str, ...],
        timeout_seconds: float = 10.0,
        maximum_request_bytes: int = 32 * 1024 * 1024,
        maximum_response_bytes: int = 2 * 1024 * 1024,
        resolver: Resolver = socket.getaddrinfo,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        normalized = tuple(_normalize_host(host) for host in allowed_hosts)
        if not normalized or any(not host for host in normalized):
            raise UploadError("an explicit upload host allowlist is required")
        self.allowed_hosts = frozenset(normalized)
        self.timeout_seconds = timeout_seconds
        self.maximum_request_bytes = maximum_request_bytes
        self.maximum_response_bytes = maximum_response_bytes
        self.resolver = resolver
        self.ssl_context = ssl_context or ssl.create_default_context()
        self.ssl_context.check_hostname = True
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        if timeout_seconds <= 0 or maximum_request_bytes <= 0 or maximum_response_bytes <= 0:
            raise UploadError("uploader limits must be positive")

    def upload(
        self,
        endpoint: str,
        envelope: object,
        *,
        bearer_token: str | None = None,
        idempotency_key: str | None = None,
    ) -> UploadResponse:
        validated = validate_evidence_envelope(
            envelope,
            maximum_bytes=self.maximum_request_bytes,
        )
        parsed, host, port, peer_ips = self._validate_endpoint(endpoint)
        if bearer_token is not None and (
            not bearer_token
            or len(bearer_token) > 16_384
            or "\r" in bearer_token
            or "\n" in bearer_token
        ):
            raise UploadError("bearer token contains invalid characters or length")
        key = idempotency_key or str(validated["evidence_digest"])
        if not key or len(key) > 256 or "\r" in key or "\n" in key:
            raise UploadError("idempotency key is invalid")
        body = json.dumps(
            validated,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        if len(body) > self.maximum_request_bytes:
            raise UploadError("evidence request exceeds size limit")
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Content-Length": str(len(body)),
            "Idempotency-Key": key,
            "User-Agent": "hol-guard-assurance/1",
            "Connection": "close",
        }
        if bearer_token is not None:
            headers["Authorization"] = f"Bearer {bearer_token}"

        connection = _PinnedHTTPSConnection(
            host,
            port,
            peer_ips,
            timeout=self.timeout_seconds,
            context=self.ssl_context,
        )
        try:
            connection.request("POST", path, body=body, headers=headers)
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise UploadError("redirects are rejected for evidence uploads")
            content_length = response.getheader("Content-Length")
            if content_length is not None:
                try:
                    declared = int(content_length)
                except ValueError as exc:
                    raise UploadError("upload response Content-Length is invalid") from exc
                if declared < 0 or declared > self.maximum_response_bytes:
                    raise UploadError("upload response exceeds size limit")
            raw = response.read(self.maximum_response_bytes + 1)
            if len(raw) > self.maximum_response_bytes:
                raise UploadError("upload response exceeds size limit")
            try:
                payload = json.loads(
                    raw.decode("utf-8"),
                    object_pairs_hook=_reject_duplicates,
                ) if raw else {}
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise UploadError("upload response is not valid unambiguous JSON") from exc
            if not isinstance(payload, dict):
                raise UploadError("upload response must be a JSON object")
            if response.status < 200 or response.status >= 300:
                raise UploadError(f"evidence upload failed with HTTP {response.status}")
            peer_ip = connection.peer_ip or "unknown"
            return UploadResponse(response.status, payload, peer_ip)
        finally:
            connection.close()

    def _validate_endpoint(
        self,
        endpoint: str,
    ) -> tuple[urllib.parse.SplitResult, str, int, tuple[str, ...]]:
        try:
            parsed = urllib.parse.urlsplit(endpoint)
            explicit_port = parsed.port
        except ValueError as exc:
            raise UploadError("endpoint URL is invalid") from exc
        if parsed.scheme != "https":
            raise UploadError("evidence endpoint must use HTTPS")
        if parsed.username or parsed.password:
            raise UploadError("endpoint userinfo is forbidden")
        if parsed.fragment:
            raise UploadError("endpoint fragments are forbidden")
        host = _normalize_host(parsed.hostname or "")
        if not host or host not in self.allowed_hosts:
            raise UploadError("endpoint host is not allowlisted")
        port = explicit_port or 443
        if port != 443:
            raise UploadError("non-default upload ports are forbidden")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise UploadError("literal IP evidence endpoints are forbidden")
        try:
            addresses = self.resolver(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise UploadError("endpoint DNS resolution failed") from exc
        peer_ips: list[str] = []
        for result in addresses:
            sockaddr = result[4]
            if not isinstance(sockaddr, tuple) or not sockaddr:
                continue
            address = str(sockaddr[0]).split("%", 1)[0]
            _reject_non_public_ip(address)
            peer_ips.append(address)
        if not peer_ips:
            raise UploadError("endpoint did not resolve to a public address")
        return parsed, host, port, tuple(dict.fromkeys(peer_ips))


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        hostname: str,
        port: int,
        peer_ips: tuple[str, ...],
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(hostname, port=port, timeout=timeout, context=context)
        self._peer_ips = peer_ips
        self.peer_ip: str | None = None

    def connect(self) -> None:
        last_error: OSError | None = None
        for address in self._peer_ips:
            raw: socket.socket | None = None
            try:
                raw = socket.create_connection((address, self.port), self.timeout)
                wrapped = self._context.wrap_socket(raw, server_hostname=self.host)
                peer = str(wrapped.getpeername()[0]).split("%", 1)[0]
                _reject_non_public_ip(peer)
                if peer not in self._peer_ips:
                    wrapped.close()
                    raise UploadError("connected peer differs from validated DNS result")
                self.sock = wrapped
                self.peer_ip = peer
                return
            except OSError as exc:
                last_error = exc
                if raw is not None:
                    raw.close()
                self.sock = None
        raise UploadError("failed to connect to validated evidence endpoint") from last_error


def _normalize_host(host: str) -> str:
    value = host.strip().lower().rstrip(".")
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UploadError("upload host cannot be normalized") from exc


def _reject_non_public_ip(address: str) -> None:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise UploadError("DNS returned an invalid IP address") from exc
    if not parsed.is_global:
        raise UploadError(f"non-public endpoint address is forbidden: {parsed}")


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value
