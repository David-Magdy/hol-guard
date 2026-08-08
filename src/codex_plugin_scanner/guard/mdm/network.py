"""Enterprise proxy and additive trust policy for Guard HTTP clients."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import platform
import re
import socket
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import IO, Literal

import keyring
import requests
from keyring.errors import KeyringError
from requests.adapters import HTTPAdapter

from .contracts import ManagedNetworkPolicy, ProxyMode
from .policy import load_managed_policy

_PUBLIC_REGISTRIES = frozenset(
    {
        "pypi.org",
        "files.pythonhosted.org",
        "registry.npmjs.org",
        "api.npmjs.org",
        "registry.yarnpkg.com",
        "crates.io",
        "static.crates.io",
        "rubygems.org",
        "repo1.maven.org",
        "repo.maven.apache.org",
        "proxy.golang.org",
        "goproxy.io",
    }
)
_PROXY_CREDENTIAL_SERVICE = "hol-guard-enterprise-proxy-v1"
_MAX_PROXY_CREDENTIAL_BYTES = 16 * 1024
_MAX_CLOCK_SKEW_SECONDS = 300

DnsDiagnosticState = Literal["ok", "failed", "not-tested", "invalid", "blocked"]
ProxyDnsDiagnosticState = Literal["ok", "failed", "not-tested"]
TlsDiagnosticState = Literal["trusted", "failed", "not-tested"]
ClockDiagnosticState = Literal["ok", "skewed", "not-tested"]
ReachabilityDiagnosticState = Literal["reachable", "failed", "not-tested", "blocked"]


class ManagedNetworkError(RuntimeError):
    """A managed network policy blocked or could not establish a request."""


@dataclass(frozen=True, slots=True)
class _ProxyCredentials:
    username: str
    password: str


@dataclass(frozen=True, slots=True)
class ProxyDiagnostic:
    mode: ProxyMode
    selected: bool
    endpoint_hash: str | None
    dns: ProxyDnsDiagnosticState
    authenticated: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "selected": self.selected,
            "endpointHash": self.endpoint_hash,
            "dns": self.dns,
            "authenticated": self.authenticated,
        }


@dataclass(frozen=True, slots=True)
class NetworkDiagnostic:
    endpoint: str
    dns: DnsDiagnosticState
    proxy: ProxyDiagnostic
    tls: TlsDiagnosticState
    clock: ClockDiagnosticState
    reachability: ReachabilityDiagnosticState
    reason_code: str
    clock_skew_seconds: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "dns": self.dns,
            "proxy": self.proxy.to_dict(),
            "tls": self.tls,
            "clock": self.clock,
            "clockSkewSeconds": self.clock_skew_seconds,
            "reachability": self.reachability,
            "reasonCode": self.reason_code,
        }


def active_network_policy() -> ManagedNetworkPolicy:
    state = load_managed_policy()
    return state.policy.network if state.policy is not None else ManagedNetworkPolicy()


def _resolved_policy(policy: ManagedNetworkPolicy | None) -> tuple[ManagedNetworkPolicy, bool]:
    if policy is not None:
        return policy, True
    state = load_managed_policy()
    if state.policy is not None:
        return state.policy.network, True
    return ManagedNetworkPolicy(), False


def platform_system_proxies() -> dict[str, str]:
    """Read OS proxy configuration without treating user environment as managed authority."""

    if platform.system() == "Darwin":
        try:
            result = subprocess.run(
                ["/usr/sbin/scutil", "--proxy"], check=True, capture_output=True, text=True, timeout=5
            )
        except (OSError, subprocess.SubprocessError):
            return {}
        values = dict(re.findall(r"^\s*([A-Za-z]+)\s*:\s*(.+?)\s*$", result.stdout, re.MULTILINE))
        proxies: dict[str, str] = {}
        for scheme, prefix in (("http", "HTTP"), ("https", "HTTPS")):
            if values.get(f"{prefix}Enable") == "1" and values.get(f"{prefix}Proxy"):
                port = values.get(f"{prefix}Port", "443" if scheme == "https" else "80")
                proxies[scheme] = f"http://{values[f'{prefix}Proxy']}:{port}"
        return proxies
    if platform.system() == "Windows":
        try:
            import winreg
        except ImportError:
            return {}
        server: object = None
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                with winreg.OpenKey(
                    hive,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                ) as key:
                    enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                    candidate, _ = winreg.QueryValueEx(key, "ProxyServer")
            except OSError:
                continue
            if enabled and isinstance(candidate, str):
                server = candidate
                break
        if not isinstance(server, str):
            return {}
        if "=" not in server:
            return {"http": f"http://{server}", "https": f"http://{server}"}
        return {
            scheme: f"http://{address}"
            for item in server.split(";")
            if "=" in item
            for scheme, address in [item.split("=", 1)]
            if scheme in {"http", "https"} and address
        }
    return {}


def _request_url(request: str | urllib.request.Request) -> str:
    return request.full_url if isinstance(request, urllib.request.Request) else request


def _validate_destination(url: str, policy: ManagedNetworkPolicy) -> None:
    hostname = (urllib.parse.urlsplit(url).hostname or "").lower()
    if not policy.allow_public_registries and hostname in _PUBLIC_REGISTRIES:
        raise ManagedNetworkError("managed_public_registry_disabled")


def _validated_proxy_url(value: str, *, require_https: bool, reason_code: str) -> str:
    if value != value.strip() or any(character.isspace() for character in value):
        raise ManagedNetworkError(reason_code)
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ManagedNetworkError(reason_code) from exc
    scheme = parsed.scheme.lower()
    if (require_https and scheme != "https") or (not require_https and scheme not in {"http", "https"}):
        raise ManagedNetworkError(reason_code)
    if parsed.hostname is None or not parsed.netloc:
        raise ManagedNetworkError(reason_code)
    if parsed.username is not None or parsed.password is not None:
        raise ManagedNetworkError("managed_proxy_credentials_forbidden")
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise ManagedNetworkError(reason_code)
    resolved_port = port or (443 if scheme == "https" else 80)
    host = parsed.hostname.lower()
    authority_host = f"[{host}]" if ":" in host else host
    return f"{scheme}://{authority_host}:{resolved_port}"


def _proxy_map(policy: ManagedNetworkPolicy) -> dict[str, str]:
    if policy.proxy_mode == "none":
        if policy.proxy_url is not None:
            raise ManagedNetworkError("managed_proxy_url_mode_mismatch")
        return {}
    if policy.proxy_mode == "explicit":
        if policy.proxy_url is None:
            raise ManagedNetworkError("managed_proxy_url_required")
        proxy = _validated_proxy_url(
            policy.proxy_url,
            require_https=True,
            reason_code="managed_proxy_url_invalid",
        )
        return {"http": proxy, "https": proxy}
    if policy.proxy_url is not None:
        raise ManagedNetworkError("managed_proxy_url_mode_mismatch")
    proxies: dict[str, str] = {}
    for scheme, proxy in platform_system_proxies().items():
        if scheme not in {"http", "https"}:
            continue
        proxies[scheme] = _validated_proxy_url(
            proxy,
            require_https=False,
            reason_code="managed_system_proxy_invalid",
        )
    return proxies


def _proxy_credential_key(proxy_url: str) -> str:
    return hashlib.sha256(proxy_url.encode("utf-8")).hexdigest()


def _load_proxy_credentials(proxy_url: str) -> _ProxyCredentials | None:
    """Load optional proxy auth from the OS credential store without policy secrets."""

    try:
        raw = keyring.get_password(_PROXY_CREDENTIAL_SERVICE, _proxy_credential_key(proxy_url))
    except (KeyringError, OSError):
        return None
    if raw is None:
        return None
    if len(raw.encode("utf-8")) > _MAX_PROXY_CREDENTIAL_BYTES:
        raise ManagedNetworkError("managed_proxy_credentials_invalid")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ManagedNetworkError("managed_proxy_credentials_invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {"username", "password"}:
        raise ManagedNetworkError("managed_proxy_credentials_invalid")
    username = payload.get("username")
    password = payload.get("password")
    if (
        not isinstance(username, str)
        or not username
        or ":" in username
        or "\r" in username
        or "\n" in username
        or not isinstance(password, str)
        or not password
        or "\r" in password
        or "\n" in password
    ):
        raise ManagedNetworkError("managed_proxy_credentials_invalid")
    return _ProxyCredentials(username=username, password=password)


def _basic_proxy_authorization(credentials: _ProxyCredentials) -> str:
    token = base64.b64encode(f"{credentials.username}:{credentials.password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def _selected_proxy_url(policy: ManagedNetworkPolicy, endpoint_scheme: str) -> str | None:
    return _proxy_map(policy).get(endpoint_scheme)


def _proxy_endpoint_hash(proxy_url: str) -> str:
    return hashlib.sha256(proxy_url.encode("utf-8")).hexdigest()


def _proxy_diagnostic(policy: ManagedNetworkPolicy, endpoint_scheme: str) -> tuple[ProxyDiagnostic, str | None]:
    try:
        selected = _selected_proxy_url(policy, endpoint_scheme)
    except ManagedNetworkError as exc:
        return ProxyDiagnostic(policy.proxy_mode, False, None, "not-tested", False), str(exc)
    if selected is None:
        return ProxyDiagnostic(policy.proxy_mode, False, None, "not-tested", False), None
    parsed = urllib.parse.urlsplit(selected)
    hostname = parsed.hostname
    if hostname is None:
        return ProxyDiagnostic(policy.proxy_mode, True, _proxy_endpoint_hash(selected), "failed", False), (
            "managed_proxy_url_invalid"
        )
    credentials: _ProxyCredentials | None = None
    if policy.proxy_mode == "explicit":
        try:
            credentials = _load_proxy_credentials(selected)
        except ManagedNetworkError as exc:
            return ProxyDiagnostic(policy.proxy_mode, True, _proxy_endpoint_hash(selected), "not-tested", False), str(exc)
    try:
        socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return ProxyDiagnostic(
            policy.proxy_mode,
            True,
            _proxy_endpoint_hash(selected),
            "failed",
            credentials is not None,
        ), "proxy_resolution_failed"
    return ProxyDiagnostic(
        policy.proxy_mode,
        True,
        _proxy_endpoint_hash(selected),
        "ok",
        credentials is not None,
    ), None


def managed_ssl_context(policy: ManagedNetworkPolicy | None = None) -> ssl.SSLContext:
    """Create mandatory TLS verification with an optional additive private CA."""

    resolved = policy or active_network_policy()
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if resolved.ca_bundle_path is not None:
        bundle = Path(resolved.ca_bundle_path)
        if not bundle.is_absolute() or bundle.is_symlink() or not bundle.is_file():
            raise ManagedNetworkError("managed_ca_bundle_invalid")
        if platform.system() != "Windows":
            try:
                if bundle.stat().st_mode & 0o022:
                    raise ManagedNetworkError("managed_ca_bundle_invalid")
            except OSError as exc:
                raise ManagedNetworkError("managed_ca_bundle_invalid") from exc
        try:
            context.load_verify_locations(cafile=str(bundle))
        except (OSError, ssl.SSLError) as exc:
            raise ManagedNetworkError("managed_ca_bundle_invalid") from exc
    return context


def managed_opener(policy: ManagedNetworkPolicy | None = None) -> urllib.request.OpenerDirector:
    resolved = policy or active_network_policy()
    proxies = _proxy_map(resolved)
    handlers: list[urllib.request.BaseHandler] = [
        urllib.request.ProxyHandler(proxies),
        urllib.request.HTTPSHandler(context=managed_ssl_context(resolved)),
    ]
    if resolved.proxy_mode == "explicit":
        selected = proxies.get("https")
        if selected is not None:
            credentials = _load_proxy_credentials(selected)
            if credentials is not None:
                password_manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
                password_manager.add_password(None, selected, credentials.username, credentials.password)
                handlers.insert(1, urllib.request.ProxyBasicAuthHandler(password_manager))
                handlers.insert(2, urllib.request.ProxyDigestAuthHandler(password_manager))
    return urllib.request.build_opener(*handlers)


def managed_urlopen(
    request: str | urllib.request.Request,
    *,
    timeout: float | None = None,
    policy: ManagedNetworkPolicy | None = None,
) -> IO[bytes]:
    resolved, managed = _resolved_policy(policy)
    _validate_destination(_request_url(request), resolved)
    if (
        not managed
        and resolved.proxy_mode == "system"
        and resolved.ca_bundle_path is None
        and resolved.allow_public_registries
    ):
        return urllib.request.urlopen(request, timeout=timeout)
    return managed_opener(resolved).open(request, timeout=timeout)


class _ManagedHTTPAdapter(HTTPAdapter):
    def __init__(self, context: ssl.SSLContext | None, proxy_authorization: str | None) -> None:
        self._managed_context = context
        self._proxy_authorization = proxy_authorization
        super().__init__()

    def init_poolmanager(
        self,
        connections: int,
        maxsize: int,
        block: bool = False,
        **pool_kwargs: object,
    ) -> None:
        if self._managed_context is not None:
            pool_kwargs["ssl_context"] = self._managed_context
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: object) -> object:
        if self._managed_context is not None:
            proxy_kwargs["ssl_context"] = self._managed_context
            proxy_kwargs["proxy_ssl_context"] = self._managed_context
        return super().proxy_manager_for(proxy, **proxy_kwargs)

    def proxy_headers(self, proxy: str) -> dict[str, str]:
        headers = super().proxy_headers(proxy)
        if self._proxy_authorization is not None:
            headers["Proxy-Authorization"] = self._proxy_authorization
        return headers


def managed_requests_session(policy: ManagedNetworkPolicy | None = None) -> requests.Session:
    resolved, managed = _resolved_policy(policy)
    proxies = _proxy_map(resolved) if managed or resolved.proxy_mode != "system" else {}
    session = requests.Session()
    session.trust_env = not managed
    if proxies:
        session.proxies.update(proxies)
    elif managed and resolved.proxy_mode in {"none", "system"}:
        session.proxies.update({"http": "", "https": ""})
    context: ssl.SSLContext | None = None
    if resolved.ca_bundle_path is not None:
        context = managed_ssl_context(resolved)
    proxy_authorization: str | None = None
    if resolved.proxy_mode == "explicit":
        selected = proxies.get("https")
        if selected is not None:
            credentials = _load_proxy_credentials(selected)
            if credentials is not None:
                proxy_authorization = _basic_proxy_authorization(credentials)
    if context is not None or proxy_authorization is not None:
        session.mount("https://", _ManagedHTTPAdapter(context, proxy_authorization))
    session.verify = True
    return session


def _response_date_header(response: object) -> str | None:
    if isinstance(response, http.client.HTTPResponse):
        return response.getheader("Date")
    if isinstance(response, urllib.error.HTTPError):
        return response.headers.get("Date")
    return None


def _clock_diagnostic(response: object) -> tuple[ClockDiagnosticState, int | None]:
    value = _response_date_header(response)
    if value is None:
        return "not-tested", None
    try:
        remote_time = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return "not-tested", None
    if remote_time.tzinfo is None:
        remote_time = remote_time.replace(tzinfo=timezone.utc)
    skew = int(abs((datetime.now(timezone.utc) - remote_time.astimezone(timezone.utc)).total_seconds()))
    return ("skewed" if skew > _MAX_CLOCK_SKEW_SECONDS else "ok"), skew


def _diagnostic_result(
    *,
    endpoint: str,
    dns: DnsDiagnosticState,
    proxy: ProxyDiagnostic,
    tls: TlsDiagnosticState,
    clock: ClockDiagnosticState,
    reachability: ReachabilityDiagnosticState,
    reason_code: str,
    clock_skew_seconds: int | None = None,
) -> NetworkDiagnostic:
    return NetworkDiagnostic(
        endpoint=endpoint,
        dns=dns,
        proxy=proxy,
        tls=tls,
        clock=clock,
        reachability=reachability,
        reason_code=reason_code,
        clock_skew_seconds=clock_skew_seconds,
    )


def diagnose_endpoint(endpoint: str, policy: ManagedNetworkPolicy | None = None) -> NetworkDiagnostic:
    resolved = policy or active_network_policy()
    parsed = urllib.parse.urlsplit(endpoint)
    hostname = parsed.hostname
    direct_proxy = ProxyDiagnostic(resolved.proxy_mode, False, None, "not-tested", False)
    if parsed.scheme != "https" or hostname is None:
        return _diagnostic_result(
            endpoint="redacted",
            dns="invalid",
            proxy=direct_proxy,
            tls="not-tested",
            clock="not-tested",
            reachability="not-tested",
            reason_code="endpoint_invalid",
        )
    endpoint_label = hostname.lower()
    try:
        _validate_destination(endpoint, resolved)
    except ManagedNetworkError as exc:
        return _diagnostic_result(
            endpoint=endpoint_label,
            dns="blocked",
            proxy=direct_proxy,
            tls="not-tested",
            clock="not-tested",
            reachability="blocked",
            reason_code=str(exc),
        )
    try:
        socket.getaddrinfo(hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return _diagnostic_result(
            endpoint=endpoint_label,
            dns="failed",
            proxy=direct_proxy,
            tls="not-tested",
            clock="not-tested",
            reachability="failed",
            reason_code="dns_resolution_failed",
        )

    proxy, proxy_error = _proxy_diagnostic(resolved, parsed.scheme)
    if proxy_error is not None:
        return _diagnostic_result(
            endpoint=endpoint_label,
            dns="ok",
            proxy=proxy,
            tls="not-tested",
            clock="not-tested",
            reachability="failed",
            reason_code=proxy_error,
        )

    request = urllib.request.Request(endpoint, method="HEAD")
    try:
        with managed_urlopen(request, timeout=10, policy=resolved) as response:
            clock, skew = _clock_diagnostic(response)
            if clock == "skewed":
                return _diagnostic_result(
                    endpoint=endpoint_label,
                    dns="ok",
                    proxy=proxy,
                    tls="trusted",
                    clock=clock,
                    clock_skew_seconds=skew,
                    reachability="reachable",
                    reason_code="clock_skew_detected",
                )
            return _diagnostic_result(
                endpoint=endpoint_label,
                dns="ok",
                proxy=proxy,
                tls="trusted",
                clock=clock,
                clock_skew_seconds=skew,
                reachability="reachable",
                reason_code="endpoint_reachable",
            )
    except urllib.error.HTTPError as exc:
        if exc.code == 407:
            return _diagnostic_result(
                endpoint=endpoint_label,
                dns="ok",
                proxy=proxy,
                tls="not-tested",
                clock="not-tested",
                reachability="failed",
                reason_code="proxy_auth_required",
            )
        clock, skew = _clock_diagnostic(exc)
        if clock == "skewed":
            return _diagnostic_result(
                endpoint=endpoint_label,
                dns="ok",
                proxy=proxy,
                tls="trusted",
                clock=clock,
                clock_skew_seconds=skew,
                reachability="reachable",
                reason_code="clock_skew_detected",
            )
        return _diagnostic_result(
            endpoint=endpoint_label,
            dns="ok",
            proxy=proxy,
            tls="trusted",
            clock=clock,
            clock_skew_seconds=skew,
            reachability="reachable",
            reason_code="endpoint_reachable",
        )
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ssl.SSLError):
            reason_code = "tls_trust_failed"
            tls: TlsDiagnosticState = "failed"
        elif proxy.selected:
            reason_code = "proxy_unreachable"
            tls = "not-tested"
        else:
            reason_code = "endpoint_unreachable"
            tls = "not-tested"
        return _diagnostic_result(
            endpoint=endpoint_label,
            dns="ok",
            proxy=proxy,
            tls=tls,
            clock="not-tested",
            reachability="failed",
            reason_code=reason_code,
        )
    except ManagedNetworkError as exc:
        return _diagnostic_result(
            endpoint=endpoint_label,
            dns="ok",
            proxy=proxy,
            tls="not-tested",
            clock="not-tested",
            reachability="failed",
            reason_code=str(exc),
        )


__all__ = [
    "ManagedNetworkError",
    "NetworkDiagnostic",
    "ProxyDiagnostic",
    "active_network_policy",
    "diagnose_endpoint",
    "managed_opener",
    "managed_requests_session",
    "managed_ssl_context",
    "managed_urlopen",
    "platform_system_proxies",
]
