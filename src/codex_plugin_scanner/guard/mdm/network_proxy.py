"""Proxy handlers whose routing authority comes only from managed policy."""

from __future__ import annotations

import urllib.parse
import urllib.request


class ManagedExplicitProxyHandler(urllib.request.ProxyHandler):
    """Apply an explicit managed proxy without consulting shell bypass variables."""

    def proxy_open(
        self,
        request: urllib.request.Request,
        proxy: str,
        request_type: str,
    ) -> object | None:
        parsed = urllib.parse.urlsplit(proxy)
        if parsed.scheme not in {"http", "https"} or parsed.hostname is None:
            raise ValueError("managed explicit proxy is invalid")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("managed explicit proxy credentials must not be embedded")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        host = parsed.hostname
        authority_host = f"[{host}]" if ":" in host else host
        request.set_proxy(f"{authority_host}:{port}", parsed.scheme)
        if request.type == parsed.scheme:
            return None
        timeout = getattr(request, "timeout", None)
        if isinstance(timeout, (int, float)):
            return self.parent.open(request, timeout=float(timeout))
        return self.parent.open(request)


__all__ = ["ManagedExplicitProxyHandler"]
