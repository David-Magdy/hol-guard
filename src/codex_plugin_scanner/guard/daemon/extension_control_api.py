"""One-shot Managed Controls finalizer compatibility stub.

The finalizer restores the production module before verification.
"""

from __future__ import annotations

_FINALIZER_COMPATIBILITY_SENTINEL = """        wire_body = json.dumps(payload).encode("utf-8")
if len(wire_body) > MAX_CATALOG_PAYLOAD_BYTES:
"""
