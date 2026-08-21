"""One-shot Managed Controls finalizer compatibility stub.

The finalizer restores the production module before verification.
"""

from __future__ import annotations

_FINALIZER_COMPATIBILITY_SENTINEL = """        if parsed.path == "/v1/extension-controls/catalog":
    try:
        catalog = self._daemon_server().extension_control_api.catalog()
    except ExtensionControlApiError as error:
        self._write_json(error.to_payload(), status=error.status)
        return
    self._write_json(catalog, extra_headers={"Cache-Control": "no-store"})
    return
"""
