"""Platform policy-integrity secret-store selection.

Keep local policy integrity usable on desktop Linux even when the Python keyring
backend is missing or unavailable.  The encrypted per-user store is already the
canonical no-prompt local-vault backend on macOS; on non-macOS platforms we
pair an available system keyring with the same local fallback, or use the local
vault directly when no keyring backend exists.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .store_base import (
    _POLICY_INTEGRITY_SERVICE_NAME,
    EncryptedFileSecretStore,
    FallbackSecretStore,
    SecretStore,
    SystemKeyringSecretStore,
)
from .store_base import (
    _build_policy_integrity_secret_store as _base_policy_integrity_secret_store,
)


def build_policy_integrity_secret_store(
    guard_home: Path,
    *,
    allow_system_keyring: bool = False,
) -> SecretStore | None:
    """Return a prompt-safe policy-integrity store for the current platform."""

    if sys.platform == "darwin":
        return _base_policy_integrity_secret_store(
            guard_home,
            allow_system_keyring=allow_system_keyring,
        )

    fallback_store = EncryptedFileSecretStore(guard_home)
    if SystemKeyringSecretStore._backend_is_available():
        return FallbackSecretStore(
            SystemKeyringSecretStore(service_name=_POLICY_INTEGRITY_SERVICE_NAME),
            fallback_store,
        )
    return fallback_store


__all__ = ["build_policy_integrity_secret_store"]
