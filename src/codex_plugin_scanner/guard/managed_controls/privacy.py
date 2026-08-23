"""Privacy boundaries for Local-to-Cloud catalog continuity."""

from __future__ import annotations

from collections.abc import Mapping

_ALLOWED_EXTENSION_FIELDS = frozenset(
    {"extension_id", "name", "version", "required", "custom", "permissions"}
)
_ALLOWED_PERMISSION_FIELDS = frozenset(
    {
        "permission_id",
        "name",
        "configurable",
        "required",
        "delegated_protection",
    }
)
_FORBIDDEN_MARKERS = (
    "command",
    "raw_command",
    "source_path",
    "working_directory",
    "secret",
    "token",
    "environment",
)


class CatalogPrivacyError(ValueError):
    """Raised when a projection crosses the catalog privacy boundary."""


def _reject_forbidden_keys(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).lower()
            if any(marker in normalized for marker in _FORBIDDEN_MARKERS):
                raise CatalogPrivacyError(f"forbidden catalog field: {key}")
            _reject_forbidden_keys(child)
    elif isinstance(value, list):
        for child in value:
            _reject_forbidden_keys(child)


def privacy_safe_catalog_payload(payload: Mapping[str, object]) -> dict[str, object]:
    _reject_forbidden_keys(payload)
    extensions = payload.get("extensions")
    if not isinstance(extensions, list):
        raise CatalogPrivacyError("extensions must be a list")
    safe_extensions: list[dict[str, object]] = []
    for extension in extensions:
        if not isinstance(extension, Mapping):
            raise CatalogPrivacyError("extension entry must be an object")
        safe = {
            key: extension[key]
            for key in _ALLOWED_EXTENSION_FIELDS
            if key in extension
        }
        permissions = safe.get("permissions", [])
        if not isinstance(permissions, list):
            raise CatalogPrivacyError("permissions must be a list")
        safe["permissions"] = [
            {
                key: permission[key]
                for key in _ALLOWED_PERMISSION_FIELDS
                if key in permission
            }
            for permission in permissions
            if isinstance(permission, Mapping)
        ]
        safe_extensions.append(safe)
    return {
        "schema_version": payload.get("schema_version"),
        "catalog_digest": payload.get("catalog_digest"),
        "extensions": safe_extensions,
    }
