"""Shared bounded limits for Extension controls and catalog exchange."""

from __future__ import annotations

from typing import Final

LIMITS_SCHEMA_VERSION: Final = 1
MAX_CATALOG_EXTENSIONS: Final = 512
MAX_CATALOG_PAYLOAD_BYTES: Final = 1_000_000
MAX_CONTROL_LAYERS: Final = 2
MAX_CONTROL_SET_RULES: Final = 1_024
MAX_CONTROL_SET_TARGETS: Final = 1_024
MAX_CONTROLS_PER_LAYER: Final = 512
MAX_CONTROLS_TOTAL: Final = MAX_CONTROL_LAYERS * MAX_CONTROLS_PER_LAYER
MAX_INPUT_TEXT_LENGTH: Final = 256
MAX_OBSERVATIONS: Final = 2_048
MAX_PERMISSIONS_PER_EXTENSION: Final = 512
MAX_RESOLUTION_IDS: Final = 1_024


def advertised_extension_control_limits() -> dict[str, int]:
    return {
        "schema_version": LIMITS_SCHEMA_VERSION,
        "max_catalog_extensions": MAX_CATALOG_EXTENSIONS,
        "max_catalog_payload_bytes": MAX_CATALOG_PAYLOAD_BYTES,
        "max_control_layers": MAX_CONTROL_LAYERS,
        "max_control_set_rules": MAX_CONTROL_SET_RULES,
        "max_control_set_targets": MAX_CONTROL_SET_TARGETS,
        "max_controls_per_layer": MAX_CONTROLS_PER_LAYER,
        "max_controls_total": MAX_CONTROLS_TOTAL,
        "max_input_text_length": MAX_INPUT_TEXT_LENGTH,
        "max_observations": MAX_OBSERVATIONS,
        "max_permissions_per_extension": MAX_PERMISSIONS_PER_EXTENSION,
        "max_resolution_ids": MAX_RESOLUTION_IDS,
    }
