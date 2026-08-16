from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.node_semver import node_semver_spec_matches


@pytest.mark.parametrize(
    ("specifier", "version", "expected"),
    (
        ("4.1.8", "4.1.8", True),
        ("4.1.8", "4.1.9", False),
        ("^4.1.8", "4.9.0", True),
        ("^4.1.8", "5.0.0", False),
        ("^0.2.3", "0.2.9", True),
        ("^0.2.3", "0.3.0", False),
        ("^0.0.3", "0.0.3", True),
        ("^0.0.3", "0.0.4", False),
        ("~4.1.8", "4.1.9", True),
        ("~4.1.8", "4.2.0", False),
        ("16.3.0-preview.8", "16.3.0-preview.8", True),
        ("16.3.0-preview.8", "16.3.0-preview.9", False),
        ("^16.3.0", "16.3.0-preview.8", False),
        (">=4.1.8", "4.1.8", False),
        ("^4.1", "4.1.8", False),
        (" ^4.1.8", "4.1.8", False),
    ),
)
def test_node_semver_spec_matches_conservative_subset(
    specifier: str,
    version: str,
    expected: bool,
) -> None:
    assert node_semver_spec_matches(specifier, version) is expected
