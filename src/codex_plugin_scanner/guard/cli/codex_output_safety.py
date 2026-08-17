"""Shared safety classifiers for Codex command and tool output."""

from __future__ import annotations

import re
from collections.abc import Collection


def output_uses_placeholder_private_key_fixture(
    response_text: str,
    *,
    fixture_pattern: re.Pattern[str],
    fixture_body_pattern: re.Pattern[str],
) -> bool:
    """Return true only when every PEM-looking match is the known placeholder fixture."""

    matches = list(fixture_pattern.finditer(response_text))
    if not matches:
        return False
    return all(
        fixture_body_pattern.search(
            " ".join(line.strip() for line in match.group("body").splitlines() if line.strip())
            .replace("\\n", " ")
            .replace("\\r", " ")
        )
        is not None
        for match in matches
    )


def source_name_stem_has_compound_secret_segment(
    stem: str,
    *,
    split_compound: bool,
    secret_like_stems: Collection[str],
) -> bool:
    """Classify compound source-name segments without matching the whole stem twice."""

    lowered = stem.lower()
    if not split_compound:
        return False
    return any(
        segment in secret_like_stems for segment in re.split(r"[-_]+", lowered) if segment and segment != lowered
    )
