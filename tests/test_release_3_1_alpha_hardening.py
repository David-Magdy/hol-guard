"""Hardening regressions for release/3.1 alpha retries."""

from __future__ import annotations

from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "publish.yml"


def test_alpha_version_selection_fetches_remote_tags() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "fetch-tags: true" in text
    assert "git -C release-tooling fetch --force --tags origin" in text
    assert "tag --points-at \"$SOURCE_SHA\"" in text


def test_hierarchical_alpha_tag_ref_is_encoded_for_lookup() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "encoded_tag=${tag//\\//%2F}" in text
    assert "git/ref/tags/${encoded_tag}" in text


def test_existing_github_prerelease_is_revalidated() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "--json targetCommitish,isDraft,isPrerelease" in text
    assert 'target" != "$SOURCE_SHA' in text
    assert "gh release download \"$tag\"" in text
    assert "cmp --silent \"$local_file\" \"$remote_file\"" in text
