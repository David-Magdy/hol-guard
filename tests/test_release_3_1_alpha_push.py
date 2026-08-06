"""High-level regression contract for automatic release/3.1 alpha publishing."""

from __future__ import annotations

from pathlib import Path


PUBLISH_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "publish.yml"


def test_release_3_1_push_computes_and_reserves_a_public_alpha() -> None:
    text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    assert "branches: [release/3.1]" in text
    assert "compute_alpha_release_version.py --release-train 3.1" in text
    assert "validate_alpha_release.py" in text
    assert "tag --points-at" in text
    assert 'tag="alpha/v${VERSION}"' in text


def test_release_3_1_push_reaches_testpypi_then_pypi() -> None:
    text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    testpypi = text.index("  publish-alpha-testpypi:")
    pypi = text.index("  publish-alpha-pypi:")
    prerelease = text.index("  release-alpha:")
    assert testpypi < pypi < prerelease
    assert "environment: testpypi" in text[testpypi:pypi]
    assert "environment: pypi" in text[pypi:prerelease]
    assert text.count("pypa/gh-action-pypi-publish@") == 2


def test_release_3_1_dispatch_can_backfill_an_exact_ancestor() -> None:
    text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    assert "expected_sha" in text
    assert "release_version" in text
    assert 'git -C release-tooling merge-base --is-ancestor "$SOURCE_SHA"' in text
    assert 'EXPECTED_SHA" != "$SOURCE_SHA' in text
