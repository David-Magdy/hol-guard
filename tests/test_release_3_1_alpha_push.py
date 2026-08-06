"""Regression contract for automatic release/3.1 alpha publishing."""

from __future__ import annotations

from pathlib import Path


PUBLISH_WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "publish.yml"


def _push_alpha_block() -> str:
    text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
    start = text.index(
        'elif [[ "$GITHUB_EVENT_NAME" == "push" && "$GITHUB_REF" =~ ^refs/heads/release/3\\.[0-9]+$ ]]'
    )
    end = text.index(
        'elif [[ "$GITHUB_EVENT_NAME" == "push" && "$GITHUB_REF" == "refs/heads/main" ]]',
        start,
    )
    return text[start:end]


def test_release_3_1_push_computes_a_public_alpha() -> None:
    text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
    block = _push_alpha_block()

    assert "branches: [main, release/3.0, release/3.1]" in text
    assert 'CHANNEL="alpha"' in block
    assert 'TRAIN="${GITHUB_REF#refs/heads/release/}"' in block
    assert 'if [[ "$TRAIN" != "3.0" && "$TRAIN" != "3.1" ]]' in block
    assert "compute_alpha_release_version.py" in block
    assert "validate_alpha_release.py" in block
    assert "GITHUB_ACTOR_ID" not in block


def test_release_3_1_push_reuses_one_reserved_alpha_per_commit() -> None:
    block = _push_alpha_block()

    assert 'git tag --points-at "$SOURCE_SHA" --list "alpha/v${TRAIN}.0a*"' in block
    assert 'if [[ "${#SOURCE_ALPHA_TAGS[@]}" -gt 1 ]]' in block
    assert 'RELEASE_VERSION="${SOURCE_ALPHA_TAGS[0]}"' in block
    assert "--validate-phase-only" in block
    assert 'REUSING_RESERVED_ALPHA=false' in block


def test_release_3_1_push_reaches_pypi_jobs() -> None:
    text = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    for job_name in (
        "reserve-alpha-tag:",
        "publish-alpha-testpypi:",
        "publish-alpha-pypi:",
        "release-alpha:",
    ):
        start = text.index(f"  {job_name}")
        next_job = text.find("\n  ", start + 3)
        job = text[start:] if next_job == -1 else text[start:next_job]
        assert "github.event_name == 'push'" in job
        assert "startsWith(github.ref, 'refs/heads/release/3.')" in job

    assert "environment: pypi" in text[text.index("  publish-alpha-pypi:") :]
