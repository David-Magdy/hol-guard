#!/usr/bin/env python3
"""Apply the release/3.1 per-commit alpha publishing repair exactly once."""

from __future__ import annotations

from pathlib import Path


WORKFLOW = Path(".github/workflows/publish.yml")
TESTS = Path("tests/test_release_train_workflow.py")


def replace_once_or_verify(text: str, old: str, new: str, *, label: str) -> str:
    old_count = text.count(old)
    new_count = text.count(new)
    if old_count == 1:
        return text.replace(old, new, 1)
    if old_count == 0 and new_count == 1:
        return text
    raise RuntimeError(f"{label}: expected old=1/new=0 or old=0/new=1, got old={old_count} new={new_count}")


def main() -> int:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    workflow = replace_once_or_verify(
        workflow,
        """    if: >-
      (github.event_name != 'workflow_dispatch' || github.run_attempt == 1) &&
      (github.event_name != 'push' || github.run_attempt == 1)
""",
        """    if: >-
      github.event_name != 'workflow_dispatch' || github.run_attempt == 1
""",
        label="push rerun build gate",
    )

    old_head_check = """          train_ref=\"refs/heads/release/${TRAIN}\"
          remote_train_sha=$(git ls-remote --exit-code origin \"$train_ref\" | awk '{print $1}')
          if [[ \"$remote_train_sha\" != \"$SOURCE_SHA\" ]]; then
            echo \"Alpha publication source is no longer the release train head\" >&2
            exit 1
          fi
"""
    new_history_check = """          train_ref=\"refs/heads/release/${TRAIN}\"
          remote_train_ref=\"refs/remotes/origin/release/${TRAIN}\"
          git fetch --no-tags origin \"+${train_ref}:${remote_train_ref}\"
          if ! git merge-base --is-ancestor \"$SOURCE_SHA\" \"$remote_train_ref\"; then
            echo \"Alpha publication source is no longer in the release train history\" >&2
            exit 1
          fi
"""
    old_count = workflow.count(old_head_check)
    new_count = workflow.count(new_history_check)
    if old_count == 2:
        workflow = workflow.replace(old_head_check, new_history_check)
    elif not (old_count == 0 and new_count == 2):
        raise RuntimeError(f"alpha source revalidation: expected old=2/new=0 or old=0/new=2, got old={old_count} new={new_count}")

    workflow = replace_once_or_verify(
        workflow,
        """          echo \"version=$VERSION\" >> \"$GITHUB_OUTPUT\"
          echo \"channel=$CHANNEL\" >> \"$GITHUB_OUTPUT\"
""",
        """          if [[ \"$GITHUB_EVENT_NAME\" == \"push\" && \"$GITHUB_REF\" =~ ^refs/heads/release/3\\.[0-9]+$ && \"$CHANNEL\" != \"alpha\" ]]; then
            echo \"Release branch push did not resolve to the alpha channel\" >&2
            exit 1
          fi
          echo \"version=$VERSION\" >> \"$GITHUB_OUTPUT\"
          echo \"channel=$CHANNEL\" >> \"$GITHUB_OUTPUT\"
""",
        label="release branch channel assertion",
    )
    WORKFLOW.write_text(workflow, encoding="utf-8")

    tests = TESTS.read_text(encoding="utf-8")
    tests = replace_once_or_verify(
        tests,
        """    assert \"github.event_name != 'push' || github.run_attempt == 1\" in build_condition
""",
        """    assert \"github.event_name != 'push' || github.run_attempt == 1\" not in build_condition
""",
        label="push rerun test",
    )

    old_alpha_block = """    alpha_run = next(
        step[\"run\"]
        for step in jobs[\"publish-alpha-pypi\"][\"steps\"]
        if step.get(\"name\") == \"Revalidate alpha publication authorization\"
    )
    assert \"list-versions --registry pypi\" in alpha_run
    assert \"git ls-remote --exit-code origin\" in alpha_run
    assert \"validate_alpha_release.py\" in alpha_run
    assert \"refs/tags/alpha/v${VERSION}\" in alpha_run
"""
    new_alpha_block = """    alpha_testpypi_run = next(
        step[\"run\"]
        for step in jobs[\"publish-alpha-testpypi\"][\"steps\"]
        if step.get(\"name\") == \"Revalidate alpha source before TestPyPI\"
    )
    alpha_run = next(
        step[\"run\"]
        for step in jobs[\"publish-alpha-pypi\"][\"steps\"]
        if step.get(\"name\") == \"Revalidate alpha publication authorization\"
    )
    for alpha_source_revalidation in (alpha_testpypi_run, alpha_run):
        assert \"git fetch --no-tags origin\" in alpha_source_revalidation
        assert 'git merge-base --is-ancestor \"$SOURCE_SHA\" \"$remote_train_ref\"' in alpha_source_revalidation
        assert \"no longer in the release train history\" in alpha_source_revalidation
        assert \"no longer the release train head\" not in alpha_source_revalidation
    assert \"list-versions --registry pypi\" in alpha_run
    assert \"validate_alpha_release.py\" in alpha_run
    assert \"refs/tags/alpha/v${VERSION}\" in alpha_run
"""
    tests = replace_once_or_verify(tests, old_alpha_block, new_alpha_block, label="alpha source history tests")
    TESTS.write_text(tests, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
