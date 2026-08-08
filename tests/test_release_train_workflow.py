"""Security and idempotency contracts for the release/3.1 alpha publisher."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PUBLISH = ROOT / ".github" / "workflows" / "publish.yml"


def workflow() -> dict[object, object]:
    value = yaml.safe_load(PUBLISH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_only_release_3_1_is_an_automatic_push_train() -> None:
    value = workflow()
    assert value[True]["push"]["branches"] == ["release/3.1"]
    assert value[True]["pull_request"]["branches"] == ["release/3.1"]


def test_dispatch_keeps_trusted_publisher_inputs() -> None:
    inputs = workflow()[True]["workflow_dispatch"]["inputs"]
    assert inputs["release_channel"]["options"] == ["alpha"]
    assert inputs["release_train"]["options"] == ["3.1"]
    assert inputs["release_version"]["required"] is True
    assert inputs["expected_sha"]["required"] is True


def test_publisher_serializes_the_release_train() -> None:
    concurrency = workflow()["concurrency"]
    assert concurrency["group"] == "hol-guard-release-3-1-alpha"
    assert concurrency["cancel-in-progress"] is False


def test_build_uses_current_tooling_and_exact_source_separately() -> None:
    steps = workflow()["jobs"]["build"]["steps"]
    by_name = {step.get("name"): step for step in steps}
    tooling = by_name["Check out current release tooling"]
    assert tooling["with"]["ref"] == "release/3.1"
    assert tooling["with"]["path"] == "release-tooling"
    dispatched = by_name["Check out dispatched package source"]
    pull_request = by_name["Check out pull-request package source"]
    pushed = by_name["Check out pushed package source"]
    assert dispatched["if"] == "github.event_name == 'workflow_dispatch'"
    assert dispatched["with"]["ref"] == "${{ github.event.inputs.expected_sha }}"
    assert pull_request["if"] == "github.event_name == 'pull_request'"
    assert pull_request["with"]["ref"] == "${{ github.event.pull_request.head.sha }}"
    assert pushed["if"] == "github.event_name == 'push'"
    assert pushed["with"]["ref"] == "${{ github.sha }}"
    assert {dispatched["with"]["path"], pull_request["with"]["path"], pushed["with"]["path"]} == {"source"}


def test_build_uses_frozen_release_dependencies() -> None:
    text = PUBLISH.read_text(encoding="utf-8")
    assert "uv sync --frozen --extra dev --extra publish --extra cisco" in text


def test_push_resolves_to_alpha() -> None:
    run = next(
        step["run"]
        for step in workflow()["jobs"]["build"]["steps"]
        if step.get("name") == "Compute immutable alpha version"
    )
    assert "CHANNEL=alpha" in run
    assert 'EVENT_REF" != "refs/heads/release/3.1' in run
    assert "compute_alpha_release_version.py --release-train 3.1" in run


def test_source_must_remain_in_release_history() -> None:
    run = next(
        step["run"]
        for step in workflow()["jobs"]["build"]["steps"]
        if step.get("name") == "Compute immutable alpha version"
    )
    assert 'git -C release-tooling merge-base --is-ancestor "$SOURCE_SHA" refs/remotes/origin/release/3.1' in run


def test_dispatch_can_publish_an_older_ancestor() -> None:
    build = workflow()["jobs"]["build"]
    checkout = next(step for step in build["steps"] if step.get("name") == "Check out dispatched package source")
    assert checkout["with"]["ref"] == "${{ github.event.inputs.expected_sha }}"
    run = next(step["run"] for step in build["steps"] if step.get("name") == "Compute immutable alpha version")
    assert 'EXPECTED_SHA" != "$SOURCE_SHA' in run
    assert 'merge-base --is-ancestor "$SOURCE_SHA"' in run


def test_push_reuses_source_alpha_reservation() -> None:
    run = next(
        step["run"]
        for step in workflow()["jobs"]["build"]["steps"]
        if step.get("name") == "Compute immutable alpha version"
    )
    assert "tag --points-at" in run
    assert 'VERSION="${SOURCE_TAGS[0]}"' in run


def test_only_one_alpha_tag_can_point_at_a_source() -> None:
    run = next(
        step["run"]
        for step in workflow()["jobs"]["build"]["steps"]
        if step.get("name") == "Compute immutable alpha version"
    )
    assert '"${#SOURCE_TAGS[@]}" -gt 1' in run


def test_distribution_version_is_stamped_in_exact_source_tree() -> None:
    step = next(
        step for step in workflow()["jobs"]["build"]["steps"] if step.get("name") == "Stamp exact package version"
    )
    assert step["working-directory"] == "source"
    assert step["run"] == (
        'uv run --no-sync python ../release-tooling/scripts/sync_repo_version.py --repo-root . --version "$VERSION"'
    )


def test_publication_reuses_one_build_artifact() -> None:
    jobs = workflow()["jobs"]
    assert jobs["publish-alpha-testpypi"]["needs"] == ["build", "reserve-alpha-tag"]
    assert jobs["publish-alpha-pypi"]["needs"] == ["build", "reserve-alpha-tag", "publish-alpha-testpypi"]
    for name in ("publish-alpha-testpypi", "publish-alpha-pypi", "release-alpha"):
        assert any(step.get("with", {}).get("name") == "distributions" for step in jobs[name]["steps"])


def test_alpha_tag_is_bound_to_source_sha() -> None:
    run = next(
        step["run"]
        for step in workflow()["jobs"]["reserve-alpha-tag"]["steps"]
        if step.get("name") == "Reserve version for source commit"
    )
    assert '-f sha="$SOURCE_SHA"' in run
    assert '"$existing" != "$SOURCE_SHA"' in run


def test_testpypi_uses_protected_trusted_publishing() -> None:
    job = workflow()["jobs"]["publish-alpha-testpypi"]
    assert job["environment"] == "testpypi"
    assert job["permissions"]["id-token"] == "write"
    assert any(str(step.get("uses", "")).startswith("pypa/gh-action-pypi-publish@") for step in job["steps"])


def test_pypi_uses_protected_trusted_publishing() -> None:
    job = workflow()["jobs"]["publish-alpha-pypi"]
    assert job["environment"] == "pypi"
    assert job["permissions"]["id-token"] == "write"
    assert any(str(step.get("uses", "")).startswith("pypa/gh-action-pypi-publish@") for step in job["steps"])


def test_testpypi_and_pypi_are_idempotent() -> None:
    jobs = workflow()["jobs"]
    for name in ("publish-alpha-testpypi", "publish-alpha-pypi"):
        run = next(step["run"] for step in jobs[name]["steps"] if step.get("name", "").startswith("Inspect "))
        assert '"$status" == "absent" || "$status" == "exact"' in run
        publisher = next(step for step in jobs[name]["steps"] if str(step.get("uses", "")).startswith("pypa/"))
        assert publisher["if"] == "steps.state.outputs.upload == 'true'"


def test_pypi_revalidates_source_history_and_tag() -> None:
    run = next(
        step["run"]
        for step in workflow()["jobs"]["publish-alpha-pypi"]["steps"]
        if step.get("name") == "Revalidate source and alpha reservation"
    )
    assert 'merge-base --is-ancestor "$SOURCE_SHA"' in run
    assert 'refs/tags/alpha/v${VERSION}' in run


def test_registry_bytes_are_verified_after_testpypi_publish() -> None:
    run = next(
        step["run"]
        for step in workflow()["jobs"]["publish-alpha-testpypi"]["steps"]
        if step.get("name") == "Verify published TestPyPI bytes and CLI"
    )
    assert "--download-dir verified-testpypi" in run
    assert "hol-guard --version" in run


def test_registry_bytes_are_verified_after_pypi_publish() -> None:
    run = next(
        step["run"]
        for step in workflow()["jobs"]["publish-alpha-pypi"]["steps"]
        if step.get("name") == "Verify published PyPI bytes and CLI"
    )
    assert "--download-dir verified-pypi" in run
    assert "hol-guard --version" in run


def test_release_is_created_only_after_pypi() -> None:
    job = workflow()["jobs"]["release-alpha"]
    assert job["needs"] == ["build", "publish-alpha-pypi"]
    assert job["permissions"]["attestations"] == "write"


def test_release_notes_show_exact_alpha_install() -> None:
    text = PUBLISH.read_text(encoding="utf-8")
    assert 'uv tool install "hol-guard[cisco]==${VERSION}"' in text


def test_no_hard_coded_actor_ids_gate_alpha_pushes() -> None:
    text = PUBLISH.read_text(encoding="utf-8")
    assert "6068672" not in text
    assert "301892678" not in text


def test_no_run_attempt_gate_prevents_recovery() -> None:
    text = PUBLISH.read_text(encoding="utf-8")
    assert "github.run_attempt == 1" not in text


def test_no_stable_main_publish_path_exists_on_release_branch() -> None:
    text = PUBLISH.read_text(encoding="utf-8")
    assert "publish-main-pypi" not in text
    assert "release-main" not in text


def test_no_plugin_scanner_distribution_is_published_from_release_3_1() -> None:
    text = PUBLISH.read_text(encoding="utf-8")
    assert "Build scanner package" not in text
    assert "plugin_scanner-*" not in text
