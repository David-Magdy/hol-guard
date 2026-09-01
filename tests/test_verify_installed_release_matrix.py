from __future__ import annotations

import copy

import pytest

from scripts.ci.verify_installed_release_matrix import (
    ALL_HARNESSES,
    REQUIRED_SCENARIOS,
    InstalledMatrixError,
    validate_matrix,
)

VERSION = "3.0.1"
SOURCE_SHA = "a" * 40
RULE_DIGEST = "b" * 64
PLATFORMS = ("manylinux-x64", "macos-x64", "macos-arm64")


def _matrix(*, include_windows: bool = False) -> dict[str, object]:
    platforms = list(PLATFORMS) + (["windows-x64"] if include_windows else [])
    entries = []
    for platform in platforms:
        scenarios = [
            {
                "name": name,
                "package_version": VERSION,
                "env_unset": True,
                "native_selected": True,
                "python_fallback": False,
                "path_search": False,
                "download_attempted": False,
                "outcome": "pass" if name != "fault-injection" else "fail-safe",
                "evidence_count": 16,
                "harness_count": len(ALL_HARNESSES),
                "harnesses": list(ALL_HARNESSES),
            }
            for name in sorted(REQUIRED_SCENARIOS)
        ]
        entries.append(
            {
                "platform": platform,
                "package_version": VERSION,
                "runtime_sha256": "c" * 64,
                "scenarios": scenarios,
            }
        )
    return {
        "schema": "hol-guard-installed-release-matrix.v1",
        "package_version": VERSION,
        "source_sha": SOURCE_SHA,
        "rule_digest": RULE_DIGEST,
        "platforms": entries,
    }


def _validate(payload: dict[str, object], **kwargs: object) -> dict[str, object]:
    return validate_matrix(
        payload,
        expected_version=VERSION,
        expected_source_sha=SOURCE_SHA,
        expected_rule_digest=RULE_DIGEST,
        **kwargs,
    )


def test_matrix_requires_all_scenarios_and_records_waiver() -> None:
    normalized = _validate(_matrix(), windows_waiver="user-waived-for-this-run")

    assert normalized["windows_waiver"] == "user-waived-for-this-run"
    assert [entry["platform"] for entry in normalized["platforms"]] == sorted(PLATFORMS)


def test_matrix_rejects_missing_scenario() -> None:
    payload = _matrix()
    platform = payload["platforms"][0]
    platform["scenarios"] = platform["scenarios"][:-1]

    with pytest.raises(InstalledMatrixError, match="scenario set is incomplete"):
        _validate(payload, windows_waiver="waived")


def test_matrix_rejects_python_fallback_or_path_search() -> None:
    payload = _matrix()
    scenario = payload["platforms"][0]["scenarios"][0]
    scenario["python_fallback"] = True

    with pytest.raises(InstalledMatrixError, match="unsafe runtime"):
        _validate(payload, windows_waiver="waived")


def test_matrix_requires_all_harnesses_per_scenario() -> None:
    payload = _matrix()
    payload["platforms"][0]["scenarios"][0]["harnesses"] = list(ALL_HARNESSES[:-1])

    with pytest.raises(InstalledMatrixError, match="all-harness coverage"):
        _validate(payload, windows_waiver="waived")


def test_matrix_rejects_sensitive_payload_fields() -> None:
    payload = _matrix()
    payload["platforms"][0]["scenarios"][0]["raw_output"] = "source"

    with pytest.raises(InstalledMatrixError, match="non-aggregate"):
        _validate(payload, windows_waiver="waived")


def test_matrix_does_not_allow_waiver_with_windows_evidence() -> None:
    with pytest.raises(InstalledMatrixError, match="waiver cannot"):
        _validate(_matrix(include_windows=True), windows_waiver="waived")


def test_matrix_rejects_pathful_windows_waiver() -> None:
    with pytest.raises(InstalledMatrixError, match="bounded release text"):
        _validate(_matrix(), windows_waiver="/tmp/operator-note")


def test_matrix_normalization_does_not_mutate_source() -> None:
    payload = _matrix()
    original = copy.deepcopy(payload)

    _validate(payload, windows_waiver="waived")

    assert payload == original
