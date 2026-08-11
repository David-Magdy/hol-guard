from __future__ import annotations

import hashlib
import json
import os
import zipfile
from pathlib import Path

import pytest

import scripts.verify_native_runtime_release as release
from scripts.release_registry_types import Registry, ReleaseFile, ReleaseInspection

VERSION = "3.0.0a99"
SOURCE_SHA = "a" * 40
RULE_DIGEST = "b" * 64
TARGETS = {
    "manylinux_2_17_x86_64": "x86_64-unknown-linux-musl",
    "macosx_13_0_x86_64": "x86_64-apple-darwin",
    "macosx_11_0_arm64": "aarch64-apple-darwin",
    "win_amd64": "x86_64-pc-windows-msvc",
}


def _native_wheel(root: Path, platform: str, *, runtime: bytes = b"native-runtime") -> Path:
    wheel = root / f"hol_guard-{VERSION}-py3-none-{platform}.whl"
    runtime_path = (
        release.WINDOWS_RUNTIME_PATH if platform.startswith("win") else release.RUNTIME_PATH
    )
    manifest = {
        "schema": "hol-guard-native-runtime.v1",
        "protocol_version": 1,
        "package_version": VERSION,
        "target": TARGETS[platform],
        "platform_tag": platform,
        "source_sha": SOURCE_SHA,
        "rule_digest": RULE_DIGEST,
        "runtime_sha256": hashlib.sha256(runtime).hexdigest(),
        "runtime_size": len(runtime),
    }
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(release.MANIFEST_PATH, json.dumps(manifest))
        archive.writestr(runtime_path, runtime)
    return wheel


def _native_set(root: Path) -> dict[str, Path]:
    root.mkdir(parents=True, exist_ok=True)
    return {platform: _native_wheel(root, platform) for platform in TARGETS}


def _pure_wheel(root: Path, project: str) -> Path:
    wheel = root / f"{project.replace('-', '_')}-{VERSION}-py3-none-any.whl"
    wheel.write_bytes(b"pure-wheel-placeholder")
    return wheel


def _file(path: Path) -> ReleaseFile:
    return ReleaseFile(
        filename=path.name,
        sha256=release._sha256_file(path),
        download_url=f"https://example.invalid/{path.name}",
    )


def _base_inspection(*native: ReleaseFile) -> ReleaseInspection:
    base = (
        ReleaseFile(
            filename=f"hol_guard-{VERSION}-py3-none-any.whl",
            sha256="1" * 64,
            download_url="https://example.invalid/pure.whl",
        ),
        ReleaseFile(
            filename=f"hol_guard-{VERSION}.tar.gz",
            sha256="2" * 64,
            download_url="https://example.invalid/source.tar.gz",
        ),
    )
    return ReleaseInspection(
        registry=Registry.PYPI,
        version=VERSION,
        exists=True,
        files=base + native,
    )


def test_local_native_set_requires_all_four_platforms(tmp_path: Path) -> None:
    wheels = _native_set(tmp_path / "dist")
    hashes = release.local_native_hashes(
        tmp_path / "dist",
        version=VERSION,
        source_sha=SOURCE_SHA,
    )
    assert set(hashes) == {path.name for path in wheels.values()}

    wheels["win_amd64"].unlink()
    with pytest.raises(release.NativeReleaseError, match="platform set is incomplete"):
        release.local_native_hashes(
            tmp_path / "dist",
            version=VERSION,
            source_sha=SOURCE_SHA,
        )


def test_local_native_set_accepts_complete_distribution_wheels(tmp_path: Path) -> None:
    dist_dir = tmp_path / "dist"
    wheels = _native_set(dist_dir)
    _pure_wheel(dist_dir, release.PROJECT)
    _pure_wheel(dist_dir, release.SCANNER_PROJECT)

    hashes = release.local_native_hashes(
        dist_dir,
        version=VERSION,
        source_sha=SOURCE_SHA,
    )

    assert set(hashes) == {path.name for path in wheels.values()}


def test_local_native_set_rejects_unexpected_wheel_project(tmp_path: Path) -> None:
    dist_dir = tmp_path / "dist"
    _native_set(dist_dir)
    _pure_wheel(dist_dir, "unexpected-project")

    with pytest.raises(release.NativeReleaseError, match="Unexpected pure release wheel"):
        release.local_native_hashes(
            dist_dir,
            version=VERSION,
            source_sha=SOURCE_SHA,
        )


def test_local_native_set_binds_manifest_to_runtime_bytes(tmp_path: Path) -> None:
    wheels = _native_set(tmp_path / "dist")
    windows = wheels["win_amd64"]
    with zipfile.ZipFile(windows, "a") as archive:
        archive.writestr(release.WINDOWS_RUNTIME_PATH, b"different")
    with pytest.raises(release.NativeReleaseError):
        release.local_native_hashes(
            tmp_path / "dist",
            version=VERSION,
            source_sha=SOURCE_SHA,
        )


def test_plan_upload_copies_only_missing_native_wheels(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheels = _native_set(tmp_path / "dist")
    existing = _file(wheels["manylinux_2_17_x86_64"])
    monkeypatch.setattr(
        release,
        "_inspection",
        lambda registry, version: _base_inspection(existing),
    )

    planned = release.plan_upload(
        Registry.PYPI,
        version=VERSION,
        source_sha=SOURCE_SHA,
        dist_dir=tmp_path / "dist",
        output_dir=tmp_path / "upload",
    )
    assert len(planned) == 3
    assert existing.filename not in planned
    assert {path.name for path in (tmp_path / "upload").iterdir()} == set(planned)


@pytest.mark.skipif(os.name == "nt", reason="POSIX dangling-symlink regression")
def test_plan_upload_refuses_dangling_destination_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheels = _native_set(tmp_path / "dist")
    monkeypatch.setattr(
        release,
        "_inspection",
        lambda registry, version: _base_inspection(),
    )
    output_dir = tmp_path / "upload"
    output_dir.mkdir()
    first_wheel = min(wheels.values(), key=lambda path: path.name)
    escaped_target = tmp_path / "escaped.whl"
    (output_dir / first_wheel.name).symlink_to(escaped_target)

    with pytest.raises(release.NativeReleaseError, match="Refusing to overwrite"):
        release.plan_upload(
            Registry.PYPI,
            version=VERSION,
            source_sha=SOURCE_SHA,
            dist_dir=tmp_path / "dist",
            output_dir=output_dir,
        )
    assert not escaped_target.exists()


def test_plan_upload_rejects_existing_conflicting_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheels = _native_set(tmp_path / "dist")
    conflicting = ReleaseFile(
        filename=wheels["win_amd64"].name,
        sha256="f" * 64,
        download_url="https://example.invalid/conflict.whl",
    )
    monkeypatch.setattr(
        release,
        "_inspection",
        lambda registry, version: _base_inspection(conflicting),
    )
    with pytest.raises(release.NativeReleaseError, match="different bytes"):
        release.plan_upload(
            Registry.PYPI,
            version=VERSION,
            source_sha=SOURCE_SHA,
            dist_dir=tmp_path / "dist",
            output_dir=tmp_path / "upload",
        )


def test_base_release_requires_pure_wheel_and_sdist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspection = ReleaseInspection(
        registry=Registry.PYPI,
        version=VERSION,
        exists=True,
        files=(
            ReleaseFile(
                filename=f"hol_guard-{VERSION}-py3-none-any.whl",
                sha256="1" * 64,
                download_url="https://example.invalid/pure.whl",
            ),
        ),
    )
    monkeypatch.setattr(release, "_inspection", lambda registry, version: inspection)
    with pytest.raises(release.NativeReleaseError, match="pure wheel or source distribution"):
        release.assert_base_release_ready(Registry.PYPI, version=VERSION)
