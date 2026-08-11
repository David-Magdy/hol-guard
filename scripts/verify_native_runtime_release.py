#!/usr/bin/env python3
"""Validate HOL Guard native wheels before and after PyPI publication."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import re
import shutil
import stat
import sys
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

from packaging.tags import Tag
from packaging.utils import InvalidWheelFilename, parse_wheel_filename
from packaging.version import InvalidVersion, Version

if __package__:
    from .release_registry_types import Registry, RegistryVerificationError, ReleaseInspection
    from .verify_release_registry import inspect_release
else:
    from release_registry_types import (  # pyright: ignore[reportImplicitRelativeImport]
        Registry,
        RegistryVerificationError,
        ReleaseInspection,
    )
    from verify_release_registry import inspect_release  # pyright: ignore[reportImplicitRelativeImport]

PROJECT: Final = "hol-guard"
SCANNER_PROJECT: Final = "plugin-scanner"
PURE_WHEEL_PROJECTS: Final = frozenset({PROJECT, SCANNER_PROJECT})
MANIFEST_PATH: Final = "codex_plugin_scanner/_native/runtime-manifest.json"
RUNTIME_PATH: Final = "codex_plugin_scanner/_native/hol-guard-runtime"
WINDOWS_RUNTIME_PATH: Final = f"{RUNTIME_PATH}.exe"
EXPECTED_PLATFORMS: Final = frozenset(
    {
        "manylinux_2_17_x86_64",
        "macosx_13_0_x86_64",
        "macosx_11_0_arm64",
        "win_amd64",
    }
)
_MAX_NATIVE_WHEEL_BYTES: Final = 256 * 1024 * 1024
_MAX_RUNTIME_BYTES: Final = 128 * 1024 * 1024
_MAX_MANIFEST_BYTES: Final = 64 * 1024
_MAX_WHEEL_ENTRIES: Final = 16_384
_SHA40: Final = re.compile(r"[0-9a-f]{40}")
_SHA64: Final = re.compile(r"[0-9a-f]{64}")


class NativeReleaseError(RuntimeError):
    """Raised when native release artifacts are not safe to publish."""


def _canonical_version(value: str) -> str:
    try:
        parsed = Version(value)
    except InvalidVersion as exc:
        raise NativeReleaseError("Native release version is invalid") from exc
    if value != str(parsed) or parsed.local is not None:
        raise NativeReleaseError("Native release version must be canonical and public")
    return value


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_zip_member_bounded(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    max_bytes: int,
    label: str,
) -> bytes:
    if info.flag_bits & 0x1:
        raise NativeReleaseError(f"Native wheel {label} entry cannot be encrypted")
    if info.file_size <= 0 or info.file_size > max_bytes:
        raise NativeReleaseError(f"Native wheel {label} size is outside the accepted release bound")
    try:
        with archive.open(info, "r") as handle:
            payload = handle.read(max_bytes + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise NativeReleaseError(f"Native wheel {label} could not be read safely") from exc
    if len(payload) != info.file_size or len(payload) > max_bytes:
        raise NativeReleaseError(f"Native wheel {label} expanded past its declared size")
    return payload


def _wheel_payload(wheel: Path, *, platform: str) -> tuple[Mapping[str, object], bytes]:
    runtime_path = WINDOWS_RUNTIME_PATH if platform.startswith("win") else RUNTIME_PATH
    try:
        with zipfile.ZipFile(wheel) as archive:
            infos = [entry for entry in archive.infolist() if not entry.is_dir()]
            if len(infos) > _MAX_WHEEL_ENTRIES:
                raise NativeReleaseError("Native wheel contains too many archive entries")
            names = [entry.filename for entry in infos]
            if len(names) != len(set(names)) or MANIFEST_PATH not in names or runtime_path not in names:
                raise NativeReleaseError(
                    "Native wheel manifest/runtime is missing or archive entries are duplicated"
                )
            manifest_info = archive.getinfo(MANIFEST_PATH)
            runtime_info = archive.getinfo(runtime_path)
            manifest_bytes = _read_zip_member_bounded(
                archive,
                manifest_info,
                max_bytes=_MAX_MANIFEST_BYTES,
                label="manifest",
            )
            runtime = _read_zip_member_bounded(
                archive,
                runtime_info,
                max_bytes=_MAX_RUNTIME_BYTES,
                label="runtime",
            )
            manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, zipfile.BadZipFile, json.JSONDecodeError, KeyError) as exc:
        raise NativeReleaseError("Native wheel manifest/runtime could not be read") from exc
    if not isinstance(manifest, dict) or not all(isinstance(key, str) for key in manifest):
        raise NativeReleaseError("Native wheel manifest must be an object")
    return manifest, runtime


def _wheel_identity(
    wheel: Path,
    *,
    version: str,
) -> tuple[str, Tag]:
    try:
        metadata = wheel.lstat()
    except OSError as exc:
        raise NativeReleaseError("Release wheel must be a regular non-symlink file") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size <= 0
        or metadata.st_size > _MAX_NATIVE_WHEEL_BYTES
    ):
        raise NativeReleaseError("Release wheel size or file type is outside the accepted release bound")
    try:
        name, wheel_version, build, tags = parse_wheel_filename(wheel.name)
    except InvalidWheelFilename as exc:
        raise NativeReleaseError(f"Invalid release wheel filename: {wheel.name}") from exc
    if str(wheel_version) != version or build or len(tags) != 1:
        raise NativeReleaseError("Release wheel version, build tag, or tag set is invalid")
    return name, next(iter(tags))


def local_native_hashes(dist_dir: Path, *, version: str, source_sha: str) -> dict[str, str]:
    version = _canonical_version(version)
    if _SHA40.fullmatch(source_sha) is None:
        raise NativeReleaseError("Native release source SHA must be a full lowercase Git SHA")
    if not dist_dir.is_dir() or dist_dir.is_symlink():
        raise NativeReleaseError("Native distribution directory must be a regular directory")

    hashes: dict[str, str] = {}
    platforms: set[str] = set()
    pure_projects: set[str] = set()
    for wheel in sorted(dist_dir.glob("*.whl")):
        name, tag = _wheel_identity(wheel, version=version)
        if tag.platform == "any":
            if (
                name not in PURE_WHEEL_PROJECTS
                or tag.interpreter != "py3"
                or tag.abi != "none"
            ):
                raise NativeReleaseError(f"Unexpected pure release wheel: {wheel.name}")
            if name in pure_projects:
                raise NativeReleaseError(f"Duplicate pure release wheel project: {name}")
            pure_projects.add(name)
            continue

        if name != PROJECT:
            raise NativeReleaseError(f"Unexpected native wheel project: {name}")
        if (
            tag.interpreter != "py3"
            or tag.abi != "none"
            or tag.platform not in EXPECTED_PLATFORMS
        ):
            raise NativeReleaseError(f"Unsupported native wheel tag: {tag}")
        if tag.platform in platforms:
            raise NativeReleaseError(f"Duplicate native wheel platform: {tag.platform}")
        platforms.add(tag.platform)

        manifest, runtime = _wheel_payload(wheel, platform=tag.platform)
        expected_keys = {
            "schema",
            "protocol_version",
            "package_version",
            "target",
            "platform_tag",
            "source_sha",
            "rule_digest",
            "runtime_sha256",
            "runtime_size",
        }
        if set(manifest) != expected_keys:
            raise NativeReleaseError("Native wheel manifest has an unexpected shape")
        if (
            manifest.get("schema") != "hol-guard-native-runtime.v1"
            or manifest.get("protocol_version") != 1
            or manifest.get("package_version") != version
            or manifest.get("platform_tag") != tag.platform
            or manifest.get("source_sha") != source_sha
            or not isinstance(manifest.get("target"), str)
            or not isinstance(manifest.get("runtime_size"), int)
            or not isinstance(manifest.get("rule_digest"), str)
            or _SHA64.fullmatch(str(manifest.get("rule_digest"))) is None
            or not isinstance(manifest.get("runtime_sha256"), str)
            or _SHA64.fullmatch(str(manifest.get("runtime_sha256"))) is None
            or manifest.get("runtime_size") != len(runtime)
            or manifest.get("runtime_sha256") != _sha256_bytes(runtime)
        ):
            raise NativeReleaseError("Native wheel manifest identity does not match the embedded runtime")
        hashes[wheel.name] = _sha256_file(wheel)

    if platforms != EXPECTED_PLATFORMS:
        missing = sorted(EXPECTED_PLATFORMS - platforms)
        extra = sorted(platforms - EXPECTED_PLATFORMS)
        raise NativeReleaseError(
            f"Native wheel platform set is incomplete: missing={missing}, extra={extra}"
        )
    return hashes


def _inspection(registry: Registry, version: str) -> ReleaseInspection:
    try:
        return inspect_release(registry, version)
    except RegistryVerificationError as exc:
        raise NativeReleaseError(str(exc)) from exc


def _assert_base_ready(inspection: ReleaseInspection) -> None:
    if not inspection.exists:
        raise NativeReleaseError("Base Guard release is not present yet")
    filenames = {item.filename for item in inspection.files}
    has_pure_wheel = any(name.endswith("-py3-none-any.whl") for name in filenames)
    has_sdist = any(not name.endswith(".whl") for name in filenames)
    if not has_pure_wheel or not has_sdist:
        raise NativeReleaseError("Base Guard release is missing its pure wheel or source distribution")


def assert_base_release_ready(registry: Registry, *, version: str) -> None:
    _assert_base_ready(_inspection(registry, _canonical_version(version)))


def _copy_exclusive(source: Path, target: Path) -> None:
    created = False
    try:
        with source.open("rb") as source_handle:
            try:
                target_handle = target.open("xb")
            except FileExistsError as exc:
                raise NativeReleaseError(
                    f"Refusing to overwrite upload artifact: {target.name}"
                ) from exc
            created = True
            with target_handle:
                shutil.copyfileobj(source_handle, target_handle, length=1024 * 1024)
    except NativeReleaseError:
        raise
    except OSError as exc:
        if created:
            with contextlib.suppress(OSError):
                target.unlink()
        raise NativeReleaseError(f"Native upload artifact could not be copied: {target.name}") from exc


def plan_upload(
    registry: Registry,
    *,
    version: str,
    source_sha: str,
    dist_dir: Path,
    output_dir: Path,
) -> tuple[str, ...]:
    local = local_native_hashes(dist_dir, version=version, source_sha=source_sha)
    inspection = _inspection(registry, version)
    _assert_base_ready(inspection)
    remote = inspection.digests
    for filename, digest in local.items():
        if filename in remote and remote[filename] != digest:
            raise NativeReleaseError(f"Registry already contains different bytes for {filename}")

    output_dir.mkdir(parents=True, exist_ok=True)
    if output_dir.is_symlink():
        raise NativeReleaseError("Native upload directory cannot be a symlink")
    planned: list[str] = []
    for filename in sorted(local):
        if filename in remote:
            continue
        _copy_exclusive(dist_dir / filename, output_dir / filename)
        planned.append(filename)
    return tuple(planned)


def assert_published_exact(
    registry: Registry,
    *,
    version: str,
    source_sha: str,
    dist_dir: Path,
) -> None:
    local = local_native_hashes(dist_dir, version=version, source_sha=source_sha)
    inspection = _inspection(registry, version)
    _assert_base_ready(inspection)
    for filename, digest in local.items():
        remote_digest = inspection.digests.get(filename)
        if remote_digest != digest:
            raise NativeReleaseError(f"Registry native artifact is absent or mismatched: {filename}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("base-ready", "plan-upload", "verify-published", "validate-local"):
        sub = subparsers.add_parser(name)
        if name != "validate-local":
            sub.add_argument("--registry", choices=[item.value for item in Registry], required=True)
        sub.add_argument("--version", required=True)
        if name != "base-ready":
            sub.add_argument("--source-sha", required=True)
            sub.add_argument("--dist-dir", type=Path, required=True)
        if name == "plan-upload":
            sub.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "base-ready":
            assert_base_release_ready(Registry(args.registry), version=args.version)
            result: object = {"status": "ready", "version": _canonical_version(args.version)}
        elif args.command == "validate-local":
            hashes = local_native_hashes(
                args.dist_dir,
                version=args.version,
                source_sha=args.source_sha,
            )
            result = {"status": "valid", "files": sorted(hashes)}
        elif args.command == "plan-upload":
            planned = plan_upload(
                Registry(args.registry),
                version=args.version,
                source_sha=args.source_sha,
                dist_dir=args.dist_dir,
                output_dir=args.output_dir,
            )
            result = {"status": "planned", "files": list(planned)}
        elif args.command == "verify-published":
            assert_published_exact(
                Registry(args.registry),
                version=args.version,
                source_sha=args.source_sha,
                dist_dir=args.dist_dir,
            )
            result = {"status": "exact", "version": args.version}
        else:
            raise NativeReleaseError("Unsupported command")
    except NativeReleaseError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
