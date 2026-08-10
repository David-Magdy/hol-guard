#!/usr/bin/env python3
"""Build one platform-specific HOL Guard wheel from the verified pure wheel.

The native runtime is injected into ``codex_plugin_scanner/_native``. The
source wheel is never modified in place, and this builder refuses any project
other than ``hol-guard``. It rewrites only wheel metadata required by the
platform artifact plus RECORD hashes.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import stat
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

_MAX_RUNTIME_BYTES = 128 * 1024 * 1024
_PLATFORM_TAG_RE = re.compile(r"^[A-Za-z0-9_.]+$")
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA64_RE = re.compile(r"^[0-9a-f]{64}$")
_NATIVE_DIR = "codex_plugin_scanner/_native"
_RUNTIME_MANIFEST_PATH = f"{_NATIVE_DIR}/runtime-manifest.json"
_DETERMINISTIC_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


class NativeWheelError(ValueError):
    """Raised when a source artifact cannot safely become a native wheel."""


@dataclass(frozen=True, slots=True)
class SourceWheel:
    path: Path
    dist_info: str
    metadata_path: str
    wheel_path: str
    record_path: str
    entries: dict[str, bytes]
    modes: dict[str, int]


def _wheel_version_for_filename(version: str) -> str:
    return version.replace("-", "_")


def _safe_archive_path(name: str) -> bool:
    if not name or "\\" in name:
        return False
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts and all(part not in {"", "."} for part in path.parts)


def _entry_mode(info: zipfile.ZipInfo) -> int:
    raw = info.external_attr >> 16
    if raw and stat.S_ISLNK(raw):
        raise NativeWheelError(f"source wheel contains a symlink entry: {info.filename}")
    mode = stat.S_IMODE(raw) if raw else 0
    return mode or 0o644


def _load_source_wheel(path: Path, *, version: str) -> SourceWheel:
    expected_name = f"hol_guard-{_wheel_version_for_filename(version)}-py3-none-any.whl"
    if path.name != expected_name:
        raise NativeWheelError(f"expected pure hol-guard wheel {expected_name}, got {path.name}")
    if not path.is_file() or path.is_symlink():
        raise NativeWheelError("source wheel must be a regular non-symlink file")

    entries: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    with zipfile.ZipFile(path, "r") as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos if not info.is_dir()]
        if len(names) != len(set(names)):
            raise NativeWheelError("source wheel contains duplicate entries")
        for info in infos:
            if info.is_dir():
                continue
            if not _safe_archive_path(info.filename):
                raise NativeWheelError(f"source wheel contains an unsafe path: {info.filename}")
            entries[info.filename] = archive.read(info)
            modes[info.filename] = _entry_mode(info)

    wheel_paths = [name for name in entries if name.endswith(".dist-info/WHEEL")]
    metadata_paths = [name for name in entries if name.endswith(".dist-info/METADATA")]
    record_paths = [name for name in entries if name.endswith(".dist-info/RECORD")]
    if len(wheel_paths) != 1 or len(metadata_paths) != 1 or len(record_paths) != 1:
        raise NativeWheelError("source wheel must contain exactly one WHEEL, METADATA, and RECORD")

    wheel_path = wheel_paths[0]
    metadata_path = metadata_paths[0]
    record_path = record_paths[0]
    dist_info = wheel_path.rsplit("/", 1)[0]
    if metadata_path.rsplit("/", 1)[0] != dist_info or record_path.rsplit("/", 1)[0] != dist_info:
        raise NativeWheelError("source wheel dist-info metadata is inconsistent")

    metadata = BytesParser().parsebytes(entries[metadata_path])
    if metadata.get("Name") != "hol-guard" or metadata.get("Version") != version:
        raise NativeWheelError("source wheel project identity or version does not match")

    wheel_text = entries[wheel_path].decode("utf-8")
    tags = [line.removeprefix("Tag:").strip() for line in wheel_text.splitlines() if line.startswith("Tag:")]
    if tags != ["py3-none-any"]:
        raise NativeWheelError("source wheel must be the canonical py3-none-any artifact")
    if f"{_NATIVE_DIR}/hol-guard-runtime" in entries or f"{_NATIVE_DIR}/hol-guard-runtime.exe" in entries:
        raise NativeWheelError("source wheel already contains a native runtime")

    return SourceWheel(
        path=path,
        dist_info=dist_info,
        metadata_path=metadata_path,
        wheel_path=wheel_path,
        record_path=record_path,
        entries=entries,
        modes=modes,
    )


def _load_runtime(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise NativeWheelError("runtime must be a regular non-symlink file")
    metadata = path.stat()
    if metadata.st_size <= 0 or metadata.st_size > _MAX_RUNTIME_BYTES:
        raise NativeWheelError("runtime size is outside the accepted release bounds")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o022:
        raise NativeWheelError("runtime is group/world writable")
    return path.read_bytes()


def _rewrite_wheel_metadata(raw: bytes, *, platform_tag: str) -> bytes:
    lines = raw.decode("utf-8").splitlines()
    rewritten = [
        line
        for line in lines
        if not line.startswith("Root-Is-Purelib:") and not line.startswith("Tag:")
    ]
    rewritten.extend(["Root-Is-Purelib: false", f"Tag: py3-none-{platform_tag}"])
    return ("\n".join(rewritten).rstrip() + "\n").encode("utf-8")


def _record_hash(content: bytes) -> str:
    digest = hashlib.sha256(content).digest()
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return f"sha256={encoded}"


def _record_content(entries: dict[str, bytes], *, record_path: str) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name in sorted(entries):
        if name == record_path:
            continue
        content = entries[name]
        writer.writerow([name, _record_hash(content), str(len(content))])
    writer.writerow([record_path, "", ""])
    return output.getvalue().encode("utf-8")


def _zip_info(name: str, *, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=_DETERMINISTIC_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | mode) << 16
    return info


def build_native_wheel(
    *,
    source_wheel: Path,
    runtime: Path,
    output_dir: Path,
    version: str,
    platform_tag: str,
    target: str,
    source_sha: str,
    rule_digest: str,
) -> Path:
    """Return a new native HOL Guard wheel without changing the source wheel."""
    if not version.strip():
        raise NativeWheelError("package version is required")
    if not _PLATFORM_TAG_RE.fullmatch(platform_tag):
        raise NativeWheelError("invalid wheel platform tag")
    if not target or any(character in target for character in "\\/\x00"):
        raise NativeWheelError("invalid runtime target")
    if not _SHA40_RE.fullmatch(source_sha):
        raise NativeWheelError("source SHA must be a lowercase 40-character Git SHA")
    if not _SHA64_RE.fullmatch(rule_digest):
        raise NativeWheelError("rule digest must be a lowercase SHA-256 hex digest")

    source = _load_source_wheel(source_wheel, version=version)
    runtime_bytes = _load_runtime(runtime)
    runtime_name = "hol-guard-runtime.exe" if platform_tag.startswith("win") else "hol-guard-runtime"
    runtime_path = f"{_NATIVE_DIR}/{runtime_name}"

    entries = dict(source.entries)
    modes = dict(source.modes)
    entries[source.wheel_path] = _rewrite_wheel_metadata(entries[source.wheel_path], platform_tag=platform_tag)
    runtime_sha256 = hashlib.sha256(runtime_bytes).hexdigest()
    manifest = {
        "schema": "hol-guard-native-runtime.v1",
        "protocol_version": 1,
        "package_version": version,
        "target": target,
        "platform_tag": platform_tag,
        "source_sha": source_sha,
        "rule_digest": rule_digest,
        "runtime_sha256": runtime_sha256,
        "runtime_size": len(runtime_bytes),
    }
    entries[runtime_path] = runtime_bytes
    entries[_RUNTIME_MANIFEST_PATH] = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    modes[runtime_path] = 0o755
    modes[_RUNTIME_MANIFEST_PATH] = 0o644
    modes[source.wheel_path] = 0o644
    entries[source.record_path] = _record_content(entries, record_path=source.record_path)
    modes[source.record_path] = 0o644

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"hol_guard-{_wheel_version_for_filename(version)}-py3-none-{platform_tag}.whl"
    if output_path.exists():
        raise NativeWheelError(f"refusing to overwrite existing native wheel: {output_path}")

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(entries):
            if not _safe_archive_path(name):
                raise NativeWheelError(f"refusing unsafe output path: {name}")
            archive.writestr(_zip_info(name, mode=modes.get(name, 0o644)), entries[name])
    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Inject the native runtime into a verified hol-guard wheel")
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--platform-tag", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--rule-digest", required=True)
    args = parser.parse_args()
    output = build_native_wheel(
        source_wheel=args.wheel,
        runtime=args.runtime,
        output_dir=args.output_dir,
        version=args.version,
        platform_tag=args.platform_tag,
        target=args.target,
        source_sha=args.source_sha,
        rule_digest=args.rule_digest,
    )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
