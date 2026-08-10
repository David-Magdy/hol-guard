from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import stat
import zipfile
from pathlib import Path

import pytest

from scripts.build_native_hol_guard_wheel import NativeWheelError, build_native_wheel

_VERSION = "3.0.0a7"
_SOURCE_SHA = "a" * 40
_RULE_DIGEST = "b" * 64
_PLATFORM_TAG = "manylinux_2_28_x86_64"
_TARGET = "x86_64-unknown-linux-gnu"


def _write_source_wheel(tmp_path: Path, *, version: str = _VERSION, unsafe_name: str | None = None) -> Path:
    path = tmp_path / f"hol_guard-{version}-py3-none-any.whl"
    dist_info = f"hol_guard-{version}.dist-info"
    entries = {
        "codex_plugin_scanner/__init__.py": b"__version__ = 'fixture'\n",
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.4\n"
            "Name: hol-guard\n"
            f"Version: {version}\n"
            "\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: test\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ).encode(),
        f"{dist_info}/RECORD": b"",
    }
    if unsafe_name is not None:
        entries[unsafe_name] = b"unsafe"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return path


def _write_runtime(tmp_path: Path) -> Path:
    path = tmp_path / "hol-guard-runtime"
    path.write_bytes(b"native-runtime-fixture-v1")
    path.chmod(0o755)
    return path


def _record_digest(content: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode()
    return f"sha256={encoded}"


def _build(tmp_path: Path, *, wheel: Path | None = None, runtime: Path | None = None) -> Path:
    return build_native_wheel(
        source_wheel=wheel or _write_source_wheel(tmp_path),
        runtime=runtime or _write_runtime(tmp_path),
        output_dir=tmp_path / "native",
        version=_VERSION,
        platform_tag=_PLATFORM_TAG,
        target=_TARGET,
        source_sha=_SOURCE_SHA,
        rule_digest=_RULE_DIGEST,
    )


def test_native_wheel_injects_runtime_manifest_and_valid_record(tmp_path: Path) -> None:
    output = _build(tmp_path)
    assert output.name == f"hol_guard-{_VERSION}-py3-none-{_PLATFORM_TAG}.whl"

    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
        runtime_path = "codex_plugin_scanner/_native/hol-guard-runtime"
        manifest_path = "codex_plugin_scanner/_native/runtime-manifest.json"
        wheel_path = f"hol_guard-{_VERSION}.dist-info/WHEEL"
        record_path = f"hol_guard-{_VERSION}.dist-info/RECORD"
        assert runtime_path in names
        assert manifest_path in names

        wheel_text = archive.read(wheel_path).decode()
        assert "Root-Is-Purelib: false" in wheel_text
        assert f"Tag: py3-none-{_PLATFORM_TAG}" in wheel_text
        assert "Tag: py3-none-any" not in wheel_text

        runtime_bytes = archive.read(runtime_path)
        manifest = json.loads(archive.read(manifest_path))
        assert manifest == {
            "package_version": _VERSION,
            "platform_tag": _PLATFORM_TAG,
            "protocol_version": 1,
            "rule_digest": _RULE_DIGEST,
            "runtime_sha256": hashlib.sha256(runtime_bytes).hexdigest(),
            "runtime_size": len(runtime_bytes),
            "schema": "hol-guard-native-runtime.v1",
            "source_sha": _SOURCE_SHA,
            "target": _TARGET,
        }
        runtime_mode = stat.S_IMODE(archive.getinfo(runtime_path).external_attr >> 16)
        assert runtime_mode == 0o755

        rows = list(csv.reader(io.StringIO(archive.read(record_path).decode())))
        by_name = {row[0]: row[1:] for row in rows}
        assert by_name[record_path] == ["", ""]
        for name in names - {record_path}:
            content = archive.read(name)
            assert by_name[name] == [_record_digest(content), str(len(content))]


def test_builder_does_not_modify_source_wheel(tmp_path: Path) -> None:
    wheel = _write_source_wheel(tmp_path)
    before = hashlib.sha256(wheel.read_bytes()).hexdigest()
    _ = _build(tmp_path, wheel=wheel)
    assert hashlib.sha256(wheel.read_bytes()).hexdigest() == before


def test_builder_refuses_plugin_scanner_artifact(tmp_path: Path) -> None:
    wheel = _write_source_wheel(tmp_path)
    scanner_wheel = wheel.with_name(f"plugin_scanner-{_VERSION}-py3-none-any.whl")
    wheel.rename(scanner_wheel)
    with pytest.raises(NativeWheelError, match="expected pure hol-guard wheel"):
        _build(tmp_path, wheel=scanner_wheel)


def test_builder_rejects_archive_path_traversal(tmp_path: Path) -> None:
    wheel = _write_source_wheel(tmp_path, unsafe_name="../escaped")
    with pytest.raises(NativeWheelError, match="unsafe path"):
        _build(tmp_path, wheel=wheel)


def test_builder_rejects_source_version_mismatch(tmp_path: Path) -> None:
    wheel = _write_source_wheel(tmp_path, version="3.0.0a6")
    with pytest.raises(NativeWheelError, match="expected pure hol-guard wheel"):
        _build(tmp_path, wheel=wheel)


def test_builder_refuses_overwrite(tmp_path: Path) -> None:
    wheel = _write_source_wheel(tmp_path)
    runtime = _write_runtime(tmp_path)
    _ = _build(tmp_path, wheel=wheel, runtime=runtime)
    with pytest.raises(NativeWheelError, match="refusing to overwrite"):
        _build(tmp_path, wheel=wheel, runtime=runtime)


@pytest.mark.skipif(os.name == "nt", reason="symlink fixture uses POSIX executable semantics")
def test_builder_rejects_symlink_runtime(tmp_path: Path) -> None:
    target = _write_runtime(tmp_path)
    link = tmp_path / "runtime-link"
    link.symlink_to(target)
    with pytest.raises(NativeWheelError, match="regular non-symlink"):
        _build(tmp_path, runtime=link)
