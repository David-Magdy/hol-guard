"""Adversarial archive assurance tests."""

from __future__ import annotations

import io
import stat
import tarfile
import zipfile
from pathlib import Path

from codex_plugin_scanner.assurance.archive_scan import scan_archive_file
from codex_plugin_scanner.assurance.limits import ScanLimits


def _rules(result) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def test_zip_traversal_duplicate_case_collision_and_symlink(tmp_path: Path) -> None:
    archive_path = tmp_path / "hostile.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../escape.py", "print('escape')")
        archive.writestr("Plugin.py", "print('one')")
        archive.writestr("plugin.py", "print('two')")
        archive.writestr("same.txt", "first")
        archive.writestr("same.txt", "second")
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "../../outside")

    result = scan_archive_file(archive_path, "hostile.zip", ScanLimits())
    rules = _rules(result)
    assert "ASSURANCE_ARCHIVE_PATH_TRAVERSAL" in rules
    assert "ASSURANCE_ARCHIVE_DUPLICATE_MEMBER" in rules
    assert "ASSURANCE_ARCHIVE_CASE_COLLISION" in rules
    assert "ASSURANCE_ARCHIVE_SYMLINK" in rules


def test_tar_links_and_special_files_are_never_extracted(tmp_path: Path) -> None:
    archive_path = tmp_path / "hostile.tar"
    with tarfile.open(archive_path, "w") as archive:
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../etc/passwd"
        archive.addfile(link)
        fifo = tarfile.TarInfo("pipe")
        fifo.type = tarfile.FIFOTYPE
        archive.addfile(fifo)
        traversal = tarfile.TarInfo("../../escape")
        payload = b"escape"
        traversal.size = len(payload)
        archive.addfile(traversal, io.BytesIO(payload))

    result = scan_archive_file(archive_path, "hostile.tar", ScanLimits())
    rules = _rules(result)
    assert "ASSURANCE_ARCHIVE_LINK" in rules
    assert "ASSURANCE_ARCHIVE_SPECIAL_FILE" in rules
    assert "ASSURANCE_ARCHIVE_PATH_TRAVERSAL" in rules
    assert not (tmp_path.parent / "escape").exists()


def test_zip_bomb_ratio_fails_closed(tmp_path: Path) -> None:
    archive_path = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("zeros.bin", b"\0" * (2 * 1024 * 1024))

    result = scan_archive_file(
        archive_path,
        "bomb.zip",
        ScanLimits(max_archive_ratio=5.0),
    )
    assert "ASSURANCE_ARCHIVE_COMPRESSION_BOMB" in _rules(result)
    assert result.complete is False


def test_nested_archive_depth_is_bounded(tmp_path: Path) -> None:
    payload = b"payload"
    for depth in range(5):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(f"level-{depth}.zip", payload)
        payload = buffer.getvalue()
    archive_path = tmp_path / "nested.zip"
    archive_path.write_bytes(payload)

    result = scan_archive_file(
        archive_path,
        "nested.zip",
        ScanLimits(max_archive_depth=2, max_archive_ratio=1000.0),
    )
    assert "ASSURANCE_ARCHIVE_DEPTH_LIMIT" in _rules(result)
    assert result.complete is False


def test_executable_inside_archive_is_reported_for_native_analysis(tmp_path: Path) -> None:
    archive_path = tmp_path / "plugin.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("bin/tool", b"\x7fELF" + b"\0" * 128)

    result = scan_archive_file(archive_path, "plugin.zip", ScanLimits())
    assert result.native_payloads
    assert result.native_payloads[0][0].endswith("!/bin/tool")
