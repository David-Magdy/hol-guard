# pyright: basic
"""In-memory, extraction-free archive inspection with strict resource limits."""

from __future__ import annotations

import gzip
import hashlib
import io
import lzma
import posixpath
import stat
import tarfile
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .limits import ScanLimits
from .models import Confidence, EvidenceLocation, SecurityFinding, Severity


ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
GZIP_MAGIC = b"\x1f\x8b"
XZ_MAGIC = b"\xfd7zXZ\x00"
NATIVE_MAGICS = (
    b"\x7fELF",
    b"MZ",
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\x00asm",
)
INCOMPLETE_ARCHIVE_RULES = frozenset(
    {
        "ASSURANCE_ARCHIVE_DEPTH_LIMIT",
        "ASSURANCE_ARCHIVE_INVALID",
        "ASSURANCE_ARCHIVE_MEMBER_LIMIT",
        "ASSURANCE_ARCHIVE_ENCRYPTED_MEMBER",
        "ASSURANCE_ARCHIVE_COMPRESSION_BOMB",
        "ASSURANCE_ARCHIVE_MEMBER_OVERSIZED",
        "ASSURANCE_ARCHIVE_EXPANSION_LIMIT",
        "ASSURANCE_ARCHIVE_MEMBER_READ_FAILED",
        "ASSURANCE_ARCHIVE_CRC_ERROR",
    }
)


@dataclass(frozen=True, slots=True)
class ArchiveMember:
    display_path: str
    size: int
    compressed_size: int | None
    kind: str
    sha256: str | None
    depth: int


@dataclass(frozen=True, slots=True)
class ArchiveResult:
    findings: tuple[SecurityFinding, ...]
    members: tuple[ArchiveMember, ...]
    text_payloads: tuple[tuple[str, bytes], ...]
    native_payloads: tuple[tuple[str, bytes], ...]
    expanded_bytes: int
    complete: bool


def looks_like_archive(path: Path, prefix: bytes) -> bool:
    suffixes = [suffix.lower() for suffix in path.suffixes]
    return (
        prefix.startswith(ZIP_MAGIC)
        or prefix.startswith(GZIP_MAGIC)
        or prefix.startswith(XZ_MAGIC)
        or any(
            suffix in {".zip", ".jar", ".whl", ".tar", ".tgz", ".gz", ".xz", ".txz"}
            for suffix in suffixes
        )
    )


def scan_archive_file(path: Path, display_path: str, limits: ScanLimits) -> ArchiveResult:
    try:
        size = path.stat().st_size
    except OSError:
        return _invalid_result(display_path, "Archive could not be statted.")
    if size > limits.max_archive_bytes:
        return ArchiveResult(
            findings=(
                _finding(
                    "ASSURANCE_ARCHIVE_OVERSIZED",
                    Severity.HIGH,
                    "Archive exceeds the scanner byte limit",
                    "The archive is digest-bound but cannot be safely expanded within managed limits.",
                    display_path,
                ),
            ),
            members=(),
            text_payloads=(),
            native_payloads=(),
            expanded_bytes=0,
            complete=False,
        )
    try:
        data = path.read_bytes()
    except OSError:
        return _invalid_result(display_path, "Archive could not be read.")
    return scan_archive_bytes(data, display_path, limits, depth=0, budget=[0, 0])


def scan_archive_bytes(
    data: bytes,
    display_path: str,
    limits: ScanLimits,
    *,
    depth: int,
    budget: list[int],
) -> ArchiveResult:
    if depth > limits.max_archive_depth:
        return ArchiveResult(
            findings=(
                _finding(
                    "ASSURANCE_ARCHIVE_DEPTH_LIMIT",
                    Severity.HIGH,
                    "Nested archive depth limit reached",
                    "Further nested content was not inspected.",
                    display_path,
                ),
            ),
            members=(),
            text_payloads=(),
            native_payloads=(),
            expanded_bytes=0,
            complete=False,
        )
    if len(data) > limits.max_archive_bytes:
        return ArchiveResult(
            findings=(
                _finding(
                    "ASSURANCE_ARCHIVE_OVERSIZED",
                    Severity.HIGH,
                    "Archive exceeds the scanner byte limit",
                    "Nested archive bytes exceed the managed limit.",
                    display_path,
                ),
            ),
            members=(),
            text_payloads=(),
            native_payloads=(),
            expanded_bytes=0,
            complete=False,
        )
    prefix = data[:8]
    suffixes = [suffix.lower() for suffix in Path(display_path).suffixes]
    if prefix.startswith(ZIP_MAGIC) or any(suffix in {".zip", ".jar", ".whl"} for suffix in suffixes):
        return _scan_zip(data, display_path, limits, depth, budget)
    if prefix.startswith(GZIP_MAGIC) or suffixes[-2:] == [".tar", ".gz"] or ".tgz" in suffixes:
        if _looks_like_tar_stream(data, compressed="gzip"):
            return _scan_tar(data, display_path, limits, depth, budget)
        return _scan_single_compressed(data, display_path, limits, depth, budget, kind="gzip")
    if prefix.startswith(XZ_MAGIC) or ".xz" in suffixes or ".txz" in suffixes:
        if _looks_like_tar_stream(data, compressed="xz"):
            return _scan_tar(data, display_path, limits, depth, budget)
        return _scan_single_compressed(data, display_path, limits, depth, budget, kind="xz")
    if ".tar" in suffixes:
        return _scan_tar(data, display_path, limits, depth, budget)
    return _invalid_result(display_path, "Archive format is unsupported or malformed.")


def _scan_zip(
    data: bytes,
    display_path: str,
    limits: ScanLimits,
    depth: int,
    budget: list[int],
) -> ArchiveResult:
    findings: list[SecurityFinding] = []
    members: list[ArchiveMember] = []
    text_payloads: list[tuple[str, bytes]] = []
    native_payloads: list[tuple[str, bytes]] = []
    complete = True
    expanded = 0
    seen_names: set[str] = set()
    seen_casefold: dict[str, str] = {}
    seen_offsets: set[int] = set()
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > limits.max_archive_members:
                findings.append(
                    _finding(
                        "ASSURANCE_ARCHIVE_MEMBER_LIMIT",
                        Severity.HIGH,
                        "Archive member count exceeds limit",
                        "Only the bounded member prefix can be inspected.",
                        display_path,
                    )
                )
                infos = infos[: limits.max_archive_members]
                complete = False
            for info in infos:
                budget[0] += 1
                if budget[0] > limits.max_archive_members:
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_MEMBER_LIMIT",
                            Severity.HIGH,
                            "Aggregate nested archive member limit reached",
                            "Further nested archive entries were not inspected.",
                            display_path,
                        )
                    )
                    complete = False
                    break
                member_name = _normalized_member_name(info.filename)
                member_display = f"{display_path}!/{member_name}"
                if _unsafe_member_name(info.filename):
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_PATH_TRAVERSAL",
                            Severity.CRITICAL,
                            "Unsafe archive member path",
                            "The member uses an absolute, parent-relative, drive, NUL, or ambiguous path.",
                            member_display,
                        )
                    )
                if member_name in seen_names:
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_DUPLICATE_MEMBER",
                            Severity.HIGH,
                            "Duplicate archive member path",
                            "Multiple records resolve to the same normalized member name.",
                            member_display,
                        )
                    )
                seen_names.add(member_name)
                folded = member_name.casefold()
                if folded in seen_casefold and seen_casefold[folded] != member_name:
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_CASE_COLLISION",
                            Severity.HIGH,
                            "Case-colliding archive members",
                            "Different member names collide on case-insensitive filesystems.",
                            member_display,
                        )
                    )
                seen_casefold[folded] = member_name
                if info.header_offset in seen_offsets:
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_OVERLAPPING_RECORD",
                            Severity.HIGH,
                            "Archive members share a local header offset",
                            "The central directory contains an ambiguous overlapping record.",
                            member_display,
                        )
                    )
                    complete = False
                seen_offsets.add(info.header_offset)

                unix_mode = (info.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(unix_mode)
                is_link = file_type == stat.S_IFLNK
                is_special = file_type not in {0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK}
                if is_link:
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_SYMLINK",
                            Severity.HIGH,
                            "Archive contains a symbolic link",
                            "Symlinks are never extracted or followed by the scanner.",
                            member_display,
                        )
                    )
                if is_special:
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_SPECIAL_FILE",
                            Severity.CRITICAL,
                            "Archive contains a special file",
                            "Device, FIFO, socket, or other special entries are unsafe in extension packages.",
                            member_display,
                        )
                    )
                if info.flag_bits & 0x1:
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_ENCRYPTED_MEMBER",
                            Severity.HIGH,
                            "Encrypted archive member cannot be inspected",
                            "Encrypted content is opaque to the scanner.",
                            member_display,
                        )
                    )
                    members.append(
                        ArchiveMember(member_display, info.file_size, info.compress_size, "encrypted", None, depth)
                    )
                    complete = False
                    continue
                ratio = info.file_size / max(1, info.compress_size)
                if ratio > limits.max_archive_ratio and info.file_size > 64 * 1024:
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_COMPRESSION_BOMB",
                            Severity.CRITICAL,
                            "Archive member has an excessive expansion ratio",
                            "Expansion was refused before the configured bomb threshold was exceeded.",
                            member_display,
                        )
                    )
                    complete = False
                    continue
                if info.file_size > limits.max_archive_member_bytes:
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_MEMBER_OVERSIZED",
                            Severity.HIGH,
                            "Archive member exceeds size limit",
                            "The complete member was not materialized for semantic analysis.",
                            member_display,
                        )
                    )
                    complete = False
                    continue
                expanded += info.file_size
                budget[1] += info.file_size
                if budget[1] > limits.max_archive_expanded_bytes:
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_EXPANSION_LIMIT",
                            Severity.CRITICAL,
                            "Aggregate archive expansion limit reached",
                            "Further archive expansion was stopped.",
                            member_display,
                        )
                    )
                    complete = False
                    break
                kind = "directory" if info.is_dir() else "symlink" if is_link else "special" if is_special else "file"
                payload: bytes | None = None
                digest: str | None = None
                if kind == "file":
                    try:
                        with archive.open(info, "r") as handle:
                            payload = _read_stream_bounded(handle, limits.max_archive_member_bytes)
                        if len(payload) != info.file_size:
                            raise OSError("zip member length mismatch")
                    except (OSError, RuntimeError, zipfile.BadZipFile):
                        findings.append(
                            _finding(
                                "ASSURANCE_ARCHIVE_MEMBER_READ_FAILED",
                                Severity.HIGH,
                                "Archive member could not be read safely",
                                "The member is corrupt, inconsistent, or changed during bounded reading.",
                                member_display,
                            )
                        )
                        complete = False
                        payload = None
                    if payload is not None:
                        digest = hashlib.sha256(payload).hexdigest()
                        nested_complete = _classify_payload(
                            payload,
                            member_display,
                            limits,
                            depth,
                            budget,
                            findings,
                            members,
                            text_payloads,
                            native_payloads,
                        )
                        complete = complete and nested_complete
                members.append(
                    ArchiveMember(member_display, info.file_size, info.compress_size, kind, digest, depth)
                )
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError):
        return _invalid_result(display_path, "ZIP archive is malformed or inconsistent.")
    if any(finding.rule_id in INCOMPLETE_ARCHIVE_RULES for finding in findings):
        complete = False
    return ArchiveResult(
        findings=tuple(_dedupe(findings)),
        members=tuple(members),
        text_payloads=tuple(text_payloads),
        native_payloads=tuple(native_payloads),
        expanded_bytes=expanded,
        complete=complete,
    )


def _scan_tar(
    data: bytes,
    display_path: str,
    limits: ScanLimits,
    depth: int,
    budget: list[int],
) -> ArchiveResult:
    findings: list[SecurityFinding] = []
    members: list[ArchiveMember] = []
    text_payloads: list[tuple[str, bytes]] = []
    native_payloads: list[tuple[str, bytes]] = []
    complete = True
    expanded = 0
    seen_names: set[str] = set()
    seen_casefold: dict[str, str] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            for index, info in enumerate(archive):
                if index >= limits.max_archive_members or budget[0] >= limits.max_archive_members:
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_MEMBER_LIMIT",
                            Severity.HIGH,
                            "Archive member count exceeds limit",
                            "Further TAR members were not inspected.",
                            display_path,
                        )
                    )
                    complete = False
                    break
                budget[0] += 1
                member_name = _normalized_member_name(info.name)
                member_display = f"{display_path}!/{member_name}"
                if _unsafe_member_name(info.name):
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_PATH_TRAVERSAL",
                            Severity.CRITICAL,
                            "Unsafe archive member path",
                            "The TAR member escapes or ambiguously addresses the package root.",
                            member_display,
                        )
                    )
                if member_name in seen_names:
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_DUPLICATE_MEMBER",
                            Severity.HIGH,
                            "Duplicate archive member path",
                            "Multiple TAR records resolve to one normalized path.",
                            member_display,
                        )
                    )
                seen_names.add(member_name)
                folded = member_name.casefold()
                if folded in seen_casefold and seen_casefold[folded] != member_name:
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_CASE_COLLISION",
                            Severity.HIGH,
                            "Case-colliding archive members",
                            "Different member names collide on case-insensitive filesystems.",
                            member_display,
                        )
                    )
                seen_casefold[folded] = member_name
                kind = "directory" if info.isdir() else "link" if info.issym() or info.islnk() else "special" if info.isdev() or info.isfifo() else "file"
                if kind == "link":
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_LINK",
                            Severity.HIGH,
                            "Archive contains a link entry",
                            "Links are never followed or extracted.",
                            member_display,
                        )
                    )
                    if _unsafe_member_name(info.linkname):
                        findings.append(
                            _finding(
                                "ASSURANCE_ARCHIVE_LINK_ESCAPE",
                                Severity.CRITICAL,
                                "Archive link target escapes the package",
                                "The link target is absolute or parent-relative.",
                                member_display,
                            )
                        )
                if kind == "special":
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_SPECIAL_FILE",
                            Severity.CRITICAL,
                            "Archive contains a special file",
                            "Device and FIFO members are not valid extension content.",
                            member_display,
                        )
                    )
                if info.size > limits.max_archive_member_bytes:
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_MEMBER_OVERSIZED",
                            Severity.HIGH,
                            "Archive member exceeds size limit",
                            "The complete member was not materialized.",
                            member_display,
                        )
                    )
                    complete = False
                    members.append(ArchiveMember(member_display, info.size, None, kind, None, depth))
                    continue
                expanded += max(0, info.size)
                budget[1] += max(0, info.size)
                if budget[1] > limits.max_archive_expanded_bytes:
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_EXPANSION_LIMIT",
                            Severity.CRITICAL,
                            "Aggregate archive expansion limit reached",
                            "Further TAR expansion was stopped.",
                            member_display,
                        )
                    )
                    complete = False
                    break
                payload: bytes | None = None
                digest: str | None = None
                if kind == "file":
                    handle = archive.extractfile(info)
                    if handle is None:
                        findings.append(
                            _finding(
                                "ASSURANCE_ARCHIVE_MEMBER_READ_FAILED",
                                Severity.HIGH,
                                "Archive member could not be read",
                                "The TAR member has no safe regular-file stream.",
                                member_display,
                            )
                        )
                        complete = False
                    else:
                        try:
                            payload = _read_stream_bounded(handle, limits.max_archive_member_bytes)
                            if len(payload) != info.size:
                                raise OSError("tar member length mismatch")
                        except OSError:
                            findings.append(
                                _finding(
                                    "ASSURANCE_ARCHIVE_MEMBER_READ_FAILED",
                                    Severity.HIGH,
                                    "Archive member could not be read",
                                    "The TAR member is truncated or inconsistent.",
                                    member_display,
                                )
                            )
                            complete = False
                            payload = None
                        if payload is not None:
                            digest = hashlib.sha256(payload).hexdigest()
                            nested_complete = _classify_payload(
                                payload,
                                member_display,
                                limits,
                                depth,
                                budget,
                                findings,
                                members,
                                text_payloads,
                                native_payloads,
                            )
                            complete = complete and nested_complete
                members.append(ArchiveMember(member_display, info.size, None, kind, digest, depth))
    except (tarfile.TarError, OSError, ValueError, lzma.LZMAError):
        return _invalid_result(display_path, "TAR archive is malformed or inconsistent.")
    if any(finding.rule_id in INCOMPLETE_ARCHIVE_RULES for finding in findings):
        complete = False
    return ArchiveResult(
        findings=tuple(_dedupe(findings)),
        members=tuple(members),
        text_payloads=tuple(text_payloads),
        native_payloads=tuple(native_payloads),
        expanded_bytes=expanded,
        complete=complete,
    )


def _scan_single_compressed(
    data: bytes,
    display_path: str,
    limits: ScanLimits,
    depth: int,
    budget: list[int],
    *,
    kind: str,
) -> ArchiveResult:
    try:
        payload = _bounded_stream_decompress(data, limits.max_archive_member_bytes, kind=kind)
    except (OSError, EOFError, gzip.BadGzipFile, lzma.LZMAError):
        return _invalid_result(display_path, f"{kind.upper()} stream is malformed or exceeds limits.")
    ratio = len(payload) / max(1, len(data))
    if ratio > limits.max_archive_ratio and len(payload) > 64 * 1024:
        return ArchiveResult(
            findings=(
                _finding(
                    "ASSURANCE_ARCHIVE_COMPRESSION_BOMB",
                    Severity.CRITICAL,
                    "Compressed stream has an excessive expansion ratio",
                    "The stream was bounded and rejected as a decompression bomb.",
                    display_path,
                ),
            ),
            members=(),
            text_payloads=(),
            native_payloads=(),
            expanded_bytes=len(payload),
            complete=False,
        )
    budget[0] += 1
    budget[1] += len(payload)
    member_display = f"{display_path}!/payload"
    findings: list[SecurityFinding] = []
    members: list[ArchiveMember] = []
    text_payloads: list[tuple[str, bytes]] = []
    native_payloads: list[tuple[str, bytes]] = []
    complete = _classify_payload(
        payload,
        member_display,
        limits,
        depth,
        budget,
        findings,
        members,
        text_payloads,
        native_payloads,
    )
    members.append(
        ArchiveMember(member_display, len(payload), len(data), "file", hashlib.sha256(payload).hexdigest(), depth)
    )
    return ArchiveResult(
        findings=tuple(_dedupe(findings)),
        members=tuple(members),
        text_payloads=tuple(text_payloads),
        native_payloads=tuple(native_payloads),
        expanded_bytes=len(payload),
        complete=complete,
    )


def _classify_payload(
    payload: bytes,
    display_path: str,
    limits: ScanLimits,
    depth: int,
    budget: list[int],
    findings: list[SecurityFinding],
    members: list[ArchiveMember],
    text_payloads: list[tuple[str, bytes]],
    native_payloads: list[tuple[str, bytes]],
) -> bool:
    if payload.startswith(NATIVE_MAGICS):
        native_payloads.append((display_path, payload))
        findings.append(
            _finding(
                "ASSURANCE_ARCHIVE_EMBEDDED_EXECUTABLE",
                Severity.HIGH,
                "Archive contains a native or WebAssembly executable",
                "The embedded artifact requires independent native structural analysis and policy review.",
                display_path,
            )
        )
        return True
    nested_path = Path(display_path)
    if looks_like_archive(nested_path, payload[:8]):
        nested = scan_archive_bytes(
            payload,
            display_path,
            limits,
            depth=depth + 1,
            budget=budget,
        )
        findings.extend(nested.findings)
        members.extend(nested.members)
        text_payloads.extend(nested.text_payloads)
        native_payloads.extend(nested.native_payloads)
        return nested.complete
    if _looks_text(payload, nested_path.suffix.lower()):
        text_payloads.append((display_path, payload[: limits.max_text_bytes]))
        return len(payload) <= limits.max_text_bytes
    return True


def _read_stream_bounded(handle: BinaryIO, limit: int) -> bytes:
    output = bytearray()
    while len(output) <= limit:
        chunk = handle.read(min(64 * 1024, limit + 1 - len(output)))
        if not chunk:
            break
        output.extend(chunk)
    if len(output) > limit:
        raise OSError("stream exceeds limit")
    return bytes(output)


def _bounded_stream_decompress(data: bytes, limit: int, *, kind: str) -> bytes:
    handle: BinaryIO
    if kind == "gzip":
        handle = gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb")
    else:
        handle = lzma.LZMAFile(io.BytesIO(data), mode="rb")
    with handle:
        return _read_stream_bounded(handle, limit)


def _looks_like_tar_stream(data: bytes, *, compressed: str) -> bool:
    try:
        payload = _bounded_stream_decompress(data, 1024 * 1024, kind=compressed)
    except (OSError, EOFError, gzip.BadGzipFile, lzma.LZMAError):
        return False
    return len(payload) >= 512 and payload[257:262] in {b"ustar", b"ustar\x00"}


def _normalized_member_name(name: str) -> str:
    normalized = posixpath.normpath(name.replace("\\", "/"))
    return unicodedata.normalize("NFC", normalized.removeprefix("./"))


def _unsafe_member_name(name: str) -> bool:
    if "\x00" in name:
        return True
    normalized = name.replace("\\", "/")
    if normalized.startswith(("/", "//")):
        return True
    if len(normalized) >= 2 and normalized[1] == ":" and normalized[0].isalpha():
        return True
    canonical = posixpath.normpath(normalized)
    return canonical == ".." or canonical.startswith("../")


def _looks_text(payload: bytes, suffix: str) -> bool:
    if suffix in {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".md",
        ".txt",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".rb",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".c",
        ".cc",
        ".cpp",
        ".h",
        ".hpp",
    }:
        return True
    sample = payload[:8192]
    if not sample or b"\x00" in sample:
        return False
    decoded = sample.decode("utf-8", errors="replace")
    replacements = decoded.count("\ufffd")
    return replacements <= max(2, len(decoded) // 100)


def _invalid_result(display_path: str, description: str) -> ArchiveResult:
    return ArchiveResult(
        findings=(
            _finding(
                "ASSURANCE_ARCHIVE_INVALID",
                Severity.HIGH,
                "Archive is malformed or unsupported",
                description,
                display_path,
            ),
        ),
        members=(),
        text_payloads=(),
        native_payloads=(),
        expanded_bytes=0,
        complete=False,
    )


def _finding(
    rule_id: str,
    severity: Severity,
    title: str,
    description: str,
    path: str,
) -> SecurityFinding:
    return SecurityFinding(
        rule_id=rule_id,
        severity=severity,
        confidence=Confidence.HIGH,
        category="archive-security",
        title=title,
        description=description,
        remediation="Reject unsafe archives or rebuild them with normalized regular-file entries and strict size bounds.",
        locations=(EvidenceLocation(path=path),),
        metadata={},
    ).with_fingerprint()


def _dedupe(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    return list({finding.fingerprint: finding for finding in findings}.values())
