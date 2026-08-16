"""Safe in-memory archive inspection with expansion and traversal defenses."""

from __future__ import annotations

import hashlib
import io
import os
import posixpath
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .limits import ScanLimits
from .models import Confidence, EvidenceLocation, SecurityFinding, Severity


ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
ARCHIVE_SUFFIXES = (
    ".zip",
    ".whl",
    ".jar",
    ".nupkg",
    ".vsix",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
)
NATIVE_MAGICS = (
    b"\x7fELF",
    b"MZ",
    b"\x00asm",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
)


@dataclass(frozen=True, slots=True)
class ArchiveMember:
    archive_path: str
    member_path: str
    compressed_size: int
    uncompressed_size: int
    sha256: str | None
    kind: str
    depth: int


@dataclass(frozen=True, slots=True)
class ArchiveResult:
    findings: tuple[SecurityFinding, ...]
    members: tuple[ArchiveMember, ...]
    native_payloads: tuple[tuple[str, bytes], ...]
    text_payloads: tuple[tuple[str, bytes], ...]
    expanded_bytes: int
    complete: bool


def looks_like_archive(path: Path, prefix: bytes) -> bool:
    lowered = path.name.lower()
    return prefix.startswith(ZIP_MAGIC) or any(lowered.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)


def scan_archive_file(path: Path, relative_path: str, limits: ScanLimits) -> ArchiveResult:
    try:
        data = path.read_bytes()
    except OSError:
        return ArchiveResult(
            findings=(
                _finding(
                    "ASSURANCE_ARCHIVE_READ_FAILED",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    "archive",
                    "Archive could not be read",
                    "The archive became unreadable during analysis.",
                    "Rescan a stable artifact and investigate filesystem integrity.",
                    relative_path,
                ),
            ),
            members=(),
            native_payloads=(),
            text_payloads=(),
            expanded_bytes=0,
            complete=False,
        )
    if len(data) > limits.max_archive_bytes:
        return ArchiveResult(
            findings=(
                _finding(
                    "ASSURANCE_ARCHIVE_FILE_OVERSIZED",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "archive",
                    "Archive exceeds analysis limit",
                    "The compressed archive exceeds the configured bounded-analysis limit.",
                    "Reduce the artifact or raise the managed limit only after capacity review.",
                    relative_path,
                    {"size": len(data), "limit": limits.max_archive_bytes},
                ),
            ),
            members=(),
            native_payloads=(),
            text_payloads=(),
            expanded_bytes=0,
            complete=False,
        )
    return scan_archive_bytes(data, relative_path, limits, depth=0, budget=[0, 0])


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
                    Confidence.HIGH,
                    "archive",
                    "Nested archive depth limit reached",
                    "The archive contains more nesting than the scanner is configured to inspect.",
                    "Flatten the artifact or review nested payloads independently.",
                    display_path,
                    {"depth": depth, "limit": limits.max_archive_depth},
                ),
            ),
            members=(),
            native_payloads=(),
            text_payloads=(),
            expanded_bytes=0,
            complete=False,
        )
    if data.startswith(ZIP_MAGIC):
        return _scan_zip(data, display_path, limits, depth=depth, budget=budget)
    try:
        return _scan_tar(data, display_path, limits, depth=depth, budget=budget)
    except tarfile.ReadError:
        return ArchiveResult(
            findings=(
                _finding(
                    "ASSURANCE_ARCHIVE_INVALID",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    "archive",
                    "Archive format is invalid or unsupported",
                    "The file is archive-shaped but cannot be parsed safely.",
                    "Rebuild the artifact using a supported deterministic archive format.",
                    display_path,
                ),
            ),
            members=(),
            native_payloads=(),
            text_payloads=(),
            expanded_bytes=0,
            complete=False,
        )


def _scan_zip(
    data: bytes,
    display_path: str,
    limits: ScanLimits,
    *,
    depth: int,
    budget: list[int],
) -> ArchiveResult:
    findings: list[SecurityFinding] = []
    members: list[ArchiveMember] = []
    native_payloads: list[tuple[str, bytes]] = []
    text_payloads: list[tuple[str, bytes]] = []
    complete = True
    expanded = 0
    seen_exact: set[str] = set()
    seen_case: dict[str, str] = {}

    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError) as exc:
        return ArchiveResult(
            findings=(
                _finding(
                    "ASSURANCE_ARCHIVE_INVALID",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    "archive",
                    "ZIP archive is invalid",
                    "The ZIP central directory or member metadata is invalid.",
                    "Rebuild the archive and verify its digest before distribution.",
                    display_path,
                    {"error": type(exc).__name__},
                ),
            ),
            members=(),
            native_payloads=(),
            text_payloads=(),
            expanded_bytes=0,
            complete=False,
        )

    with archive:
        infos = archive.infolist()
        if len(infos) > limits.max_archive_members:
            findings.append(
                _finding(
                    "ASSURANCE_ARCHIVE_MEMBER_LIMIT",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "archive",
                    "Archive member limit exceeded",
                    "The archive declares more members than can be inspected safely.",
                    "Split the artifact and review why it contains so many entries.",
                    display_path,
                    {"members": len(infos), "limit": limits.max_archive_members},
                )
            )
            infos = infos[: limits.max_archive_members]
            complete = False

        for info in infos:
            budget[0] += 1
            if budget[0] > limits.max_archive_members:
                complete = False
                break
            member_name = info.filename
            issue = _unsafe_member_name(member_name)
            if issue:
                findings.append(
                    _finding(
                        "ASSURANCE_ARCHIVE_PATH_TRAVERSAL",
                        Severity.CRITICAL,
                        Confidence.HIGH,
                        "archive",
                        "Unsafe archive member path",
                        issue,
                        "Reject absolute paths, drive prefixes, NULs, and parent traversal before extraction.",
                        f"{display_path}!/{member_name}",
                    )
                )
            normalized = _normalized_member_name(member_name)
            if normalized in seen_exact:
                findings.append(
                    _finding(
                        "ASSURANCE_ARCHIVE_DUPLICATE_MEMBER",
                        Severity.HIGH,
                        Confidence.HIGH,
                        "archive",
                        "Duplicate archive member",
                        "The archive contains multiple entries with the same normalized path.",
                        "Reject duplicate paths to prevent parser and installer confusion.",
                        f"{display_path}!/{member_name}",
                    )
                )
            seen_exact.add(normalized)
            folded = normalized.casefold()
            previous = seen_case.get(folded)
            if previous is not None and previous != normalized:
                findings.append(
                    _finding(
                        "ASSURANCE_ARCHIVE_CASE_COLLISION",
                        Severity.HIGH,
                        Confidence.HIGH,
                        "archive",
                        "Case-colliding archive members",
                        "Two archive entries collide on case-insensitive filesystems.",
                        "Require unique case-folded paths before installation.",
                        f"{display_path}!/{member_name}",
                        {"collides_with": previous},
                    )
                )
            seen_case[folded] = normalized

            unix_mode = (info.external_attr >> 16) & 0xFFFF
            is_link = stat.S_ISLNK(unix_mode)
            is_special = unix_mode and not (
                stat.S_ISREG(unix_mode) or stat.S_ISDIR(unix_mode) or is_link
            )
            if is_link:
                findings.append(
                    _finding(
                        "ASSURANCE_ARCHIVE_SYMLINK",
                        Severity.HIGH,
                        Confidence.HIGH,
                        "archive",
                        "Archive contains a symbolic link",
                        "Symbolic links can redirect later writes outside the installation root.",
                        "Reject links in consumer extension archives.",
                        f"{display_path}!/{member_name}",
                    )
                )
            if is_special:
                findings.append(
                    _finding(
                        "ASSURANCE_ARCHIVE_SPECIAL_FILE",
                        Severity.CRITICAL,
                        Confidence.HIGH,
                        "archive",
                        "Archive contains a special file",
                        "Device, FIFO, socket, and other special entries are unsafe in extension archives.",
                        "Reject the artifact and distribute regular files and directories only.",
                        f"{display_path}!/{member_name}",
                    )
                )
            if info.flag_bits & 0x1:
                findings.append(
                    _finding(
                        "ASSURANCE_ARCHIVE_ENCRYPTED_MEMBER",
                        Severity.HIGH,
                        Confidence.HIGH,
                        "archive",
                        "Encrypted archive member is opaque",
                        "Encrypted content cannot be statically inspected.",
                        "Distribute reviewable plaintext archive members over an authenticated channel.",
                        f"{display_path}!/{member_name}",
                    )
                )
                complete = False
            ratio = info.file_size / max(1, info.compress_size)
            if ratio > limits.max_archive_ratio:
                findings.append(
                    _finding(
                        "ASSURANCE_ARCHIVE_COMPRESSION_BOMB",
                        Severity.CRITICAL,
                        Confidence.HIGH,
                        "archive",
                        "Suspicious archive expansion ratio",
                        "A member expands far beyond its compressed representation.",
                        "Reject high-ratio members and enforce aggregate expansion budgets.",
                        f"{display_path}!/{member_name}",
                        {"ratio": round(ratio, 2), "limit": limits.max_archive_ratio},
                    )
                )
                complete = False
            if info.file_size > limits.max_archive_member_bytes:
                findings.append(
                    _finding(
                        "ASSURANCE_ARCHIVE_MEMBER_OVERSIZED",
                        Severity.HIGH,
                        Confidence.HIGH,
                        "archive",
                        "Archive member exceeds analysis limit",
                        "The member is too large for bounded in-memory analysis.",
                        "Review the member independently or reduce its size.",
                        f"{display_path}!/{member_name}",
                        {"size": info.file_size, "limit": limits.max_archive_member_bytes},
                    )
                )
                complete = False

            kind = "directory" if info.is_dir() else "symlink" if is_link else "special" if is_special else "file"
            member_digest: str | None = None
            payload: bytes | None = None
            if (
                kind == "file"
                and not (info.flag_bits & 0x1)
                and info.file_size <= limits.max_archive_member_bytes
                and ratio <= limits.max_archive_ratio
                and budget[1] + info.file_size <= limits.max_archive_expanded_bytes
            ):
                try:
                    payload = _read_zip_member_bounded(archive, info, limits.max_archive_member_bytes)
                except (OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_MEMBER_READ_FAILED",
                            Severity.MEDIUM,
                            Confidence.HIGH,
                            "archive",
                            "Archive member could not be read",
                            "Member decompression failed or violated a bound.",
                            "Rebuild the archive and scan a stable artifact.",
                            f"{display_path}!/{member_name}",
                        )
                    )
                    complete = False
                else:
                    member_digest = hashlib.sha256(payload).hexdigest()
                    expanded += len(payload)
                    budget[1] += len(payload)
                    _classify_payload(
                        payload,
                        f"{display_path}!/{member_name}",
                        limits,
                        depth,
                        budget,
                        findings,
                        members,
                        native_payloads,
                        text_payloads,
                    )
            elif kind == "file" and budget[1] + info.file_size > limits.max_archive_expanded_bytes:
                findings.append(
                    _finding(
                        "ASSURANCE_ARCHIVE_EXPANSION_LIMIT",
                        Severity.CRITICAL,
                        Confidence.HIGH,
                        "archive",
                        "Aggregate archive expansion limit reached",
                        "Continuing decompression would exceed the managed resource budget.",
                        "Reject or split the archive after investigating its expansion behavior.",
                        f"{display_path}!/{member_name}",
                    )
                )
                complete = False

            members.append(
                ArchiveMember(
                    archive_path=display_path,
                    member_path=member_name,
                    compressed_size=info.compress_size,
                    uncompressed_size=info.file_size,
                    sha256=member_digest,
                    kind=kind,
                    depth=depth,
                )
            )

    return ArchiveResult(
        findings=tuple(_dedupe(findings)),
        members=tuple(members),
        native_payloads=tuple(native_payloads),
        text_payloads=tuple(text_payloads),
        expanded_bytes=expanded,
        complete=complete,
    )


def _scan_tar(
    data: bytes,
    display_path: str,
    limits: ScanLimits,
    *,
    depth: int,
    budget: list[int],
) -> ArchiveResult:
    findings: list[SecurityFinding] = []
    members: list[ArchiveMember] = []
    native_payloads: list[tuple[str, bytes]] = []
    text_payloads: list[tuple[str, bytes]] = []
    complete = True
    expanded = 0
    seen_exact: set[str] = set()
    seen_case: dict[str, str] = {}

    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for index, info in enumerate(archive):
            budget[0] += 1
            if index >= limits.max_archive_members or budget[0] > limits.max_archive_members:
                findings.append(
                    _finding(
                        "ASSURANCE_ARCHIVE_MEMBER_LIMIT",
                        Severity.HIGH,
                        Confidence.HIGH,
                        "archive",
                        "Archive member limit exceeded",
                        "The TAR archive contains more members than the scanner can safely inspect.",
                        "Split the artifact and inspect each component independently.",
                        display_path,
                    )
                )
                complete = False
                break
            member_name = info.name
            issue = _unsafe_member_name(member_name)
            if issue:
                findings.append(
                    _finding(
                        "ASSURANCE_ARCHIVE_PATH_TRAVERSAL",
                        Severity.CRITICAL,
                        Confidence.HIGH,
                        "archive",
                        "Unsafe archive member path",
                        issue,
                        "Reject unsafe member paths before extraction.",
                        f"{display_path}!/{member_name}",
                    )
                )
            normalized = _normalized_member_name(member_name)
            if normalized in seen_exact:
                findings.append(
                    _finding(
                        "ASSURANCE_ARCHIVE_DUPLICATE_MEMBER",
                        Severity.HIGH,
                        Confidence.HIGH,
                        "archive",
                        "Duplicate archive member",
                        "The TAR archive contains a duplicate normalized path.",
                        "Reject duplicate archive member paths.",
                        f"{display_path}!/{member_name}",
                    )
                )
            seen_exact.add(normalized)
            folded = normalized.casefold()
            if folded in seen_case and seen_case[folded] != normalized:
                findings.append(
                    _finding(
                        "ASSURANCE_ARCHIVE_CASE_COLLISION",
                        Severity.HIGH,
                        Confidence.HIGH,
                        "archive",
                        "Case-colliding archive members",
                        "Entries collide on case-insensitive filesystems.",
                        "Require unique case-folded member names.",
                        f"{display_path}!/{member_name}",
                    )
                )
            seen_case[folded] = normalized

            if info.issym() or info.islnk():
                findings.append(
                    _finding(
                        "ASSURANCE_ARCHIVE_LINK",
                        Severity.HIGH,
                        Confidence.HIGH,
                        "archive",
                        "Archive contains a link",
                        "Symbolic and hard links can redirect writes outside the installation root.",
                        "Reject links in extension archives.",
                        f"{display_path}!/{member_name}",
                        {"target": info.linkname},
                    )
                )
            if info.isdev() or info.isfifo():
                findings.append(
                    _finding(
                        "ASSURANCE_ARCHIVE_SPECIAL_FILE",
                        Severity.CRITICAL,
                        Confidence.HIGH,
                        "archive",
                        "Archive contains a special file",
                        "Device or FIFO entries are not valid extension content.",
                        "Reject the artifact.",
                        f"{display_path}!/{member_name}",
                    )
                )
            kind = (
                "directory"
                if info.isdir()
                else "link"
                if info.issym() or info.islnk()
                else "special"
                if info.isdev() or info.isfifo()
                else "file"
            )
            payload: bytes | None = None
            member_digest: str | None = None
            if kind == "file" and info.size <= limits.max_archive_member_bytes:
                if budget[1] + info.size > limits.max_archive_expanded_bytes:
                    findings.append(
                        _finding(
                            "ASSURANCE_ARCHIVE_EXPANSION_LIMIT",
                            Severity.CRITICAL,
                            Confidence.HIGH,
                            "archive",
                            "Aggregate archive expansion limit reached",
                            "Continuing member reads would exceed the managed resource budget.",
                            "Reject or split the archive.",
                            f"{display_path}!/{member_name}",
                        )
                    )
                    complete = False
                else:
                    extracted = archive.extractfile(info)
                    if extracted is not None:
                        try:
                            payload = _read_stream_bounded(extracted, limits.max_archive_member_bytes)
                        finally:
                            extracted.close()
                        member_digest = hashlib.sha256(payload).hexdigest()
                        expanded += len(payload)
                        budget[1] += len(payload)
                        _classify_payload(
                            payload,
                            f"{display_path}!/{member_name}",
                            limits,
                            depth,
                            budget,
                            findings,
                            members,
                            native_payloads,
                            text_payloads,
                        )
            elif kind == "file":
                findings.append(
                    _finding(
                        "ASSURANCE_ARCHIVE_MEMBER_OVERSIZED",
                        Severity.HIGH,
                        Confidence.HIGH,
                        "archive",
                        "Archive member exceeds analysis limit",
                        "The member is too large for bounded analysis.",
                        "Review the member independently or reduce its size.",
                        f"{display_path}!/{member_name}",
                    )
                )
                complete = False
            members.append(
                ArchiveMember(
                    archive_path=display_path,
                    member_path=member_name,
                    compressed_size=max(0, info.size),
                    uncompressed_size=max(0, info.size),
                    sha256=member_digest,
                    kind=kind,
                    depth=depth,
                )
            )

    return ArchiveResult(
        findings=tuple(_dedupe(findings)),
        members=tuple(members),
        native_payloads=tuple(native_payloads),
        text_payloads=tuple(text_payloads),
        expanded_bytes=expanded,
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
    native_payloads: list[tuple[str, bytes]],
    text_payloads: list[tuple[str, bytes]],
) -> None:
    prefix = payload[:16]
    if any(prefix.startswith(magic) for magic in NATIVE_MAGICS):
        native_payloads.append((display_path, payload))
    if _is_probably_text(payload):
        text_payloads.append((display_path, payload[: limits.max_text_bytes]))
    if looks_like_archive(Path(display_path), prefix):
        nested = scan_archive_bytes(payload, display_path, limits, depth=depth + 1, budget=budget)
        findings.extend(nested.findings)
        members.extend(nested.members)
        native_payloads.extend(nested.native_payloads)
        text_payloads.extend(nested.text_payloads)


def _read_zip_member_bounded(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int) -> bytes:
    with archive.open(info, "r") as handle:
        return _read_stream_bounded(handle, limit)


def _read_stream_bounded(handle: object, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = handle.read(min(1024 * 1024, limit + 1 - total))  # type: ignore[attr-defined]
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise RuntimeError("decompressed member exceeded limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _unsafe_member_name(name: str) -> str | None:
    if "\x00" in name:
        return "Archive member contains a NUL byte."
    normalized_slashes = name.replace("\\", "/")
    if normalized_slashes.startswith("/") or normalized_slashes.startswith("//"):
        return "Archive member uses an absolute path."
    if len(normalized_slashes) >= 2 and normalized_slashes[1] == ":":
        return "Archive member uses a Windows drive prefix."
    parts = PurePosixPath(normalized_slashes).parts
    if any(part == ".." for part in parts):
        return "Archive member contains parent traversal."
    normalized = posixpath.normpath(normalized_slashes)
    if normalized == ".." or normalized.startswith("../"):
        return "Archive member escapes the installation root."
    return None


def _normalized_member_name(name: str) -> str:
    normalized = posixpath.normpath(name.replace("\\", "/"))
    return normalized.removeprefix("./")


def _is_probably_text(payload: bytes) -> bool:
    sample = payload[:8192]
    if not sample:
        return False
    if b"\x00" in sample:
        return False
    printable = sum(byte in b"\t\n\r" or 32 <= byte <= 126 for byte in sample)
    return printable / len(sample) >= 0.85


def _finding(
    rule_id: str,
    severity: Severity,
    confidence: Confidence,
    category: str,
    title: str,
    description: str,
    remediation: str,
    path: str,
    metadata: dict[str, object] | None = None,
) -> SecurityFinding:
    return SecurityFinding(
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        category=category,
        title=title,
        description=description,
        remediation=remediation,
        locations=(EvidenceLocation(path=path),),
        metadata=metadata or {},
    ).with_fingerprint()


def _dedupe(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    return list({finding.fingerprint: finding for finding in findings}.values())
