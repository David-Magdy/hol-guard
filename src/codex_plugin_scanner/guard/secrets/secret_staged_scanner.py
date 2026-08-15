"""Bounded leaked-secret scanning for the Git staging index."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .git_subprocess import run_git
from .secret_detection import SecretFinding, SecretScanSource
from .secret_repository_scanner import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_FINDINGS,
    DEFAULT_MAX_TOTAL_BYTES,
    RepositorySecretScanResult,
    _bounded_positive,
    _scan_blob,
)


def _git_repository_root(root: Path) -> Path | None:
    try:
        result = run_git(root, ["rev-parse", "--show-toplevel"])
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    raw = os.fsdecode(result.stdout).strip()
    if not raw:
        return None
    resolved = Path(raw).resolve()
    return resolved if resolved.exists() and resolved.is_dir() else None


def _git_staged_paths(root: Path) -> list[str] | None:
    try:
        result = run_git(
            root,
            ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z", "--"],
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return [os.fsdecode(item) for item in result.stdout.split(b"\0") if item]


def _git_staged_blob(root: Path, path: str, max_file_bytes: int) -> tuple[bytes | None, str | None]:
    spec = f":{path}"
    try:
        size_result = run_git(root, ["cat-file", "-s", spec])
    except (OSError, subprocess.SubprocessError):
        return None, "git_staged_blob_unavailable"
    if size_result.returncode != 0:
        return None, "git_staged_blob_unavailable"
    try:
        size = int(size_result.stdout.strip())
    except ValueError:
        return None, "git_staged_blob_unavailable"
    if size < 0:
        return None, "git_staged_blob_unavailable"
    if size > max_file_bytes:
        return None, "max_file_bytes"
    try:
        blob_result = run_git(root, ["cat-file", "blob", spec])
    except (OSError, subprocess.SubprocessError):
        return None, "git_staged_blob_unavailable"
    if blob_result.returncode != 0:
        return None, "git_staged_blob_unavailable"
    if len(blob_result.stdout) > max_file_bytes:
        return None, "max_file_bytes"
    return blob_result.stdout, None


def scan_staged_secrets(
    target: Path,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_findings: int = DEFAULT_MAX_FINDINGS,
) -> RepositorySecretScanResult:
    """Scan only content currently staged in a Git index.

    The working tree is never read for candidate content. This makes the result
    suitable for pre-commit enforcement even when unstaged edits differ from the
    index that will actually be committed.
    """

    requested_root = target.expanduser().resolve()
    if not requested_root.exists() or not requested_root.is_dir():
        raise ValueError("staged secret scan target must be an existing directory")
    root = _git_repository_root(requested_root)
    if root is None:
        return RepositorySecretScanResult(
            findings=(),
            files_scanned=0,
            commits_scanned=0,
            bytes_scanned=0,
            history_enabled=False,
            truncated=True,
            errors=("git_staged_enumeration_failed",),
            truncation_reasons=(),
        )

    max_files = _bounded_positive(max_files, default=DEFAULT_MAX_FILES, maximum=100_000)
    max_file_bytes = _bounded_positive(
        max_file_bytes,
        default=DEFAULT_MAX_FILE_BYTES,
        maximum=32 * 1024 * 1024,
    )
    max_total_bytes = _bounded_positive(
        max_total_bytes,
        default=DEFAULT_MAX_TOTAL_BYTES,
        maximum=4 * 1024 * 1024 * 1024,
    )
    max_findings = _bounded_positive(max_findings, default=DEFAULT_MAX_FINDINGS, maximum=10_000)

    paths = _git_staged_paths(root)
    if paths is None:
        return RepositorySecretScanResult(
            findings=(),
            files_scanned=0,
            commits_scanned=0,
            bytes_scanned=0,
            history_enabled=False,
            truncated=True,
            errors=("git_staged_enumeration_failed",),
            truncation_reasons=(),
        )

    findings: list[SecretFinding] = []
    errors: set[str] = set()
    truncation_reasons: set[str] = set()
    files_scanned = 0
    bytes_scanned = 0
    truncated = False
    staged_source: SecretScanSource = "staged"
    for relative_path in paths:
        if files_scanned >= max_files:
            truncation_reasons.add("max_files")
            truncated = True
            break
        if bytes_scanned >= max_total_bytes:
            truncation_reasons.add("max_total_bytes")
            truncated = True
            break
        if len(findings) >= max_findings:
            truncation_reasons.add("max_findings")
            truncated = True
            break
        data, unavailable_reason = _git_staged_blob(root, relative_path, max_file_bytes)
        if unavailable_reason is not None:
            truncated = True
            if unavailable_reason.startswith("max_"):
                truncation_reasons.add(unavailable_reason)
            else:
                errors.add(unavailable_reason)
            continue
        if data is None:
            continue
        if bytes_scanned + len(data) > max_total_bytes:
            truncation_reasons.add("max_total_bytes")
            truncated = True
            break
        found, scanned_bytes = _scan_blob(
            data,
            path=relative_path.replace("\\", "/"),
            source=staged_source,
            commit=None,
            finding_budget=max_findings - len(findings),
        )
        files_scanned += 1
        bytes_scanned += scanned_bytes
        findings.extend(found)
        if len(findings) >= max_findings:
            truncation_reasons.add("max_findings")
            truncated = True
            break

    deduped: dict[tuple[str, int, str], SecretFinding] = {}
    for finding in findings:
        key = (finding.path, finding.line, finding.candidate)
        existing = deduped.get(key)
        if existing is None or finding.confidence_score > existing.confidence_score:
            deduped[key] = finding
    ordered = tuple(sorted(deduped.values(), key=lambda item: (item.path, item.line, item.rule_id))[:max_findings])
    if len(deduped) > len(ordered):
        truncation_reasons.add("max_findings")
        truncated = True

    order = ("max_files", "max_file_bytes", "max_total_bytes", "max_findings")
    return RepositorySecretScanResult(
        findings=ordered,
        files_scanned=files_scanned,
        commits_scanned=0,
        bytes_scanned=bytes_scanned,
        history_enabled=False,
        truncated=truncated,
        errors=tuple(sorted(errors)),
        truncation_reasons=tuple(reason for reason in order if reason in truncation_reasons),
    )


__all__ = ["scan_staged_secrets"]
