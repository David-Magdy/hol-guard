# pyright: basic
"""Central resource limits for extension assurance."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScanLimits:
    max_files: int = 100_000
    max_total_bytes: int = 4 * 1024 * 1024 * 1024
    max_file_bytes: int = 64 * 1024 * 1024
    max_text_bytes: int = 4 * 1024 * 1024
    max_findings: int = 100_000
    max_manifest_bytes: int = 4 * 1024 * 1024
    max_archive_bytes: int = 512 * 1024 * 1024
    max_archive_members: int = 100_000
    max_archive_member_bytes: int = 128 * 1024 * 1024
    max_archive_expanded_bytes: int = 2 * 1024 * 1024 * 1024
    max_archive_ratio: float = 200.0
    max_archive_depth: int = 4
    max_native_strings: int = 20_000
    native_timeout_seconds: float = 20.0
    max_osv_queries: int = 1_000
    osv_timeout_seconds: float = 10.0
    max_osv_response_bytes: int = 8 * 1024 * 1024

    def validate(self) -> None:
        integer_limits = {
            "max_files": self.max_files,
            "max_total_bytes": self.max_total_bytes,
            "max_file_bytes": self.max_file_bytes,
            "max_text_bytes": self.max_text_bytes,
            "max_findings": self.max_findings,
            "max_manifest_bytes": self.max_manifest_bytes,
            "max_archive_bytes": self.max_archive_bytes,
            "max_archive_members": self.max_archive_members,
            "max_archive_member_bytes": self.max_archive_member_bytes,
            "max_archive_expanded_bytes": self.max_archive_expanded_bytes,
            "max_native_strings": self.max_native_strings,
            "max_osv_queries": self.max_osv_queries,
            "max_osv_response_bytes": self.max_osv_response_bytes,
        }
        for name, value in integer_limits.items():
            if isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_files > 10_000_000:
            raise ValueError("max_files exceeds hard safety ceiling")
        if self.max_total_bytes > 64 * 1024 * 1024 * 1024:
            raise ValueError("max_total_bytes exceeds hard safety ceiling")
        if self.max_file_bytes > self.max_total_bytes:
            raise ValueError("max_file_bytes cannot exceed max_total_bytes")
        if self.max_text_bytes > self.max_file_bytes:
            raise ValueError("max_text_bytes cannot exceed max_file_bytes")
        if self.max_archive_member_bytes > self.max_archive_expanded_bytes:
            raise ValueError("max_archive_member_bytes cannot exceed aggregate expansion limit")
        if self.max_archive_depth < 0 or self.max_archive_depth > 16:
            raise ValueError("max_archive_depth must be between 0 and 16")
        if self.max_archive_ratio <= 1.0 or self.max_archive_ratio > 100_000.0:
            raise ValueError("max_archive_ratio is outside the allowed range")
        if self.native_timeout_seconds <= 0 or self.native_timeout_seconds > 600:
            raise ValueError("native_timeout_seconds is outside the allowed range")
        if self.osv_timeout_seconds <= 0 or self.osv_timeout_seconds > 120:
            raise ValueError("osv_timeout_seconds is outside the allowed range")
