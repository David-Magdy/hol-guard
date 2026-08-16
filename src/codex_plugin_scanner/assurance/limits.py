"""Resource limits shared by assurance analyzers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScanLimits:
    max_files: int = 20_000
    max_total_bytes: int = 1_073_741_824
    max_file_bytes: int = 64 * 1024 * 1024
    max_text_bytes: int = 4 * 1024 * 1024
    max_archive_bytes: int = 256 * 1024 * 1024
    max_archive_members: int = 20_000
    max_archive_member_bytes: int = 64 * 1024 * 1024
    max_archive_expanded_bytes: int = 512 * 1024 * 1024
    max_archive_ratio: float = 250.0
    max_archive_depth: int = 4
    max_native_strings: int = 10_000
    max_native_string_bytes: int = 8 * 1024 * 1024
    max_json_depth: int = 64
    max_findings: int = 10_000
    rust_timeout_seconds: float = 15.0
    osv_timeout_seconds: float = 8.0
    detonation_timeout_seconds: int = 30

    def validate(self) -> None:
        integer_fields = (
            self.max_files,
            self.max_total_bytes,
            self.max_file_bytes,
            self.max_text_bytes,
            self.max_archive_bytes,
            self.max_archive_members,
            self.max_archive_member_bytes,
            self.max_archive_expanded_bytes,
            self.max_archive_depth,
            self.max_native_strings,
            self.max_native_string_bytes,
            self.max_json_depth,
            self.max_findings,
            self.detonation_timeout_seconds,
        )
        if any(value <= 0 for value in integer_fields):
            raise ValueError("all scanner limits must be positive")
        if self.max_archive_ratio < 1.0:
            raise ValueError("max_archive_ratio must be at least 1")
        if self.rust_timeout_seconds <= 0 or self.osv_timeout_seconds <= 0:
            raise ValueError("scanner timeouts must be positive")
