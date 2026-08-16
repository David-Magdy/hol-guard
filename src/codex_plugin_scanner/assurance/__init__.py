"""High-assurance extension scanning and evidence ingestion.

The assurance package layers bounded static analysis, optional Rust-native parsing,
provenance, drift, managed policy, and sandbox planning on top of the existing
plugin scanner.  It never treats a clean static result as proof of safety.
"""

from .models import (
    AssuranceDecision,
    AssuranceLevel,
    AssuranceReport,
    CoverageState,
    Disposition,
    EvidenceLayer,
    SecurityFinding,
)
from .orchestrator import AssuranceOptions, scan_extension_assurance

__all__ = [
    "AssuranceDecision",
    "AssuranceLevel",
    "AssuranceOptions",
    "AssuranceReport",
    "CoverageState",
    "Disposition",
    "EvidenceLayer",
    "SecurityFinding",
    "scan_extension_assurance",
]
