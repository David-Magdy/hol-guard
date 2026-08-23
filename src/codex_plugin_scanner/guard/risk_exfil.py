"""High-confidence exfiltration intent signals."""

from __future__ import annotations

import re

from .types import GuardSignal

_RULE_VERSION = "guard-risk-v2"
_EXPLICIT_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bexfiltrat(?:e|es|ed|ing|ion)\b", "explicit exfiltration intent"),
    (r"(gist\.github\.com|pastebin\.com|transfer\.sh|webhook)", "external sink destination"),
    (r"scp\s+", "scp transfer intent"),
)
_TRANSFER_VERB = re.compile(r"\b(?:upload|send|post|sync)\b")
_SECRET_SOURCE = re.compile(
    "".join(
        (
            r"(?:\.env\b|\.npmrc\b|\.pypirc\b|\.ssh/|\.aws/credentials\b|\.kube/config\b|",
            r"\b(?:api[_-]?key|auth[_-]?token|access[_-]?token|credential|password|private[_-]?key|secret)\b)",
        )
    )
)
_NETWORK_SINK = re.compile(r"(?:https?://|\b(?:curl|wget|scp)\b|gist\.github\.com|pastebin\.com|transfer\.sh|webhook)")


def detect_exfil_intent(text: str) -> list[GuardSignal]:
    """Detect explicit sinks or a sensitive source-to-network transfer."""

    patterns = list(_EXPLICIT_PATTERNS)
    if _TRANSFER_VERB.search(text) and _SECRET_SOURCE.search(text) and _NETWORK_SINK.search(text):
        patterns.append((_TRANSFER_VERB.pattern, "sensitive transfer intent"))
    return [
        GuardSignal(
            signal_id=f"network:exfil:{reason.replace(' ', '-')}",
            family="network",
            severity=8,
            confidence=0.79,
            evidence_source="artifact",
            matched_text=reason,
            explanation="includes exfiltration-oriented intent",
            remediation="Confirm destination and data class before allowing transfer.",
            rule_version=_RULE_VERSION,
        )
        for pattern, reason in patterns
        if re.search(pattern, text)
    ]
