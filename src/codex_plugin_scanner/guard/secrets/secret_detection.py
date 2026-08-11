"""Context-aware leaked-secret detection for HOL Guard.

The runtime in this module is deliberately local, deterministic, and dependency-free.
It combines strong provider formats with contextual scoring for generic credentials,
entropy/rarity signals, and conservative sample suppression.

Security invariants:
- public finding payloads never contain the raw candidate secret;
- fingerprints are HMACs and require an explicit caller-owned key;
- no network or LLM call is made by detection;
- generic findings require contextual evidence and are suppressed in obvious
  documentation/test fixtures unless the candidate has a strong provider format.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Literal, TypedDict

SecretSeverity = Literal["medium", "high", "critical"]
SecretConfidence = Literal["low", "medium", "high"]
SecretScanSource = Literal["working_tree", "git_history", "text", "staged"]
SecretValidationKind = Literal[
    "none",
    "github",
    "gitlab",
    "aws",
    "slack",
    "stripe",
    "openai",
    "anthropic",
    "huggingface",
    "npm",
    "pypi",
    "google",
    "sendgrid",
]


class SecretRuleCatalogEntry(TypedDict):
    """Public, non-sensitive detector catalog metadata."""

    rule_id: str
    family: str
    severity: SecretSeverity
    validation: SecretValidationKind
    strong_format: bool
    description: str


_DETECTOR_VERSION = "guard-secrets-v1"

_SAMPLE_WORDS = re.compile(
    r"(?i)(?:example|sample|dummy|fake|fixture|placeholder|changeme|replace[_-]?me|"
    r"your[_-]?(?:api[_-]?)?(?:key|token|secret|password)|test[_-]?(?:key|token|secret))"
)
_CREDENTIAL_KEYWORDS = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?key|auth[_-]?token|bearer|credential|password|passwd|"
    r"private[_-]?key|secret|token|webhook|client[_-]?secret)"
)
_ASSIGNMENT = re.compile(
    r"(?im)(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,80})\s*[:=]\s*"
    r"(?P<quote>[\"']?)(?P<secret>[^\s\"',}{]{12,256})(?P=quote)"
)
_GENERIC_CANDIDATE_POLICY_VERSION = "credential-expression-filter-v1"
_CODE_REFERENCE_PREFIXES = (
    "config.",
    "context.",
    "crypto.",
    "data.",
    "deno.env.",
    "env.",
    "headers.",
    "import.meta.env.",
    "local.",
    "module.",
    "os.environ",
    "os.getenv",
    "params.",
    "payload.",
    "process.env.",
    "request.",
    "response.",
    "secret.",
    "secrets.",
    "self.",
    "settings.",
    "this.",
    "values.",
    "var.",
    "vault.",
)
_CODE_MEMBER_REFERENCE = re.compile(
    r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*)+$"
)
_CODE_CALL_REFERENCE = re.compile(
    r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*)*\s*\("
)
_CODE_IDENTIFIER_REFERENCE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
_INTERPOLATED_REFERENCE = re.compile(r"^(?:\$\{|\$\(|\{\{|<%|%\{|@\{)")
_CODE_SUFFIXES = frozenset(
    {
        ".bash",
        ".cjs",
        ".cs",
        ".dart",
        ".go",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".kts",
        ".lua",
        ".mjs",
        ".php",
        ".ps1",
        ".py",
        ".rb",
        ".rs",
        ".scala",
        ".sh",
        ".svelte",
        ".swift",
        ".ts",
        ".tsx",
        ".vue",
        ".zsh",
    }
)
_DATABASE_URL = re.compile(
    r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis)://"
    r"[^\s:/@]{1,128}:(?P<secret>[^\s/@]{6,256})@[^\s]+"
)
_BASIC_AUTH_URL = re.compile(r"(?i)\bhttps?://[^\s:/@]{1,128}:(?P<secret>[^\s/@]{8,256})@[^\s]+")
_JWT = re.compile(r"\b(?P<secret>eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b")

_DOC_SEGMENTS = frozenset(
    {
        "docs",
        "doc",
        "documentation",
        "examples",
        "example",
        "fixtures",
        "fixture",
        "samples",
        "sample",
        "test",
        "tests",
        "spec",
        "specs",
        "__tests__",
        "__fixtures__",
    }
)
_DOC_SUFFIXES = frozenset({".md", ".mdx", ".rst", ".adoc", ".txt"})
_HIGH_SIGNAL_BASENAMES = frozenset(
    {
        ".env",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".git-credentials",
        "credentials",
        "secrets.yml",
        "secrets.yaml",
        "terraform.tfvars",
    }
)


@dataclass(frozen=True, slots=True)
class SecretRule:
    rule_id: str
    family: str
    severity: SecretSeverity
    pattern: re.Pattern[str]
    validation: SecretValidationKind = "none"
    strong_format: bool = True
    description: str = ""


@dataclass(frozen=True, slots=True)
class SecretFinding:
    rule_id: str
    family: str
    severity: SecretSeverity
    confidence: SecretConfidence
    confidence_score: float
    line: int
    path: str
    source: SecretScanSource
    commit: str | None
    validation: SecretValidationKind
    entropy: float
    context_reasons: tuple[str, ...]
    candidate: str = field(repr=False, compare=False)

    def fingerprint(self, key: bytes) -> str:
        """Return a tenant/caller-scoped HMAC without exposing candidate bytes."""

        if not key:
            raise ValueError("secret fingerprint key must not be empty")
        material = f"{self.rule_id}\0{self.candidate}".encode("utf-8", errors="strict")
        return hmac.new(key, material, hashlib.sha256).hexdigest()

    def to_public_dict(self, *, fingerprint_key: bytes | None = None) -> dict[str, object]:
        payload: dict[str, object] = {
            "rule_id": self.rule_id,
            "family": self.family,
            "severity": self.severity,
            "confidence": self.confidence,
            "confidence_score": round(self.confidence_score, 4),
            "line": self.line,
            "path": self.path,
            "source": self.source,
            "commit": self.commit,
            "validation": self.validation,
            "entropy": round(self.entropy, 4),
            "context_reasons": list(self.context_reasons),
        }
        if fingerprint_key is not None:
            payload["fingerprint"] = self.fingerprint(fingerprint_key)
        return payload


@dataclass(frozen=True, slots=True)
class SecretScanSummary:
    detector_version: str
    findings: tuple[SecretFinding, ...]

    def to_public_dict(self, *, fingerprint_key: bytes | None = None) -> dict[str, object]:
        return {
            "schema": "guard-secret-scan.v1",
            "detector_version": self.detector_version,
            "finding_count": len(self.findings),
            "findings": [finding.to_public_dict(fingerprint_key=fingerprint_key) for finding in self.findings],
        }


def _compile(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


SECRET_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "github-token",
        "GitHub token",
        "critical",
        _compile(r"\b(?P<secret>(?:gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255}))\b"),
        "github",
        description="GitHub personal, OAuth, user, server, refresh, or fine-grained token.",
    ),
    SecretRule(
        "gitlab-token",
        "GitLab token",
        "critical",
        _compile(r"\b(?P<secret>glpat-[A-Za-z0-9_-]{20,255})\b"),
        "gitlab",
        description="GitLab personal/project/group access token.",
    ),
    SecretRule(
        "aws-access-key",
        "AWS access key ID",
        "high",
        _compile(r"\b(?P<secret>(?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        "aws",
        description="AWS long-lived or STS access key identifier.",
    ),
    SecretRule(
        "slack-token",
        "Slack token",
        "critical",
        _compile(r"\b(?P<secret>xox[baprs]-[A-Za-z0-9-]{10,255})\b"),
        "slack",
        description="Slack bot, app, user, refresh, or service token.",
    ),
    SecretRule(
        "slack-webhook",
        "Slack incoming webhook",
        "critical",
        _compile(r"(?P<secret>https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{24,255})"),
        "slack",
        description="Slack incoming webhook URL.",
    ),
    SecretRule(
        "stripe-secret-key",
        "Stripe secret key",
        "critical",
        _compile(r"\b(?P<secret>(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255})\b"),
        "stripe",
        description="Stripe secret or restricted API key.",
    ),
    SecretRule(
        "openai-api-key",
        "OpenAI API key",
        "critical",
        _compile(r"\b(?P<secret>sk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,255})\b"),
        "openai",
        description="OpenAI project/service/account API key.",
    ),
    SecretRule(
        "anthropic-api-key",
        "Anthropic API key",
        "critical",
        _compile(r"\b(?P<secret>sk-ant-[A-Za-z0-9_-]{20,255})\b"),
        "anthropic",
        description="Anthropic API key.",
    ),
    SecretRule(
        "huggingface-token",
        "Hugging Face token",
        "high",
        _compile(r"\b(?P<secret>hf_[A-Za-z0-9]{24,255})\b"),
        "huggingface",
        description="Hugging Face user or organization token.",
    ),
    SecretRule(
        "npm-token",
        "npm access token",
        "critical",
        _compile(r"\b(?P<secret>npm_[A-Za-z0-9]{30,255})\b"),
        "npm",
        description="npm granular or automation access token.",
    ),
    SecretRule(
        "pypi-token",
        "PyPI API token",
        "critical",
        _compile(r"\b(?P<secret>pypi-[A-Za-z0-9_-]{24,255})\b"),
        "pypi",
        description="PyPI scoped API token.",
    ),
    SecretRule(
        "google-api-key",
        "Google API key",
        "high",
        _compile(r"\b(?P<secret>AIza[0-9A-Za-z_-]{35})\b"),
        "google",
        description="Google Cloud/Firebase API key.",
    ),
    SecretRule(
        "sendgrid-api-key",
        "SendGrid API key",
        "critical",
        _compile(r"\b(?P<secret>SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b"),
        "sendgrid",
        description="SendGrid API key.",
    ),
    SecretRule(
        "pem-private-key",
        "PEM private key",
        "critical",
        _compile(
            r"(?P<secret>-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)",
            re.MULTILINE,
        ),
        description="Private-key material in PEM/OpenSSH-style form.",
    ),
    SecretRule(
        "database-url-password",
        "Database URL password",
        "critical",
        _DATABASE_URL,
        strong_format=False,
        description="Password embedded in a database connection URL.",
    ),
    SecretRule(
        "basic-auth-url-password",
        "Basic-auth URL password",
        "high",
        _BASIC_AUTH_URL,
        strong_format=False,
        description="Credential embedded in an HTTP(S) URL.",
    ),
    SecretRule(
        "jwt-token",
        "JWT bearer token",
        "high",
        _JWT,
        strong_format=False,
        description="JWT-like bearer token in credential context.",
    ),
)


def detector_version() -> str:
    material_parts = [
        f"{rule.rule_id}|{rule.severity}|{rule.validation}|{rule.pattern.pattern}|{rule.pattern.flags}"
        for rule in SECRET_RULES
    ]
    material_parts.append(
        "|".join(
            (
                "credential-assignment",
                _ASSIGNMENT.pattern,
                str(_ASSIGNMENT.flags),
                _GENERIC_CANDIDATE_POLICY_VERSION,
            )
        )
    )
    digest = hashlib.sha256("\n".join(material_parts).encode("utf-8")).hexdigest()[:16]
    return f"{_DETECTOR_VERSION}:{digest}"


def secret_rule_catalog() -> list[SecretRuleCatalogEntry]:
    entries = [
        SecretRuleCatalogEntry(
            rule_id=rule.rule_id,
            family=rule.family,
            severity=rule.severity,
            validation=rule.validation,
            strong_format=rule.strong_format,
            description=rule.description,
        )
        for rule in SECRET_RULES
    ]
    entries.append(
        SecretRuleCatalogEntry(
            rule_id="credential-assignment",
            family="Contextual credential assignment",
            severity="high",
            validation="none",
            strong_format=False,
            description="High-entropy credential assignment accepted only with contextual evidence.",
        )
    )
    return entries


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    length = float(len(value))
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _rarity_score(value: str) -> float:
    if not value:
        return 0.0
    entropy_component = min(shannon_entropy(value) / 5.2, 1.0)
    classes = sum(
        int(bool(pattern.search(value)))
        for pattern in (
            re.compile(r"[a-z]"),
            re.compile(r"[A-Z]"),
            re.compile(r"[0-9]"),
            re.compile(r"[^A-Za-z0-9]"),
        )
    )
    class_component = min(classes / 3.0, 1.0)
    length_component = min(max(len(value) - 12, 0) / 36.0, 1.0)
    return min((entropy_component * 0.55) + (class_component * 0.2) + (length_component * 0.25), 1.0)


def _normalized_path(path: str | None) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").strip().lower()


def _path_is_documentation(path: str) -> bool:
    normalized = _normalized_path(path)
    if not normalized:
        return False
    pure = PurePosixPath(normalized)
    parts = set(pure.parts)
    return bool(parts & _DOC_SEGMENTS) or pure.suffix in _DOC_SUFFIXES


def _path_is_high_signal(path: str) -> bool:
    normalized = _normalized_path(path)
    if not normalized:
        return False
    pure = PurePosixPath(normalized)
    basename = pure.name
    if basename == ".env" or basename.startswith(".env."):
        return True
    return basename in _HIGH_SIGNAL_BASENAMES or any(part in {".aws", ".ssh", ".gnupg"} for part in pure.parts)


def _obvious_sample(candidate: str, context: str) -> bool:
    combined = f"{candidate}\n{context}"
    if _SAMPLE_WORDS.search(combined) is None:
        return False
    # Do not suppress a structurally strong, long random-looking token just
    # because nearby documentation contains the word "example".
    return _rarity_score(candidate) < 0.76 or len(candidate) < 28


def _candidate_is_indirect_reference(
    candidate: str,
    *,
    quoted: bool,
    path: str,
) -> bool:
    """Reject code/config expressions that name a secret without containing it."""

    value = candidate.strip()
    if not value:
        return True
    lowered = value.lower()
    if lowered in {"false", "none", "null", "true", "undefined"}:
        return True
    if _INTERPOLATED_REFERENCE.match(value) is not None:
        return True
    if lowered.startswith(_CODE_REFERENCE_PREFIXES):
        return True
    if quoted:
        return False
    if _CODE_CALL_REFERENCE.match(value) is not None:
        return True
    if any(operator in value for operator in ("=>", "??", "||", "&&")):
        return True
    if any(character in value for character in "()[]{};`"):
        return True
    if _CODE_MEMBER_REFERENCE.fullmatch(value) is not None:
        return True
    suffix = PurePosixPath(_normalized_path(path)).suffix
    if suffix not in _CODE_SUFFIXES or _CODE_IDENTIFIER_REFERENCE.fullmatch(value) is None:
        return False
    digit_count = sum(character.isdigit() for character in value)
    return value[0].islower() and digit_count <= 1


def _confidence_label(score: float) -> SecretConfidence:
    if score >= 0.84:
        return "high"
    if score >= 0.64:
        return "medium"
    return "low"


def _context_score(
    candidate: str,
    *,
    path: str,
    line_text: str,
    strong_format: bool,
) -> tuple[float, tuple[str, ...]]:
    score = 0.9 if strong_format else 0.3
    reasons: list[str] = ["provider-format" if strong_format else "contextual-candidate"]
    rarity = _rarity_score(candidate)
    score += rarity * (0.08 if strong_format else 0.34)
    if rarity >= 0.72:
        reasons.append("high-token-rarity")
    if _CREDENTIAL_KEYWORDS.search(line_text) is not None:
        score += 0.22
        reasons.append("credential-name-context")
    if _path_is_high_signal(path):
        score += 0.14
        reasons.append("sensitive-file-context")
    if _path_is_documentation(path):
        score -= 0.28 if not strong_format else 0.08
        reasons.append("documentation-context")
    if _SAMPLE_WORDS.search(line_text) is not None:
        score -= 0.32 if not strong_format else 0.1
        reasons.append("sample-marker-context")
    return max(0.0, min(score, 1.0)), tuple(reasons)


def _line_number(text: str, match_start: int) -> int:
    return text.count("\n", 0, match_start) + 1


def _line_text(text: str, match_start: int) -> str:
    start = text.rfind("\n", 0, match_start) + 1
    end = text.find("\n", match_start)
    if end < 0:
        end = len(text)
    return text[start:end][:1024]


def _finding_from_match(
    *,
    rule: SecretRule,
    candidate: str,
    text: str,
    match_start: int,
    path: str,
    source: SecretScanSource,
    commit: str | None,
) -> SecretFinding | None:
    line_text = _line_text(text, match_start)
    if _obvious_sample(candidate, line_text) and not rule.strong_format:
        return None
    score, reasons = _context_score(
        candidate,
        path=path,
        line_text=line_text,
        strong_format=rule.strong_format,
    )
    minimum_score = 0.56 if rule.strong_format else 0.64
    if score < minimum_score:
        return None
    return SecretFinding(
        rule_id=rule.rule_id,
        family=rule.family,
        severity=rule.severity,
        confidence=_confidence_label(score),
        confidence_score=score,
        line=_line_number(text, match_start),
        path=path,
        source=source,
        commit=commit,
        validation=rule.validation,
        entropy=shannon_entropy(candidate),
        context_reasons=reasons,
        candidate=candidate,
    )


def scan_secret_text(
    text: str,
    *,
    path: str = "",
    source: SecretScanSource = "text",
    commit: str | None = None,
    max_findings: int = 200,
) -> SecretScanSummary:
    """Scan text for leaked credentials without serializing candidate bytes."""

    if not isinstance(text, str) or not text:
        return SecretScanSummary(detector_version=detector_version(), findings=())
    bounded_max = max(1, min(int(max_findings), 10_000))
    findings: list[SecretFinding] = []
    seen: set[tuple[str, int, str]] = set()

    for rule in SECRET_RULES:
        for match in rule.pattern.finditer(text):
            candidate = match.groupdict().get("secret") or match.group(0)
            finding = _finding_from_match(
                rule=rule,
                candidate=candidate,
                text=text,
                match_start=match.start(),
                path=path,
                source=source,
                commit=commit,
            )
            if finding is None:
                continue
            identity = (finding.rule_id, finding.line, candidate)
            if identity in seen:
                continue
            seen.add(identity)
            findings.append(finding)
            if len(findings) >= bounded_max:
                findings.sort(key=lambda item: (item.path, item.line, item.rule_id, item.commit or ""))
                return SecretScanSummary(detector_version=detector_version(), findings=tuple(findings))

    # Generic assignments are intentionally evaluated after provider formats so
    # the structured detector wins when both identify the same token.
    provider_candidates = {finding.candidate for finding in findings}
    generic_rule = SecretRule(
        rule_id="credential-assignment",
        family="Contextual credential assignment",
        severity="high",
        pattern=_ASSIGNMENT,
        strong_format=False,
        description="Contextual high-entropy credential assignment.",
    )
    for match in _ASSIGNMENT.finditer(text):
        candidate = match.group("secret")
        if candidate in provider_candidates:
            continue
        if _candidate_is_indirect_reference(
            candidate,
            quoted=bool(match.group("quote")),
            path=path,
        ):
            continue
        name = match.group("name")
        if _CREDENTIAL_KEYWORDS.search(name) is None:
            continue
        if _obvious_sample(candidate, match.group(0)):
            continue
        if _rarity_score(candidate) < 0.54 and len(candidate) < 24:
            continue
        finding = _finding_from_match(
            rule=generic_rule,
            candidate=candidate,
            text=text,
            match_start=match.start(),
            path=path,
            source=source,
            commit=commit,
        )
        if finding is None:
            continue
        identity = (finding.rule_id, finding.line, candidate)
        if identity in seen:
            continue
        seen.add(identity)
        findings.append(finding)
        if len(findings) >= bounded_max:
            break

    findings.sort(key=lambda item: (item.path, item.line, item.rule_id, item.commit or ""))
    return SecretScanSummary(detector_version=detector_version(), findings=tuple(findings))


__all__ = [
    "SECRET_RULES",
    "SecretConfidence",
    "SecretFinding",
    "SecretRule",
    "SecretRuleCatalogEntry",
    "SecretScanSource",
    "SecretScanSummary",
    "SecretSeverity",
    "SecretValidationKind",
    "detector_version",
    "scan_secret_text",
    "secret_rule_catalog",
    "shannon_entropy",
]
