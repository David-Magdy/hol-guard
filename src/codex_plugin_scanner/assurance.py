"""Layered assurance checks for plugins, MCP servers, and agent skills.

The scanner deliberately separates detection, coverage, provenance, native
inspection, archive inspection, and runtime evidence. A completed static scan
is evidence about supported content, never a blanket claim that an extension
is safe.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import math
import os
import re
import tarfile
import unicodedata
import zipfile
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .evidence_envelope import verify_attestation
from .models import CheckResult, Finding, IntegrationResult, SEVERITY_ORDER, Severity
from .runtime_assurance import validate_runtime_evidence
from .rust_kernel import InventoryRecord, KernelResult, scan_inventory

ASSURANCE_VERSION = "2.0"
MAX_FINDINGS = 1_000
MAX_TEXT_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_TEXT_BYTES = 96 * 1024 * 1024
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 10_000
MAX_ARCHIVE_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_RATIO = 200.0
MAX_ARCHIVE_DEPTH = 2
MAX_DECODED_CANDIDATES = 12

_TEXT_EXTENSIONS = frozenset(
    {
        ".c",
        ".cc",
        ".cfg",
        ".cmd",
        ".conf",
        ".cpp",
        ".cs",
        ".css",
        ".env",
        ".go",
        ".h",
        ".hpp",
        ".html",
        ".ini",
        ".java",
        ".js",
        ".json",
        ".jsx",
        ".kt",
        ".lua",
        ".md",
        ".mjs",
        ".php",
        ".pl",
        ".properties",
        ".ps1",
        ".py",
        ".rb",
        ".rs",
        ".sh",
        ".sql",
        ".toml",
        ".ts",
        ".tsx",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
        ".zsh",
    }
)
_ARCHIVE_SUFFIXES = frozenset({".zip", ".jar", ".whl", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".7z", ".rar"})
_CONTEXT_PARTS = frozenset({"docs", "doc", "examples", "example", "fixtures", "fixture", "samples", "sample", "tests", "test"})
_NATIVE_FORMATS = frozenset({"elf", "pe", "mach-o", "wasm"})
_BIDI_CONTROLS = frozenset(chr(value) for value in (0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)))
_ZERO_WIDTH = frozenset({"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"})
_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){24,}(?![0-9A-Fa-f])")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)
_PRIVATE_NETWORK_RE = re.compile(
    r"(?:127(?:\.\d{1,3}){3}|0\.0\.0\.0|localhost|169\.254\.169\.254|metadata\.google\.internal|"
    r"10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|"
    r"\[?::1\]?|2130706433|0x7f000001)",
    re.I,
)
_SECRET_NAME_RE = re.compile(r"(?:token|secret|password|credential|api[_-]?key|private[_-]?key|authorization)", re.I)


@dataclass(frozen=True, slots=True)
class ScanBudget:
    max_files: int = 20_000
    max_hashed_bytes: int = 512 * 1024 * 1024
    max_text_file_bytes: int = MAX_TEXT_FILE_BYTES
    max_total_text_bytes: int = MAX_TOTAL_TEXT_BYTES
    max_archive_bytes: int = MAX_ARCHIVE_BYTES


@dataclass(frozen=True, slots=True)
class RulePattern:
    rule_id: str
    severity: Severity
    category: str
    title: str
    description: str
    remediation: str
    pattern: re.Pattern[str]


@dataclass(slots=True)
class Coverage:
    text_bytes: int = 0
    text_files: int = 0
    archives: int = 0
    native_files: int = 0
    opaque_files: int = 0
    oversized_files: int = 0
    unreadable_files: int = 0
    invalid_utf8_files: int = 0
    excluded_directories: int = 0
    truncated: bool = False
    archive_partial: bool = False
    native_partial: bool = False


_TEXT_RULES: tuple[RulePattern, ...] = (
    RulePattern(
        "ASSURANCE_PROMPT_INJECTION",
        Severity.HIGH,
        "instruction-security",
        "Instruction override or prompt injection",
        "The file contains instructions that attempt to override higher-priority policy or conceal intent.",
        "Remove policy-override instructions and make all privileged behavior explicit and reviewable.",
        re.compile(
            r"(?:ignore|disregard|override|forget).{0,80}(?:previous|prior|system|developer|security|policy|instructions?)|"
            r"(?:do not|never) (?:tell|reveal|mention|disclose).{0,80}(?:user|operator|reviewer)|"
            r"(?:hidden|secret) (?:instruction|prompt)|jailbreak",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_TOOL_POISONING",
        Severity.HIGH,
        "instruction-security",
        "Tool description attempts to manipulate the model",
        "A tool or skill description contains coercive, hidden, or unrelated instructions for the model.",
        "Restrict descriptions to truthful capability and parameter documentation.",
        re.compile(
            r"(?:before|after) (?:using|calling|invoking) (?:this )?tool.{0,120}(?:must|always|secretly)|"
            r"(?:model|assistant) (?:must|should|shall).{0,100}(?:ignore|exfiltrate|upload|send|conceal)|"
            r"(?:trusted|safe) regardless of|do not ask (?:the )?user",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_COMMAND_INJECTION",
        Severity.CRITICAL,
        "code-execution",
        "Potential command injection",
        "Untrusted or dynamically assembled values appear to reach a shell or command interpreter.",
        "Use an argument vector, disable shell parsing, and validate every externally controlled argument.",
        re.compile(
            r"(?:subprocess\.(?:run|call|Popen)|child_process\.(?:exec|execSync)|Runtime\.getRuntime\(\)\.exec|"
            r"os\.(?:system|popen)|ProcessBuilder|shell_exec|passthru|exec\s*\().{0,180}"
            r"(?:shell\s*=\s*True|\$\{|\+\s*(?:input|request|args|params|user)|format\(|f[\"'])|"
            r"(?:cmd\.exe\s*/c|powershell(?:\.exe)?\s+-c|/bin/(?:sh|bash)\s+-c).{0,160}(?:\$\{|%\w+%|\+)",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_DYNAMIC_EXECUTION",
        Severity.HIGH,
        "code-execution",
        "Dynamic code execution",
        "The extension dynamically evaluates code or loads executable content.",
        "Replace dynamic evaluation with a fixed parser or constrained allowlisted dispatch.",
        re.compile(
            r"\b(?:eval|exec|compile)\s*\(|new\s+Function\s*\(|vm\.(?:runIn|compileFunction)|"
            r"Assembly\.Load\s*\(|ClassLoader\b|dlopen\s*\(|LoadLibrary(?:A|W)?\s*\(",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_UNSAFE_DESERIALIZATION",
        Severity.HIGH,
        "deserialization",
        "Unsafe deserialization surface",
        "A general-purpose object deserializer may process attacker-controlled content.",
        "Use a schema-bound data format and a safe loader that cannot instantiate arbitrary objects.",
        re.compile(
            r"pickle\.(?:load|loads)\s*\(|yaml\.(?:load|unsafe_load)\s*\(|marshal\.loads\s*\(|"
            r"ObjectInputStream\b|BinaryFormatter\b|NetDataContractSerializer\b|unserialize\s*\(|"
            r"node-serialize|serialize-javascript.{0,40}unsafe",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_SSRF",
        Severity.HIGH,
        "network-security",
        "Server-side request forgery surface",
        "A caller-controlled URL or host appears to be fetched without an explicit destination policy.",
        "Parse once, resolve safely, block private and metadata ranges, pin the validated destination, and reject redirects.",
        re.compile(
            r"(?:requests\.(?:get|post|request)|urllib\.request\.urlopen|fetch\s*\(|axios\.|http\.(?:get|request)|"
            r"WebClient\(|HttpClient).{0,180}(?:url|uri|endpoint|host|request|params|args|input)",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_CLOUD_METADATA_ACCESS",
        Severity.CRITICAL,
        "credential-access",
        "Cloud instance metadata access",
        "The extension references a cloud metadata endpoint commonly used to obtain workload credentials.",
        "Remove metadata access or isolate it behind an explicit, least-privilege workload identity broker.",
        re.compile(r"169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data|metadata/identity/oauth2/token", re.I),
    ),
    RulePattern(
        "ASSURANCE_XXE",
        Severity.HIGH,
        "parser-security",
        "XML external entity processing",
        "XML parsing enables DTD or external entity behavior that can read files or make network requests.",
        "Disable DTDs, external entities, and network access in the XML parser.",
        re.compile(
            r"resolve_entities\s*=\s*True|load_dtd\s*=\s*True|setFeature\(.{0,80}external-general-entities.{0,20}true|"
            r"DocumentBuilderFactory.{0,160}setExpandEntityReferences\s*\(\s*true",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_PATH_TRAVERSAL",
        Severity.HIGH,
        "filesystem-security",
        "Path traversal or unsafe archive extraction",
        "Externally controlled path components may escape the intended root directory.",
        "Resolve against a fixed root, reject absolute and parent components, and verify the final resolved path remains inside it.",
        re.compile(
            r"extractall\s*\(|(?:join|resolve|Path)\s*\(.{0,120}(?:request|params|args|input|filename)|"
            r"\.\.\/(?:\.\.\/)+|\.\.\\(?:\.\.\\)+",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_ARBITRARY_FILE_WRITE",
        Severity.HIGH,
        "filesystem-security",
        "Potential arbitrary file write",
        "An externally supplied path appears to control a write, rename, or extraction destination.",
        "Constrain writes to a dedicated root and validate the final path immediately before opening it.",
        re.compile(
            r"(?:writeFile|write_text|write_bytes|open\s*\(|FileOutputStream|rename\s*\().{0,160}"
            r"(?:request|params|args|input|filename|path)",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_CREDENTIAL_ACCESS",
        Severity.HIGH,
        "credential-access",
        "Credential store access",
        "The extension references operating-system, cloud, browser, package-manager, or developer credential stores.",
        "Use narrowly scoped credential APIs and require explicit user authorization before access.",
        re.compile(
            r"(?:\.aws[/\\]credentials|\.ssh[/\\](?:id_rsa|id_ed25519)|\.npmrc|\.pypirc|\.docker[/\\]config\.json|"
            r"Login Data|Cookies|Local State|keychain|credential manager|security\s+find-generic-password|"
            r"pass\s+show|secret-tool\s+lookup|wallet\.dat|keystore)",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_SECRET_EXFILTRATION",
        Severity.CRITICAL,
        "data-exfiltration",
        "Credential or environment exfiltration",
        "Sensitive environment or credential material appears to be sent to a remote destination.",
        "Never transmit ambient credentials. Send only explicitly selected, redacted fields to an allowlisted destination.",
        re.compile(
            r"(?:process\.env|os\.environ|env::vars|GetEnvironmentVariables|credentials?|tokens?|secrets?).{0,220}"
            r"(?:fetch\s*\(|axios|requests\.|curl|wget|http\.|socket|webhook|upload|post\s*\()|"
            r"(?:fetch\s*\(|axios|requests\.|curl|wget|webhook).{0,220}(?:process\.env|os\.environ|credentials?|tokens?|secrets?)",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_DOWNLOAD_EXECUTE",
        Severity.CRITICAL,
        "supply-chain",
        "Download-and-execute chain",
        "Remote content is piped or passed directly to an interpreter or executable loader.",
        "Download to a quarantined location, verify an immutable digest and signature, then require review before execution.",
        re.compile(
            r"(?:curl|wget|Invoke-WebRequest|iwr).{0,180}(?:\|\s*(?:sh|bash|zsh|python|node|powershell)|"
            r"&&\s*(?:chmod|sh|bash|python|node)|-OutFile.{0,100}(?:Start-Process|&\s))|"
            r"(?:requests\.|fetch\s*\().{0,220}(?:exec\s*\(|eval\s*\(|subprocess|child_process)",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_TLS_DISABLED",
        Severity.HIGH,
        "network-security",
        "TLS verification disabled",
        "The extension disables certificate or hostname validation.",
        "Use the platform trust store and explicit certificate pinning only where operationally justified.",
        re.compile(
            r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0|"
            r"CURLOPT_SSL_VERIFYPEER.{0,40}(?:false|0)|InsecureSkipVerify\s*:\s*true|"
            r"ServerCertificateCustomValidationCallback.{0,80}(?:=>\s*true|return\s+true)",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_DOCKER_SOCKET",
        Severity.CRITICAL,
        "container-security",
        "Container engine socket access",
        "Access to a Docker or container runtime socket can provide host-equivalent control.",
        "Do not mount container-engine sockets into extensions; use a least-privilege broker if container operations are required.",
        re.compile(r"/var/run/docker\.sock|docker_engine|containerd\.sock|podman\.sock", re.I),
    ),
    RulePattern(
        "ASSURANCE_PRIVILEGE_ESCALATION",
        Severity.CRITICAL,
        "privilege-escalation",
        "Privilege escalation behavior",
        "The extension requests elevated privileges, setuid behavior, or unrestricted container execution.",
        "Remove elevation and grant the minimum capability through an audited, user-approved broker.",
        re.compile(
            r"\bsudo\b|pkexec|setuid\s*\(|setgid\s*\(|chmod\s+(?:4|6)[0-7]{3}|--privileged|"
            r"CAP_SYS_ADMIN|SeDebugPrivilege|runas\s+/user",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_PERSISTENCE",
        Severity.HIGH,
        "persistence",
        "Persistence mechanism",
        "The extension creates or modifies an operating-system persistence mechanism.",
        "Remove persistence or require explicit installation approval with a reversible, documented uninstall path.",
        re.compile(
            r"(?:/etc/(?:cron|systemd)|crontab\s+-|systemctl\s+enable|LaunchAgents|LaunchDaemons|"
            r"CurrentVersion[/\\]Run|schtasks\s+/create|New-Service|sc\.exe\s+create|Startup[/\\])",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_DESTRUCTIVE_OPERATION",
        Severity.CRITICAL,
        "impact",
        "Destructive filesystem or infrastructure operation",
        "The extension contains broad deletion, disk, database, or infrastructure-destruction behavior.",
        "Constrain destructive operations to an explicit allowlist and require a separate confirmation boundary.",
        re.compile(
            r"rm\s+-rf\s+(?:/|~|\$HOME|\*)|Remove-Item.{0,80}-Recurse.{0,40}-Force|"
            r"(?:DROP\s+(?:DATABASE|SCHEMA)|TRUNCATE\s+TABLE)|mkfs\b|diskpart\b|"
            r"terraform\s+destroy.{0,40}-auto-approve|kubectl\s+delete.{0,40}--all",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_CRYPTO_MINING",
        Severity.HIGH,
        "resource-abuse",
        "Cryptocurrency mining behavior",
        "Mining software, pool protocols, or resource-abuse indicators are present.",
        "Remove mining behavior and audit all bundled native artifacts and download paths.",
        re.compile(r"stratum\+tcp|xmrig|minerd|cryptonight|randomx|pool\.supportxmr|nanopool", re.I),
    ),
    RulePattern(
        "ASSURANCE_INPUT_CAPTURE",
        Severity.CRITICAL,
        "surveillance",
        "Keyboard, clipboard, or screen capture",
        "The extension captures sensitive user input or screen content outside a clear, narrow product purpose.",
        "Remove ambient capture or require explicit, visible, time-bounded user consent for the minimum necessary surface.",
        re.compile(
            r"GetAsyncKeyState|SetWindowsHookEx|CGEventTapCreate|pynput\.keyboard|keylog|"
            r"clipboard\.(?:read|readText)|pbpaste|xclip\s+-o|ImageGrab\.grab|screencapture",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_PROCESS_INJECTION",
        Severity.CRITICAL,
        "evasion",
        "Process injection or debugger manipulation",
        "The extension contains APIs commonly used to inject code into another process or manipulate tracing.",
        "Remove cross-process injection and use a documented extension or IPC interface.",
        re.compile(
            r"WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|VirtualAllocEx|process_vm_writev|"
            r"ptrace\s*\(|mach_inject|DYLD_INSERT_LIBRARIES|LD_PRELOAD",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_SQL_INJECTION",
        Severity.HIGH,
        "injection",
        "Potential SQL injection",
        "Request-controlled values appear to be concatenated or formatted into a SQL statement.",
        "Use parameterized queries and prohibit dynamic identifier interpolation unless allowlisted.",
        re.compile(
            r"(?:SELECT|INSERT|UPDATE|DELETE|DROP).{0,180}(?:\+\s*(?:request|params|args|input|user)|"
            r"f[\"']|\.format\s*\(|\$\{)|execute\s*\(.{0,120}(?:request|params|args|input)",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_TEMPLATE_INJECTION",
        Severity.HIGH,
        "injection",
        "Server-side template injection",
        "Externally controlled template source is compiled or rendered as code-capable template content.",
        "Render fixed templates and pass external data only as values.",
        re.compile(
            r"(?:Template|from_string|compileTemplate|Handlebars\.compile|ejs\.render|pug\.render).{0,150}"
            r"(?:request|params|args|input|user)",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_REGEX_DOS",
        Severity.MEDIUM,
        "resource-abuse",
        "Potential regular-expression denial of service",
        "A nested or ambiguous repetition pattern may be applied to externally controlled input.",
        "Use a linear-time expression, bound input length, or use an engine with guaranteed execution limits.",
        re.compile(r"\([^\n)]*(?:\+|\*)[^\n)]*\)(?:\+|\*).{0,180}(?:request|input|text|body|content)", re.I),
    ),
    RulePattern(
        "ASSURANCE_RESOURCE_EXHAUSTION",
        Severity.MEDIUM,
        "resource-abuse",
        "Unbounded resource consumption",
        "The extension contains an unbounded allocation, recursion, decompression, or worker-spawn surface.",
        "Enforce input, depth, output, process, memory, and time budgets before consuming attacker-controlled data.",
        re.compile(
            r"while\s*\(\s*true\s*\)|while\s+True|for\s*\(\s*;\s*;\s*\)|new\s+Worker.{0,80}(?:request|input)|"
            r"multiprocessing\.(?:Pool|Process).{0,80}(?:request|input)|decompress\s*\(.{0,120}(?:request|input|body)",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_OAUTH_TOKEN_FORWARDING",
        Severity.HIGH,
        "authorization",
        "OAuth token forwarding or confused-deputy risk",
        "A bearer or access token appears to be forwarded to a caller-controlled or unrelated destination.",
        "Bind tokens to issuer, audience, resource, tenant, and destination; exchange rather than forward ambient tokens.",
        re.compile(
            r"(?:Authorization|Bearer|access[_-]?token).{0,220}(?:url|endpoint|host|request|params|args)|"
            r"(?:fetch|axios|requests\.).{0,220}(?:Authorization|Bearer|access[_-]?token)",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_MCP_AUTH_BYPASS",
        Severity.HIGH,
        "mcp-security",
        "MCP authorization boundary is missing or bypassed",
        "An MCP surface accepts remote requests or privileged tools without a clear authorization check.",
        "Authenticate the client, authorize every tool and resource, bind tokens to audience, and deny by default.",
        re.compile(
            r"(?:mcp|tool).{0,120}(?:auth\s*=\s*false|authorization\s*:\s*none|skip[_-]?auth|allow[_-]?anonymous)|"
            r"(?:SSE|streamable.?http).{0,160}(?:0\.0\.0\.0|::).{0,160}(?:no.?auth|anonymous)",
            re.I,
        ),
    ),
    RulePattern(
        "ASSURANCE_PROTOTYPE_POLLUTION",
        Severity.HIGH,
        "injection",
        "Prototype pollution surface",
        "Untrusted object keys may modify JavaScript object prototypes.",
        "Reject prototype keys and use schema validation with null-prototype objects for untrusted maps.",
        re.compile(r"(?:__proto__|constructor\.prototype|prototype\[).{0,120}(?:request|input|body|params|merge|assign)", re.I),
    ),
)


class _Collector:
    def __init__(self) -> None:
        self._findings: dict[str, list[Finding]] = defaultdict(list)
        self._seen: set[tuple[str, str | None, int | None]] = set()

    def add(self, layer: str, finding: Finding) -> None:
        key = (finding.rule_id, finding.file_path, finding.line_number)
        if key in self._seen or sum(len(items) for items in self._findings.values()) >= MAX_FINDINGS:
            return
        self._seen.add(key)
        self._findings[layer].append(finding)

    def layer(self, layer: str) -> tuple[Finding, ...]:
        return tuple(sorted(self._findings.get(layer, ()), key=_finding_sort_key))

    def all(self) -> tuple[Finding, ...]:
        return tuple(sorted((finding for items in self._findings.values() for finding in items), key=_finding_sort_key))


def _finding_sort_key(finding: Finding) -> tuple[int, str, str, int]:
    return (
        -SEVERITY_ORDER[finding.severity],
        finding.rule_id,
        finding.file_path or "",
        finding.line_number or 0,
    )


def _is_non_runtime_context(path: str) -> bool:
    parts = {part.lower() for part in PurePosixPath(path).parts}
    return bool(parts & _CONTEXT_PARTS) or path.lower().endswith((".example", ".sample"))


def _contextual_severity(severity: Severity, path: str) -> Severity:
    if not _is_non_runtime_context(path):
        return severity
    return {
        Severity.CRITICAL: Severity.MEDIUM,
        Severity.HIGH: Severity.LOW,
        Severity.MEDIUM: Severity.INFO,
        Severity.LOW: Severity.INFO,
        Severity.INFO: Severity.INFO,
    }[severity]


def _finding(
    rule_id: str,
    severity: Severity,
    category: str,
    title: str,
    description: str,
    remediation: str,
    *,
    path: str | None = None,
    line: int | None = None,
    source: str = "assurance-native",
) -> Finding:
    actual = _contextual_severity(severity, path) if path else severity
    return Finding(
        rule_id=rule_id,
        severity=actual,
        category=category,
        title=title,
        description=description,
        remediation=remediation,
        file_path=path,
        line_number=line,
        source=source,
    )


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _scan_text_patterns(text: str, path: str, collector: _Collector, *, decoded: bool = False) -> set[str]:
    triggered: set[str] = set()
    normalized = unicodedata.normalize("NFKC", text)
    for rule in _TEXT_RULES:
        for match in rule.pattern.finditer(normalized):
            collector.add(
                "static",
                _finding(
                    rule.rule_id,
                    rule.severity,
                    rule.category,
                    rule.title,
                    rule.description,
                    rule.remediation,
                    path=path,
                    line=_line_number(normalized, match.start()),
                    source="assurance-decoded" if decoded else "assurance-native",
                ),
            )
            triggered.add(rule.rule_id)
            break
    return triggered


def _scan_unicode(text: str, path: str, collector: _Collector) -> None:
    if any(character in _BIDI_CONTROLS for character in text):
        collector.add(
            "static",
            _finding(
                "ASSURANCE_BIDI_CONTROL",
                Severity.HIGH,
                "evasion",
                "Bidirectional text control characters",
                "The file contains bidirectional control characters that can make reviewed code differ from displayed code.",
                "Remove bidirectional controls or escape and document the exact code points where linguistically required.",
                path=path,
            ),
        )
    if any(character in _ZERO_WIDTH for character in text):
        collector.add(
            "static",
            _finding(
                "ASSURANCE_ZERO_WIDTH_OBFUSCATION",
                Severity.MEDIUM,
                "evasion",
                "Zero-width characters in executable or instruction content",
                "Invisible Unicode characters can disguise identifiers, commands, URLs, or instructions.",
                "Remove invisible controls from executable and instruction-bearing content.",
                path=path,
            ),
        )
    confusable = any(ord(character) > 127 and unicodedata.category(character).startswith("L") for character in text)
    ascii_security_terms = re.search(r"(?:admin|auth|token|tool|system|security|allow|deny)", text, re.I)
    if confusable and ascii_security_terms:
        collector.add(
            "static",
            _finding(
                "ASSURANCE_CONFUSABLE_IDENTIFIER",
                Severity.MEDIUM,
                "evasion",
                "Potential Unicode-confusable security identifier",
                "Non-ASCII letters appear near security-sensitive identifiers and may create a visual spoofing risk.",
                "Use normalized ASCII identifiers for security-sensitive names and reject mixed-script lookalikes.",
                path=path,
            ),
        )


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(value in {9, 10, 13} or 32 <= value <= 126 for value in data)
    return printable / len(data)


def _scan_obfuscation(text: str, path: str, collector: _Collector) -> set[str]:
    decoded_rule_ids: set[str] = set()
    candidates = 0
    for match in _BASE64_RE.finditer(text):
        if candidates >= MAX_DECODED_CANDIDATES:
            break
        candidates += 1
        value = match.group(0)
        try:
            data = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error):
            continue
        if not 24 <= len(data) <= 64 * 1024 or _printable_ratio(data) < 0.75:
            continue
        decoded = data.decode("utf-8", errors="replace")
        triggered = _scan_text_patterns(decoded, path, collector, decoded=True)
        if triggered:
            decoded_rule_ids.update(triggered)
            collector.add(
                "static",
                _finding(
                    "ASSURANCE_ENCODED_PAYLOAD",
                    Severity.HIGH,
                    "evasion",
                    "Encoded executable or security-sensitive payload",
                    "A bounded decode revealed security-sensitive behavior hidden in Base64 content.",
                    "Store transparent declarative data instead of encoded executable instructions or commands.",
                    path=path,
                    line=_line_number(text, match.start()),
                ),
            )
    for match in _HEX_RE.finditer(text):
        if candidates >= MAX_DECODED_CANDIDATES:
            break
        candidates += 1
        try:
            data = bytes.fromhex(match.group(0))
        except ValueError:
            continue
        if _printable_ratio(data) < 0.75:
            continue
        triggered = _scan_text_patterns(data.decode("utf-8", errors="replace"), path, collector, decoded=True)
        if triggered:
            decoded_rule_ids.update(triggered)
            collector.add(
                "static",
                _finding(
                    "ASSURANCE_ENCODED_PAYLOAD",
                    Severity.HIGH,
                    "evasion",
                    "Encoded executable or security-sensitive payload",
                    "A bounded decode revealed security-sensitive behavior hidden in hexadecimal content.",
                    "Store transparent declarative data instead of encoded executable instructions or commands.",
                    path=path,
                    line=_line_number(text, match.start()),
                ),
            )
    return decoded_rule_ids


def _iter_json_nodes(value: object) -> Iterable[tuple[str, object]]:
    pending: list[tuple[str, object]] = [("$", value)]
    while pending:
        pointer, node = pending.pop()
        yield pointer, node
        if isinstance(node, dict):
            for key in sorted(node, reverse=True):
                pending.append((f"{pointer}.{key}", node[key]))
        elif isinstance(node, list):
            for index in range(len(node) - 1, -1, -1):
                pending.append((f"{pointer}[{index}]", node[index]))


def _scan_package_json(payload: dict[str, Any], path: str, collector: _Collector) -> None:
    scripts = payload.get("scripts")
    if isinstance(scripts, dict):
        for name in ("preinstall", "install", "postinstall", "prepare", "prepublish", "prepack"):
            script = scripts.get(name)
            if not isinstance(script, str) or not script.strip():
                continue
            severity = Severity.HIGH if re.search(r"curl|wget|powershell|node\s+-e|python\s+-c|base64|chmod|sudo", script, re.I) else Severity.MEDIUM
            collector.add(
                "static",
                _finding(
                    "ASSURANCE_PACKAGE_LIFECYCLE_SCRIPT",
                    severity,
                    "supply-chain",
                    "Package lifecycle script",
                    "The package executes code automatically during installation, preparation, or publication.",
                    "Remove automatic lifecycle execution or make the exact, offline-safe behavior reviewable and reproducible.",
                    path=path,
                ),
            )
            _scan_text_patterns(script, path, collector)
    for section_name in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        dependencies = payload.get(section_name)
        if not isinstance(dependencies, dict):
            continue
        for name, version in dependencies.items():
            if not isinstance(version, str):
                continue
            mutable = version.strip().lower() in {"*", "latest", "next", "canary"} or version.startswith(
                ("git+", "git://", "github:", "http://")
            )
            unpinned_vcs = ("github.com" in version or version.startswith("git+")) and not re.search(r"#[0-9a-f]{40}$", version, re.I)
            if mutable or unpinned_vcs:
                collector.add(
                    "static",
                    _finding(
                        "ASSURANCE_MUTABLE_DEPENDENCY",
                        Severity.HIGH if unpinned_vcs else Severity.MEDIUM,
                        "supply-chain",
                        "Mutable dependency source",
                        "A dependency can resolve to different code without a manifest change.",
                        "Pin dependencies to immutable versions and lockfile integrity values; pin VCS sources to a full commit.",
                        path=path,
                    ),
                )
    for key in ("bin", "main", "module", "exports"):
        if key in payload:
            value = payload[key]
            if isinstance(value, str) and (value.startswith("/") or ".." in PurePosixPath(value.replace("\\", "/")).parts):
                collector.add(
                    "static",
                    _finding(
                        "ASSURANCE_UNSAFE_PACKAGE_ENTRYPOINT",
                        Severity.HIGH,
                        "supply-chain",
                        "Unsafe package entry point",
                        "A package entry point is absolute or escapes the package root.",
                        "Use a relative entry point that resolves within the published package.",
                        path=path,
                    ),
                )


def _scan_mcp_json(payload: dict[str, Any], path: str, collector: _Collector) -> None:
    names: dict[str, str] = {}
    for pointer, node in _iter_json_nodes(payload):
        if not isinstance(node, dict):
            continue
        name = node.get("name")
        description = node.get("description")
        if isinstance(name, str):
            normalized = unicodedata.normalize("NFKC", name).casefold().replace("-", "_")
            previous = names.get(normalized)
            if previous is not None and previous != name:
                collector.add(
                    "static",
                    _finding(
                        "ASSURANCE_MCP_TOOL_COLLISION",
                        Severity.HIGH,
                        "mcp-security",
                        "Confusable or colliding MCP tool names",
                        "Multiple tool names normalize to the same security-relevant identifier.",
                        "Use unique normalized tool names and reject duplicate or confusable registrations.",
                        path=path,
                    ),
                )
            names[normalized] = name
        if isinstance(description, str):
            _scan_text_patterns(description, path, collector)
        command = node.get("command")
        args = node.get("args")
        command_text = " ".join(
            [command] + [str(item) for item in args]
            if isinstance(command, str) and isinstance(args, list)
            else [command]
            if isinstance(command, str)
            else []
        )
        if command_text:
            if re.search(r"(?:^|\s)(?:sh|bash|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?)(?:\s|$)", command_text, re.I):
                collector.add(
                    "static",
                    _finding(
                        "ASSURANCE_MCP_SHELL_LAUNCHER",
                        Severity.HIGH,
                        "mcp-security",
                        "MCP server launches through a shell",
                        "The MCP server command uses a general-purpose shell, increasing injection and policy-bypass risk.",
                        "Launch a fixed executable with an argument vector and validate every configured argument.",
                        path=path,
                    ),
                )
            if re.search(r"\b(?:npx|bunx|uvx|pipx)\b", command_text, re.I) and not re.search(
                r"(?:@\d+\.\d+\.\d+|@[0-9a-f]{40}\b|==\d+\.\d+)", command_text, re.I
            ):
                collector.add(
                    "static",
                    _finding(
                        "ASSURANCE_MCP_UNPINNED_RUNNER",
                        Severity.HIGH,
                        "mcp-security",
                        "MCP package runner is not immutably pinned",
                        "The MCP server may download and execute mutable package content at startup.",
                        "Install from a verified lockfile or pin the runner target to an immutable digest or full commit.",
                        path=path,
                    ),
                )
        for key in ("url", "endpoint", "serverUrl", "baseUrl"):
            url = node.get(key)
            if isinstance(url, str) and url.lower().startswith("http://"):
                collector.add(
                    "static",
                    _finding(
                        "ASSURANCE_MCP_PLAINTEXT_TRANSPORT",
                        Severity.HIGH,
                        "mcp-security",
                        "MCP endpoint uses plaintext HTTP",
                        "MCP requests, responses, or bearer credentials can be intercepted or modified in transit.",
                        "Use HTTPS with certificate validation and bind authentication to the intended resource.",
                        path=path,
                    ),
                )
        env = node.get("env")
        if isinstance(env, dict) and any(_SECRET_NAME_RE.search(str(key)) for key in env):
            collector.add(
                "static",
                _finding(
                    "ASSURANCE_MCP_AMBIENT_CREDENTIAL",
                    Severity.HIGH,
                    "mcp-security",
                    "MCP server receives ambient credentials",
                    "Credential-like environment variables are injected directly into an MCP server process.",
                    "Use a narrowly scoped credential broker and grant each server only the minimum token at request time.",
                    path=path,
                ),
            )
        auth = node.get("auth") or node.get("authentication")
        if isinstance(auth, dict) and str(auth.get("type", "")).lower() in {"oauth", "oauth2"}:
            if not any(key in auth for key in ("audience", "resource", "resourceIndicator")):
                collector.add(
                    "static",
                    _finding(
                        "ASSURANCE_MCP_OAUTH_RESOURCE_MISSING",
                        Severity.HIGH,
                        "authorization",
                        "MCP OAuth resource binding is missing",
                        "OAuth configuration does not declare an audience or resource binding for the MCP server.",
                        "Bind authorization requests and access tokens to the exact MCP resource and validate the audience.",
                        path=path,
                    ),
                )


def _scan_structured_text(text: str, path: str, collector: _Collector) -> None:
    suffix = PurePosixPath(path).suffix.lower()
    name = PurePosixPath(path).name.lower()
    if suffix != ".json":
        return
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return
    if not isinstance(payload, dict):
        return
    if name == "package.json":
        _scan_package_json(payload, path, collector)
    if name in {".mcp.json", "mcp.json", "mcp-config.json", "server.json", "plugin.json"} or "mcpServers" in payload:
        _scan_mcp_json(payload, path, collector)
    if "openapi" in payload or "swagger" in payload:
        servers = payload.get("servers")
        if isinstance(servers, list):
            for server in servers:
                if isinstance(server, dict) and str(server.get("url", "")).lower().startswith("http://"):
                    collector.add(
                        "static",
                        _finding(
                            "ASSURANCE_API_PLAINTEXT_SERVER",
                            Severity.MEDIUM,
                            "network-security",
                            "API schema declares a plaintext server",
                            "An API endpoint in the extension schema uses plaintext HTTP.",
                            "Use HTTPS and validate the server identity before sending credentials or sensitive data.",
                            path=path,
                        ),
                    )
        if not payload.get("security") and not payload.get("components", {}).get("securitySchemes") if isinstance(payload.get("components"), dict) else True:
            collector.add(
                "static",
                _finding(
                    "ASSURANCE_API_AUTH_UNDECLARED",
                    Severity.LOW,
                    "authorization",
                    "API schema does not declare authentication",
                    "The API schema does not document a security scheme, so consumers cannot verify the intended authorization boundary.",
                    "Declare the required authentication and authorization scopes in the schema.",
                    path=path,
                ),
            )


def _safe_archive_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    candidate = PurePosixPath(normalized)
    return bool(candidate.parts) and not candidate.is_absolute() and ".." not in candidate.parts and not re.match(r"^[A-Za-z]:", normalized)


def _archive_finding(
    collector: _Collector,
    rule_id: str,
    severity: Severity,
    title: str,
    description: str,
    remediation: str,
    path: str,
) -> None:
    collector.add(
        "archive",
        _finding(
            rule_id,
            severity,
            "archive-security",
            title,
            description,
            remediation,
            path=path,
            source="assurance-archive",
        ),
    )


def _inspect_zip_bytes(data: bytes, label: str, collector: _Collector, coverage: Coverage, depth: int) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ARCHIVE_ENTRIES:
                coverage.archive_partial = True
                _archive_finding(
                    collector,
                    "ASSURANCE_ARCHIVE_ENTRY_LIMIT",
                    Severity.HIGH,
                    "Archive entry limit exceeded",
                    "The archive contains more entries than the bounded scanner can safely inspect.",
                    "Reduce archive size and publish only the files required by the extension.",
                    label,
                )
                entries = entries[:MAX_ARCHIVE_ENTRIES]
            expanded = 0
            compressed = 0
            for info in entries:
                expanded += max(0, info.file_size)
                compressed += max(0, info.compress_size)
                if not _safe_archive_name(info.filename):
                    _archive_finding(
                        collector,
                        "ASSURANCE_ARCHIVE_TRAVERSAL",
                        Severity.CRITICAL,
                        "Archive path traversal",
                        "An archive entry is absolute or escapes its extraction root.",
                        "Reject absolute and parent paths before extraction and verify the resolved destination remains inside the root.",
                        label,
                    )
                unix_mode = (info.external_attr >> 16) & 0xFFFF
                if (unix_mode & 0o170000) == 0o120000:
                    _archive_finding(
                        collector,
                        "ASSURANCE_ARCHIVE_LINK",
                        Severity.HIGH,
                        "Archive contains a symbolic link",
                        "A symbolic-link entry can redirect later writes outside the intended extraction root.",
                        "Reject links in extension archives or validate each final target after extraction into an isolated directory.",
                        label,
                    )
                if info.flag_bits & 0x1:
                    coverage.archive_partial = True
                    _archive_finding(
                        collector,
                        "ASSURANCE_ARCHIVE_ENCRYPTED",
                        Severity.HIGH,
                        "Encrypted archive content",
                        "Encrypted entries cannot be inspected by the static scanner.",
                        "Publish inspectable content or provide separately verified provenance and runtime evidence.",
                        label,
                    )
                suffix = PurePosixPath(info.filename).suffix.lower()
                if depth < MAX_ARCHIVE_DEPTH and suffix in _ARCHIVE_SUFFIXES and info.file_size <= MAX_ARCHIVE_BYTES:
                    try:
                        nested = archive.read(info, pwd=None)
                    except (RuntimeError, OSError, zipfile.BadZipFile):
                        coverage.archive_partial = True
                    else:
                        _inspect_archive_bytes(nested, f"{label}!/{info.filename}", collector, coverage, depth + 1)
            ratio = expanded / max(1, compressed)
            if expanded > MAX_ARCHIVE_EXPANDED_BYTES or ratio > MAX_ARCHIVE_RATIO:
                _archive_finding(
                    collector,
                    "ASSURANCE_ARCHIVE_BOMB",
                    Severity.CRITICAL,
                    "Archive expansion bomb",
                    "Archive metadata exceeds the bounded expansion-size or compression-ratio policy.",
                    "Reject the archive or rebuild it with bounded, reviewable contents.",
                    label,
                )
    except (zipfile.BadZipFile, OSError, RuntimeError):
        coverage.archive_partial = True
        _archive_finding(
            collector,
            "ASSURANCE_ARCHIVE_MALFORMED",
            Severity.HIGH,
            "Malformed or unsupported ZIP archive",
            "The archive could not be enumerated safely and completely.",
            "Rebuild the archive using a supported format and deterministic tooling.",
            label,
        )


def _inspect_tar_bytes(data: bytes, label: str, collector: _Collector, coverage: Coverage, depth: int) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            entries = archive.getmembers()
            if len(entries) > MAX_ARCHIVE_ENTRIES:
                coverage.archive_partial = True
                entries = entries[:MAX_ARCHIVE_ENTRIES]
                _archive_finding(
                    collector,
                    "ASSURANCE_ARCHIVE_ENTRY_LIMIT",
                    Severity.HIGH,
                    "Archive entry limit exceeded",
                    "The archive contains more entries than the bounded scanner can safely inspect.",
                    "Reduce archive size and publish only the files required by the extension.",
                    label,
                )
            expanded = 0
            for member in entries:
                expanded += max(0, member.size)
                if not _safe_archive_name(member.name):
                    _archive_finding(
                        collector,
                        "ASSURANCE_ARCHIVE_TRAVERSAL",
                        Severity.CRITICAL,
                        "Archive path traversal",
                        "An archive entry is absolute or escapes its extraction root.",
                        "Reject absolute and parent paths before extraction and verify the resolved destination remains inside the root.",
                        label,
                    )
                if member.issym() or member.islnk():
                    _archive_finding(
                        collector,
                        "ASSURANCE_ARCHIVE_LINK",
                        Severity.HIGH,
                        "Archive contains a symbolic or hard link",
                        "A link entry can redirect reads or writes outside the intended extraction root.",
                        "Reject archive links or resolve and validate each destination in an isolated extraction root.",
                        label,
                    )
                suffix = PurePosixPath(member.name).suffix.lower()
                if depth < MAX_ARCHIVE_DEPTH and member.isfile() and suffix in _ARCHIVE_SUFFIXES and member.size <= MAX_ARCHIVE_BYTES:
                    extracted = archive.extractfile(member)
                    if extracted is not None:
                        nested = extracted.read(MAX_ARCHIVE_BYTES + 1)
                        if len(nested) <= MAX_ARCHIVE_BYTES:
                            _inspect_archive_bytes(nested, f"{label}!/{member.name}", collector, coverage, depth + 1)
                        else:
                            coverage.archive_partial = True
            if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
                _archive_finding(
                    collector,
                    "ASSURANCE_ARCHIVE_BOMB",
                    Severity.CRITICAL,
                    "Archive expansion bomb",
                    "Archive metadata exceeds the bounded expansion-size policy.",
                    "Reject the archive or rebuild it with bounded, reviewable contents.",
                    label,
                )
    except (tarfile.TarError, OSError, EOFError):
        coverage.archive_partial = True
        _archive_finding(
            collector,
            "ASSURANCE_ARCHIVE_MALFORMED",
            Severity.HIGH,
            "Malformed or unsupported TAR archive",
            "The archive could not be enumerated safely and completely.",
            "Rebuild the archive using a supported deterministic format.",
            label,
        )


def _inspect_archive_bytes(data: bytes, label: str, collector: _Collector, coverage: Coverage, depth: int = 0) -> None:
    if depth > MAX_ARCHIVE_DEPTH:
        coverage.archive_partial = True
        return
    if data.startswith(b"PK\x03\x04"):
        _inspect_zip_bytes(data, label, collector, coverage, depth)
        return
    try:
        if tarfile.is_tarfile(io.BytesIO(data)):
            _inspect_tar_bytes(data, label, collector, coverage, depth)
            return
    except (OSError, tarfile.TarError):
        pass
    coverage.archive_partial = True


def _inspect_archive(path: Path, relative: str, collector: _Collector, coverage: Coverage, budget: ScanBudget) -> None:
    coverage.archives += 1
    try:
        size = path.stat().st_size
    except OSError:
        coverage.unreadable_files += 1
        coverage.archive_partial = True
        return
    if size > budget.max_archive_bytes:
        coverage.oversized_files += 1
        coverage.archive_partial = True
        _archive_finding(
            collector,
            "ASSURANCE_ARCHIVE_SCAN_LIMIT",
            Severity.MEDIUM,
            "Archive exceeds static inspection limit",
            "The archive is larger than the bounded static inspection budget.",
            "Publish smaller deterministic artifacts or require isolated runtime and provenance evidence.",
            relative,
        )
        return
    try:
        data = path.read_bytes()
    except OSError:
        coverage.unreadable_files += 1
        coverage.archive_partial = True
        return
    suffix = path.suffix.lower()
    if suffix in {".7z", ".rar"}:
        coverage.archive_partial = True
        _archive_finding(
            collector,
            "ASSURANCE_ARCHIVE_FORMAT_UNSUPPORTED",
            Severity.MEDIUM,
            "Archive format requires an external analyzer",
            "The archive format is recognized but is not parsed by the dependency-free scanner path.",
            "Use ZIP or TAR for inspectable publication or supply independently verified analysis evidence.",
            relative,
        )
        return
    _inspect_archive_bytes(data, relative, collector, coverage)


def _inspect_native(record: InventoryRecord, collector: _Collector, coverage: Coverage, *, engine: str) -> None:
    coverage.native_files += 1
    severity = Severity.MEDIUM if record.format in {"elf", "pe", "mach-o"} else Severity.LOW
    collector.add(
        "native",
        _finding(
            "ASSURANCE_NATIVE_ARTIFACT",
            severity,
            "native-security",
            "Native or WebAssembly executable content",
            "The extension contains executable content that requires structural and runtime review beyond source scanning.",
            "Publish reproducible build provenance, immutable hashes, hardening metadata, and isolated runtime evidence.",
            path=record.path,
            source=f"assurance-{engine}-kernel",
        ),
    )
    indicator_severity = {
        "cloud-metadata": Severity.CRITICAL,
        "container-socket": Severity.CRITICAL,
        "credential-store": Severity.HIGH,
        "browser-credential-store": Severity.CRITICAL,
        "wallet-store": Severity.CRITICAL,
        "process-injection": Severity.CRITICAL,
        "persistence": Severity.HIGH,
        "crypto-mining": Severity.HIGH,
        "input-capture": Severity.CRITICAL,
        "process-execution": Severity.MEDIUM,
    }
    for indicator in record.indicators:
        collector.add(
            "native",
            _finding(
                "ASSURANCE_NATIVE_SENSITIVE_CAPABILITY",
                indicator_severity.get(indicator, Severity.MEDIUM),
                "native-security",
                "Sensitive capability indicator in executable content",
                f"Bounded native inspection identified the capability class: {indicator}.",
                "Review the binary origin, imports, reproducible build, signature, and isolated runtime behavior.",
                path=record.path,
                source=f"assurance-{engine}-kernel",
            ),
        )
    if record.format in {"elf", "pe", "mach-o"} and not record.hardening:
        collector.add(
            "native",
            _finding(
                "ASSURANCE_NATIVE_HARDENING_UNPROVEN",
                Severity.MEDIUM,
                "native-security",
                "Native hardening could not be proven",
                "The bounded parser did not prove expected platform hardening for this executable.",
                "Build with platform hardening, publish build metadata, and validate with a dedicated binary analyzer.",
                path=record.path,
                source=f"assurance-{engine}-kernel",
            ),
        )
    coverage.native_partial = True


def _root_digest(records: tuple[InventoryRecord, ...]) -> str:
    hasher = hashlib.sha256()
    for record in records:
        hasher.update(record.path.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(str(record.size).encode("ascii"))
        hasher.update(b"\0")
        hasher.update((record.sha256 or f"[{record.kind}:{record.error or 'unhashed'}]").encode("utf-8"))
        hasher.update(b"\n")
    return hasher.hexdigest()


def _load_runtime_layer(root: Path, target_digest: str) -> tuple[str, tuple[str, ...]]:
    path = root / ".hol-guard" / "runtime-evidence.json"
    if not path.is_file():
        return "not-run", ("No bounded runtime detonation evidence was supplied.",)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "failed", ("Runtime evidence is unreadable or malformed.",)
    return validate_runtime_evidence(payload, target_digest=target_digest)


def _layer_status(findings: tuple[Finding, ...], *, complete: bool, absent_ok: bool = False, present: bool = True) -> str:
    if absent_ok and not present:
        return "complete"
    if not complete:
        return "partial"
    return "complete"


def _layer_check(name: str, findings: tuple[Finding, ...], *, complete: bool, max_points: int = 10) -> CheckResult:
    blocking = [finding for finding in findings if SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[Severity.HIGH]]
    passed = complete and not blocking
    points = max_points if passed else max_points // 2 if complete and not any(f.severity == Severity.CRITICAL for f in findings) else 0
    message = (
        "Layer completed without high-severity findings."
        if passed
        else f"Layer emitted {len(findings)} finding(s); complete={str(complete).lower()}."
    )
    return CheckResult(name=name, passed=passed, points=points, max_points=max_points, message=message, findings=findings)


def _integration(
    layer_id: str,
    status: str,
    findings: tuple[Finding, ...],
    *,
    analyzer: str,
    coverage_percent: float,
    digest: str,
    limitations: tuple[str, ...] = (),
) -> IntegrationResult:
    metadata = {
        "layer": layer_id,
        "analyzer": analyzer,
        "coverage_percent": f"{coverage_percent:.2f}",
        "evidence_digest": digest,
        "high_or_critical": str(
            sum(SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[Severity.HIGH] for finding in findings)
        ),
        "limitations": " | ".join(limitations[:8]),
    }
    return IntegrationResult(
        name=f"assurance-{layer_id}",
        status=status,
        message=f"{layer_id} evidence is {status}; {len(findings)} finding(s).",
        findings_count=len(findings),
        metadata=metadata,
    )


def _correlate(collector: _Collector) -> None:
    findings = collector.all()
    ids = {finding.rule_id for finding in findings}
    by_path: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        if finding.file_path:
            by_path[finding.file_path].add(finding.rule_id)
    for path, path_ids in sorted(by_path.items()):
        if "ASSURANCE_CREDENTIAL_ACCESS" in path_ids and (
            "ASSURANCE_SSRF" in path_ids or "ASSURANCE_SECRET_EXFILTRATION" in path_ids
        ):
            collector.add(
                "static",
                _finding(
                    "ASSURANCE_CORRELATED_CREDENTIAL_EXFILTRATION",
                    Severity.CRITICAL,
                    "correlation",
                    "Credential access combined with outbound networking",
                    "The same file contains credential-access and outbound-request behavior, increasing exfiltration risk.",
                    "Separate credential access from networking and enforce a destination-bound, least-privilege broker.",
                    path=path,
                ),
            )
        if "ASSURANCE_ENCODED_PAYLOAD" in path_ids and (
            "ASSURANCE_DYNAMIC_EXECUTION" in path_ids or "ASSURANCE_COMMAND_INJECTION" in path_ids
        ):
            collector.add(
                "static",
                _finding(
                    "ASSURANCE_CORRELATED_OBFUSCATED_EXECUTION",
                    Severity.CRITICAL,
                    "correlation",
                    "Obfuscation combined with code execution",
                    "Encoded content and a dynamic execution surface occur in the same file.",
                    "Remove encoded executable content and dynamic evaluation.",
                    path=path,
                ),
            )
        if "ASSURANCE_PROMPT_INJECTION" in path_ids and "ASSURANCE_CREDENTIAL_ACCESS" in path_ids:
            collector.add(
                "static",
                _finding(
                    "ASSURANCE_CORRELATED_PROMPT_CREDENTIAL_ACCESS",
                    Severity.CRITICAL,
                    "correlation",
                    "Instruction override combined with credential access",
                    "Instruction-manipulation content and credential-store access occur in the same artifact path.",
                    "Remove policy overrides and require a separate, user-approved credential boundary.",
                    path=path,
                ),
            )
    if "ASSURANCE_NATIVE_ARTIFACT" in ids and "ASSURANCE_DOWNLOAD_EXECUTE" in ids:
        collector.add(
            "native",
            _finding(
                "ASSURANCE_CORRELATED_NATIVE_DELIVERY",
                Severity.CRITICAL,
                "correlation",
                "Native executable combined with mutable delivery",
                "The extension contains native code and a download-and-execute path.",
                "Remove mutable delivery and require immutable signed artifacts with reproducible build evidence.",
            ),
        )


def run_assurance_checks(
    root: str | Path,
    budget: ScanBudget | None = None,
) -> tuple[tuple[CheckResult, ...], tuple[IntegrationResult, ...]]:
    """Run layered assurance checks without executing the target."""

    resolved = Path(root).resolve()
    actual_budget = budget or ScanBudget()
    collector = _Collector()
    coverage = Coverage()
    try:
        kernel = scan_inventory(
            resolved,
            max_files=actual_budget.max_files,
            max_bytes=actual_budget.max_hashed_bytes,
        )
    except Exception as exc:
        failure = _finding(
            "ASSURANCE_INVENTORY_FAILED",
            Severity.HIGH,
            "coverage",
            "Assurance inventory failed",
            f"The deterministic file inventory failed with {exc.__class__.__name__}.",
            "Repair filesystem access or run the scanner in a clean, readable copy of the extension.",
        )
        check = CheckResult(
            name="Assurance inventory",
            passed=False,
            points=0,
            max_points=50,
            message="Layered assurance could not inventory the target.",
            findings=(failure,),
        )
        integration = _integration(
            "static",
            "failed",
            (failure,),
            analyzer="unavailable",
            coverage_percent=0.0,
            digest=hashlib.sha256(str(resolved).encode()).hexdigest(),
            limitations=("No assurance claims were produced.",),
        )
        return (check,), (integration,)

    coverage.truncated = kernel.truncated
    coverage.excluded_directories = kernel.excluded_directories
    target_digest = _root_digest(kernel.records)
    feature_ids_by_path: dict[str, set[str]] = defaultdict(set)

    for record in kernel.records:
        path = resolved / record.path
        try:
            safe_path = path.resolve(strict=False)
        except OSError:
            safe_path = path
        if not safe_path.is_relative_to(resolved) and record.kind != "symlink":
            collector.add(
                "static",
                _finding(
                    "ASSURANCE_PATH_ESCAPED_ROOT",
                    Severity.HIGH,
                    "coverage",
                    "Inventory path escaped the scan root",
                    "A filesystem path resolved outside the selected extension root.",
                    "Scan a clean copy and reject filesystem objects that resolve outside the artifact root.",
                    path=record.path,
                ),
            )
            continue
        if record.kind == "symlink":
            if record.symlink_escapes_root:
                collector.add(
                    "static",
                    _finding(
                        "ASSURANCE_SYMLINK_ESCAPE",
                        Severity.HIGH,
                        "filesystem-security",
                        "Symbolic link escapes the extension root",
                        "A symbolic link resolves outside the scanned artifact and can hide or redirect content.",
                        "Remove escaping links and package real, reviewable content inside the artifact.",
                        path=record.path,
                    ),
                )
            continue
        if record.error:
            coverage.unreadable_files += 1
        if record.format in _NATIVE_FORMATS:
            _inspect_native(record, collector, coverage, engine=kernel.engine)
        suffix = path.suffix.lower()
        if record.format in {"zip", "gzip", "archive", "7z", "rar"} or suffix in _ARCHIVE_SUFFIXES:
            _inspect_archive(path, record.path, collector, coverage, actual_budget)
        is_text = record.format == "text" or suffix in _TEXT_EXTENSIONS or path.name.startswith(".")
        if not is_text or record.size > actual_budget.max_text_file_bytes:
            if is_text and record.size > actual_budget.max_text_file_bytes:
                coverage.oversized_files += 1
            elif record.format in {"binary", None} and record.format not in _NATIVE_FORMATS:
                coverage.opaque_files += 1
            continue
        if coverage.text_bytes + record.size > actual_budget.max_total_text_bytes:
            coverage.truncated = True
            break
        try:
            raw = path.read_bytes()
        except OSError:
            coverage.unreadable_files += 1
            continue
        coverage.text_bytes += len(raw)
        coverage.text_files += 1
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            coverage.invalid_utf8_files += 1
            text = raw.decode("utf-8", errors="replace")
        _scan_unicode(text, record.path, collector)
        feature_ids_by_path[record.path].update(_scan_text_patterns(text, record.path, collector))
        feature_ids_by_path[record.path].update(_scan_obfuscation(text, record.path, collector))
        _scan_structured_text(text, record.path, collector)

    if coverage.truncated or coverage.unreadable_files or coverage.oversized_files:
        collector.add(
            "static",
            _finding(
                "ASSURANCE_COVERAGE_INCOMPLETE",
                Severity.MEDIUM,
                "coverage",
                "Static assurance coverage is incomplete",
                "Resource limits, unreadable files, or oversized content prevented complete supported-format inspection.",
                "Reduce artifact size, repair access, or raise a documented bounded scan policy in an isolated environment.",
            ),
        )
    _correlate(collector)

    static_findings = collector.layer("static")
    archive_findings = collector.layer("archive")
    native_findings = collector.layer("native")
    inventory_denominator = max(1, len(kernel.records))
    gaps = coverage.unreadable_files + coverage.oversized_files + coverage.opaque_files
    coverage_percent = max(0.0, 100.0 * (inventory_denominator - min(inventory_denominator, gaps)) / inventory_denominator)
    static_complete = not coverage.truncated and coverage.unreadable_files == 0 and coverage.oversized_files == 0
    archive_complete = not coverage.archive_partial
    native_complete = coverage.native_files == 0

    attestation = verify_attestation(
        resolved / ".hol-guard" / "attestation.json",
        target_digest=target_digest,
    )
    provenance_status = "verified" if attestation.status == "verified" else "partial" if attestation.status == "self-attested" else "unavailable" if attestation.status == "absent" else "failed"
    provenance_findings: tuple[Finding, ...] = ()
    if attestation.status == "failed":
        provenance_findings = (
            _finding(
                "ASSURANCE_PROVENANCE_INVALID",
                Severity.HIGH,
                "provenance",
                "Artifact attestation failed verification",
                attestation.reason,
                "Regenerate the attestation for the exact artifact digest and sign it with a caller-trusted publisher key.",
                path=".hol-guard/attestation.json",
                source="assurance-provenance",
            ),
        )
    elif attestation.status in {"absent", "self-attested"}:
        provenance_findings = (
            _finding(
                "ASSURANCE_PROVENANCE_UNTRUSTED",
                Severity.LOW if attestation.status == "absent" else Severity.INFO,
                "provenance",
                "Publisher provenance is not independently trusted",
                attestation.reason,
                "Provide an attestation signed by a key in the consumer-controlled trust root.",
                path=".hol-guard/attestation.json" if attestation.status != "absent" else None,
                source="assurance-provenance",
            ),
        )

    runtime_status, runtime_limitations = _load_runtime_layer(resolved, target_digest)
    runtime_findings: tuple[Finding, ...] = ()
    if runtime_status == "failed":
        runtime_findings = (
            _finding(
                "ASSURANCE_RUNTIME_EVIDENCE_INVALID",
                Severity.HIGH,
                "runtime-assurance",
                "Runtime assurance evidence is invalid",
                runtime_limitations[0] if runtime_limitations else "Runtime evidence failed validation.",
                "Rerun bounded detonation against the exact artifact digest with every mandatory containment control.",
                path=".hol-guard/runtime-evidence.json",
                source="assurance-runtime",
            ),
        )
    elif runtime_status in {"not-run", "partial"}:
        runtime_findings = (
            _finding(
                "ASSURANCE_RUNTIME_UNPROVEN",
                Severity.INFO if runtime_status == "not-run" else Severity.LOW,
                "runtime-assurance",
                "Runtime behavior is not fully proven",
                runtime_limitations[0] if runtime_limitations else "No complete runtime evidence is available.",
                "Run the explicit bounded detonation workflow and preserve complete trace evidence for the exact digest.",
                source="assurance-runtime",
            ),
        )

    checks = (
        _layer_check("Static adversarial analysis", static_findings, complete=static_complete),
        _layer_check("Archive safety analysis", archive_findings, complete=archive_complete),
        _layer_check("Native and WebAssembly analysis", native_findings, complete=native_complete),
        _layer_check("Publisher provenance", provenance_findings, complete=provenance_status == "verified"),
        _layer_check("Bounded runtime assurance", runtime_findings, complete=runtime_status == "verified"),
    )

    layer_payloads = {
        "static": {
            "status": _layer_status(static_findings, complete=static_complete),
            "findings": [finding.rule_id for finding in static_findings],
            "coverage": coverage_percent,
        },
        "archive": {
            "status": _layer_status(archive_findings, complete=archive_complete, absent_ok=True, present=coverage.archives > 0),
            "findings": [finding.rule_id for finding in archive_findings],
            "archives": coverage.archives,
        },
        "native": {
            "status": "complete" if coverage.native_files == 0 else "partial",
            "findings": [finding.rule_id for finding in native_findings],
            "nativeFiles": coverage.native_files,
        },
        "provenance": {"status": provenance_status, "keyId": attestation.key_id},
        "runtime": {"status": runtime_status},
    }
    integrations = (
        _integration(
            "static",
            layer_payloads["static"]["status"],
            static_findings,
            analyzer=f"{kernel.engine}-kernel+python-rules/{ASSURANCE_VERSION}",
            coverage_percent=coverage_percent,
            digest=hashlib.sha256(json.dumps(layer_payloads["static"], sort_keys=True).encode()).hexdigest(),
            limitations=(
                f"excluded_directories={coverage.excluded_directories}",
                f"invalid_utf8_files={coverage.invalid_utf8_files}",
            ),
        ),
        _integration(
            "archive",
            layer_payloads["archive"]["status"],
            archive_findings,
            analyzer="bounded-in-memory-archive-parser",
            coverage_percent=100.0 if archive_complete else 50.0,
            digest=hashlib.sha256(json.dumps(layer_payloads["archive"], sort_keys=True).encode()).hexdigest(),
            limitations=("Nested archive depth and expansion are strictly bounded.",),
        ),
        _integration(
            "native",
            layer_payloads["native"]["status"],
            native_findings,
            analyzer=f"{kernel.engine}-kernel-headers-and-strings",
            coverage_percent=100.0 if coverage.native_files == 0 else 60.0,
            digest=hashlib.sha256(json.dumps(layer_payloads["native"], sort_keys=True).encode()).hexdigest(),
            limitations=(
                "Structural parsing and bounded strings are not equivalent to complete disassembly or decompilation.",
                "Runtime behavior requires separate bounded detonation evidence.",
            ),
        ),
        _integration(
            "provenance",
            provenance_status,
            provenance_findings,
            analyzer="dsse-ed25519-in-toto",
            coverage_percent=100.0 if provenance_status == "verified" else 0.0,
            digest=hashlib.sha256(json.dumps(layer_payloads["provenance"], sort_keys=True).encode()).hexdigest(),
            limitations=(() if provenance_status == "verified" else (attestation.reason,)),
        ),
        _integration(
            "runtime",
            runtime_status,
            runtime_findings,
            analyzer="oci-deny-by-default-detonation",
            coverage_percent=100.0 if runtime_status == "verified" else 50.0 if runtime_status == "partial" else 0.0,
            digest=hashlib.sha256(json.dumps(layer_payloads["runtime"], sort_keys=True).encode()).hexdigest(),
            limitations=runtime_limitations,
        ),
        IntegrationResult(
            name="assurance-target",
            status="complete" if static_complete else "partial",
            message="Deterministic target digest and coverage inventory generated.",
            metadata={
                "target_digest": target_digest,
                "kernel": kernel.engine,
                "files_seen": str(kernel.files_seen),
                "bytes_hashed": str(kernel.bytes_hashed),
                "coverage_percent": f"{coverage_percent:.2f}",
                "opaque_files": str(coverage.opaque_files),
                "unreadable_files": str(coverage.unreadable_files),
                "oversized_files": str(coverage.oversized_files),
                "truncated": str(coverage.truncated).lower(),
            },
        ),
    )
    return checks, integrations
