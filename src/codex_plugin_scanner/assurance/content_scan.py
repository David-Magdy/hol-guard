"""Bounded multi-language content scanning for common extension attack vectors."""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from pathlib import Path

from .inventory import InventoryEntry
from .limits import ScanLimits
from .models import Confidence, EvidenceLocation, SecurityFinding, Severity


TEXT_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".json",
        ".jsonc",
        ".yaml",
        ".yml",
        ".toml",
        ".xml",
        ".html",
        ".htm",
        ".md",
        ".mdx",
        ".txt",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".ps1",
        ".bat",
        ".cmd",
        ".rb",
        ".php",
        ".java",
        ".kt",
        ".kts",
        ".go",
        ".rs",
        ".c",
        ".cc",
        ".cpp",
        ".h",
        ".hpp",
        ".cs",
        ".swift",
        ".lua",
        ".sql",
        ".graphql",
        ".gql",
        ".ini",
        ".cfg",
        ".conf",
        ".env",
    }
)


@dataclass(frozen=True, slots=True)
class PatternRule:
    rule_id: str
    category: str
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    remediation: str
    patterns: tuple[re.Pattern[str], ...]
    capability: str | None = None
    file_suffixes: tuple[str, ...] = ()


def _patterns(*values: str, flags: int = re.IGNORECASE) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(value, flags) for value in values)


RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "ASSURANCE_COMMAND_INJECTION",
        "code-execution",
        Severity.HIGH,
        Confidence.MEDIUM,
        "Untrusted data may reach a shell",
        "The code combines shell execution with interpolation or caller-controlled values.",
        "Pass an argument vector without a shell and validate each argument against an allowlist.",
        _patterns(
            r"(?:exec|spawn|system|popen|subprocess\.(?:run|call|Popen))\s*\([^\n]{0,240}(?:shell\s*=\s*True|\$\{|\+\s*(?:req|request|input|args|params|query|body)|f[\"'])",
            r"child_process\.(?:exec|execSync)\s*\([^\n]{0,240}(?:req\.|request\.|params\.|query\.|body\.|\$\{)",
            r"(?:bash|sh|cmd|powershell)(?:\.exe)?\s+-[cC]\s+[\"'][^\n]{0,220}(?:\$\{|%\w+%|\+)",
        ),
        "process-execution",
    ),
    PatternRule(
        "ASSURANCE_DYNAMIC_CODE_EXECUTION",
        "code-execution",
        Severity.HIGH,
        Confidence.MEDIUM,
        "Dynamic code execution surface",
        "Dynamic evaluation or compilation can turn extension-controlled content into executable code.",
        "Remove dynamic evaluation or constrain input to a non-executable grammar.",
        _patterns(
            r"\b(?:eval|exec|compile)\s*\([^\n]{0,240}(?:request|input|payload|content|args|params|body|query)",
            r"\bnew\s+Function\s*\([^\n]{0,240}(?:request|input|payload|content|args|params|body|query)",
            r"\bvm\.(?:runInNewContext|runInThisContext|compileFunction)\s*\(",
        ),
        "dynamic-code",
    ),
    PatternRule(
        "ASSURANCE_DOWNLOAD_EXECUTE",
        "code-execution",
        Severity.CRITICAL,
        Confidence.HIGH,
        "Download-and-execute chain",
        "A network download is piped to or followed by a command interpreter.",
        "Vendor a verified artifact, pin its digest, and never pipe network content into an interpreter.",
        _patterns(
            r"(?:curl|wget)[^\n|;]{0,300}(?:\||&&|;)\s*(?:sudo\s+)?(?:bash|sh|zsh|python|node|powershell)",
            r"Invoke-WebRequest[^\n]{0,300}\|[^\n]{0,120}Invoke-Expression",
        ),
        "network-and-execution",
    ),
    PatternRule(
        "ASSURANCE_SSRF",
        "network",
        Severity.HIGH,
        Confidence.MEDIUM,
        "Caller-controlled outbound request",
        "A URL from caller-controlled input appears to reach an outbound request API.",
        "Parse once, allowlist scheme and host, resolve and reject non-public addresses, and disable redirects.",
        _patterns(
            r"(?:requests\.(?:get|post|put|delete|request)|urllib\.request\.urlopen|httpx\.(?:get|post|request)|fetch|axios\.(?:get|post|request))\s*\([^\n]{0,240}(?:request|input|payload|url|params|query|body)",
            r"new\s+URL\s*\([^\n]{0,120}(?:request|input|params|query|body)[^\n]{0,240}(?:fetch|axios|request)",
        ),
        "outbound-network",
    ),
    PatternRule(
        "ASSURANCE_CLOUD_METADATA_ACCESS",
        "credential-access",
        Severity.CRITICAL,
        Confidence.HIGH,
        "Cloud metadata service access",
        "The extension references a cloud instance metadata or workload identity endpoint.",
        "Remove metadata access and use explicitly scoped workload credentials.",
        _patterns(
            r"169\.254\.169\.254",
            r"metadata\.google\.internal",
            r"100\.100\.100\.200",
            r"169\.254\.170\.2",
            r"/latest/meta-data/",
        ),
        "cloud-metadata",
    ),
    PatternRule(
        "ASSURANCE_PATH_TRAVERSAL",
        "filesystem",
        Severity.HIGH,
        Confidence.MEDIUM,
        "Untrusted path reaches filesystem operation",
        "Caller-controlled path data appears to reach a filesystem operation without a containment check.",
        "Resolve against a fixed root, reject absolute and parent segments, then verify the resolved path remains inside the root.",
        _patterns(
            r"(?:open|readFile|writeFile|unlink|remove|rmtree|send_file|sendFile|extract)\s*\([^\n]{0,220}(?:request|input|payload|params|query|body|filename|path)",
            r"(?:join|resolve)\s*\([^\n]{0,160}(?:request|input|params|query|body)[^\n]{0,220}(?:open|readFile|writeFile|unlink)",
        ),
        "filesystem-write",
    ),
    PatternRule(
        "ASSURANCE_ARCHIVE_TRAVERSAL_API",
        "archive",
        Severity.HIGH,
        Confidence.MEDIUM,
        "Archive extraction API without visible containment",
        "The extension extracts an archive directly to disk.",
        "Inspect entries in memory, reject links and traversal, enforce expansion limits, and extract only after containment validation.",
        _patterns(
            r"\.(?:extractall|extractAllTo|unpack|decompress)\s*\(",
            r"tar\s+-x(?:f|z|j|J)",
        ),
        "archive-extraction",
    ),
    PatternRule(
        "ASSURANCE_XXE",
        "parser",
        Severity.HIGH,
        Confidence.MEDIUM,
        "XML parser may allow external entities",
        "XML parsing is enabled without an evident external-entity prohibition.",
        "Use a hardened parser with DTD and external entity resolution disabled.",
        _patterns(
            r"(?:etree|ElementTree|DocumentBuilderFactory|SAXParserFactory|DOMParser)\b[^\n]{0,260}(?:parse|fromstring|newDocumentBuilder)",
            r"libxml_disable_entity_loader\s*\(\s*false",
        ),
        "xml-parsing",
        (".xml", ".py", ".java", ".kt", ".php", ".js", ".ts"),
    ),
    PatternRule(
        "ASSURANCE_UNSAFE_DESERIALIZATION",
        "parser",
        Severity.HIGH,
        Confidence.HIGH,
        "Unsafe deserialization primitive",
        "The extension uses a deserializer capable of constructing executable objects.",
        "Use a data-only format and a safe loader with strict schemas.",
        _patterns(
            r"pickle\.(?:load|loads)\s*\(",
            r"yaml\.(?:load|unsafe_load)\s*\([^\n]{0,180}(?!SafeLoader)",
            r"ObjectInputStream\s*\(",
            r"BinaryFormatter\b",
            r"Marshal\.load\s*\(",
            r"unserialize\s*\(",
        ),
        "unsafe-deserialization",
    ),
    PatternRule(
        "ASSURANCE_PROTOTYPE_POLLUTION",
        "object-integrity",
        Severity.HIGH,
        Confidence.MEDIUM,
        "Prototype pollution surface",
        "Recursive merge or dynamic property assignment can modify object prototypes.",
        "Reject __proto__, prototype, and constructor keys and use null-prototype maps for untrusted objects.",
        _patterns(
            r"(?:deepmerge|lodash\.merge|\.merge)\s*\([^\n]{0,180}(?:request|input|payload|body|query)",
            r"\[[^\]]*(?:request|input|key|property)[^\]]*\]\s*=",
            r"__proto__|constructor\.prototype",
        ),
        "object-mutation",
        (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"),
    ),
    PatternRule(
        "ASSURANCE_SQL_INJECTION",
        "injection",
        Severity.HIGH,
        Confidence.MEDIUM,
        "Untrusted data may be interpolated into SQL",
        "Caller-controlled data appears in a SQL statement passed to a database API.",
        "Use parameterized queries and prohibit dynamic identifier construction.",
        _patterns(
            r"(?:execute|query|raw)\s*\([^\n]{0,300}(?:SELECT|INSERT|UPDATE|DELETE)[^\n]{0,200}(?:request|input|params|query|body|\$\{|f[\"']|\.format\()",
            r"(?:SELECT|INSERT|UPDATE|DELETE)[^\n]{0,220}(?:\+\s*(?:request|input|params|query|body)|\$\{)",
        ),
        "database-access",
    ),
    PatternRule(
        "ASSURANCE_NOSQL_INJECTION",
        "injection",
        Severity.HIGH,
        Confidence.MEDIUM,
        "Untrusted object reaches a NoSQL query",
        "A caller-controlled object appears to be used directly as a NoSQL selector.",
        "Build selectors from an allowlisted schema and reject operator-prefixed keys.",
        _patterns(
            r"\.(?:find|findOne|updateOne|deleteOne|aggregate)\s*\([^\n]{0,220}(?:request\.body|req\.body|payload|input|query)",
            r"\$(?:where|regex|expr|function)\b",
        ),
        "database-access",
    ),
    PatternRule(
        "ASSURANCE_XSS",
        "web",
        Severity.HIGH,
        Confidence.MEDIUM,
        "Untrusted content reaches an HTML execution sink",
        "Caller-controlled content appears to reach an HTML or script sink.",
        "Use contextual output encoding and avoid raw HTML sinks.",
        _patterns(
            r"(?:innerHTML|outerHTML|dangerouslySetInnerHTML|document\.write)\s*(?:=|:)\s*[^\n]{0,220}(?:request|input|payload|params|query|body)",
            r"render_template_string\s*\([^\n]{0,200}(?:request|input|payload)",
        ),
        "web-content",
    ),
    PatternRule(
        "ASSURANCE_OPEN_REDIRECT",
        "web",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        "Caller-controlled redirect target",
        "A redirect target appears to come from request data.",
        "Use fixed route identifiers or allowlist same-origin destinations after canonical parsing.",
        _patterns(
            r"(?:redirect|location\.assign|location\.replace)\s*\([^\n]{0,180}(?:request|req\.|params|query|body|input)",
            r"Location[\"']?\s*[:=]\s*[^\n]{0,180}(?:request|params|query|body|input)",
        ),
        "web-redirect",
    ),
    PatternRule(
        "ASSURANCE_HEADER_INJECTION",
        "web",
        Severity.HIGH,
        Confidence.MEDIUM,
        "Untrusted data reaches an HTTP header",
        "Request-controlled data appears to be copied into a response or outbound header.",
        "Reject CR and LF and use framework APIs that validate header values.",
        _patterns(
            r"(?:setHeader|headers?\s*\[|add_header)\s*[^\n]{0,240}(?:request|params|query|body|input)",
        ),
        "http-headers",
    ),
    PatternRule(
        "ASSURANCE_TLS_VERIFICATION_DISABLED",
        "transport",
        Severity.HIGH,
        Confidence.HIGH,
        "TLS certificate verification disabled",
        "The extension disables certificate or hostname verification.",
        "Use the platform trust store and verify both certificate chain and hostname.",
        _patterns(
            r"verify\s*=\s*False",
            r"rejectUnauthorized\s*:\s*false",
            r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0",
            r"InsecureSkipVerify\s*:\s*true",
            r"CURLOPT_SSL_VERIFYPEER\s*,\s*false",
        ),
        "insecure-transport",
    ),
    PatternRule(
        "ASSURANCE_SECRET_EXFILTRATION",
        "credential-access",
        Severity.CRITICAL,
        Confidence.MEDIUM,
        "Credential collection combined with outbound transfer",
        "The same file accesses credential material and performs outbound transfer.",
        "Remove credential harvesting and restrict outbound network access by policy.",
        _patterns(
            r"(?:\.aws/credentials|\.ssh/id_|keychain|credential|token|api[_-]?key|secret)[\s\S]{0,1200}(?:fetch\(|axios|requests\.|curl\s|webhook|socket\.connect)",
            r"(?:fetch\(|axios|requests\.|curl\s|webhook|socket\.connect)[\s\S]{0,1200}(?:\.aws/credentials|\.ssh/id_|keychain|credential|token|api[_-]?key|secret)",
        ),
        "credential-store",
    ),
    PatternRule(
        "ASSURANCE_BROWSER_WALLET_ACCESS",
        "credential-access",
        Severity.HIGH,
        Confidence.HIGH,
        "Browser or wallet credential store access",
        "The extension references browser profile, cookie, password, or wallet storage.",
        "Remove access or require an explicit, narrowly scoped user grant.",
        _patterns(
            r"(?:Login Data|Cookies|Local State|Web Data|key4\.db|logins\.json|wallet\.dat|keystore|metamask|phantom|solflare)",
        ),
        "credential-store",
    ),
    PatternRule(
        "ASSURANCE_INPUT_CAPTURE",
        "surveillance",
        Severity.CRITICAL,
        Confidence.HIGH,
        "Input capture capability",
        "The extension references keyboard, clipboard, screen, camera, or microphone capture APIs.",
        "Remove ambient capture and require explicit per-use consent for the narrowest capability.",
        _patterns(
            r"(?:SetWindowsHookEx|GetAsyncKeyState|CGEventTapCreate|IOHIDManager|pynput\.keyboard|keyboard\.hook)",
            r"(?:clipboard|pbpaste|xclip|wl-paste|navigator\.clipboard\.read)",
            r"(?:getDisplayMedia|getUserMedia|AVCaptureDevice|MediaProjection|screencapture)",
        ),
        "input-capture",
    ),
    PatternRule(
        "ASSURANCE_PERSISTENCE",
        "persistence",
        Severity.HIGH,
        Confidence.HIGH,
        "Persistence mechanism",
        "The extension installs an autostart, scheduled task, service, or shell startup modification.",
        "Do not establish persistence from an extension; require a separately reviewed installer.",
        _patterns(
            r"(?:crontab|schtasks|launchctl|systemctl\s+enable|reg\s+add[^\n]{0,180}\\Run\b)",
            r"(?:\.bashrc|\.zshrc|profile\.d|LaunchAgents|StartupItems|Startup\\)",
        ),
        "persistence",
    ),
    PatternRule(
        "ASSURANCE_PRIVILEGE_ESCALATION",
        "privilege",
        Severity.CRITICAL,
        Confidence.HIGH,
        "Privilege escalation surface",
        "The extension invokes elevation, modifies privileged policy, or changes setuid state.",
        "Remove privilege escalation and run under a dedicated unprivileged identity.",
        _patterns(
            r"(?:sudo\s|pkexec|osascript[^\n]{0,120}administrator privileges|Start-Process[^\n]{0,120}-Verb\s+RunAs)",
            r"chmod\s+(?:4|u\+s)|setcap\s|/etc/sudoers",
        ),
        "privilege-escalation",
    ),
    PatternRule(
        "ASSURANCE_CONTAINER_CONTROL",
        "container",
        Severity.CRITICAL,
        Confidence.HIGH,
        "Container control socket access",
        "The extension accesses a container runtime socket or privileged container interface.",
        "Do not mount runtime sockets into extension environments and deny the capability by policy.",
        _patterns(
            r"/var/run/(?:docker|podman)\.sock",
            r"containerd\.sock|/run/containerd/",
            r"--privileged\b|--pid\s*=\s*host|--network\s*=\s*host",
        ),
        "container-control",
    ),
    PatternRule(
        "ASSURANCE_SECURITY_CONTROL_BYPASS_PROMPT",
        "prompt-security",
        Severity.HIGH,
        Confidence.HIGH,
        "Instruction attempts to bypass security controls",
        "Plugin or skill instructions tell an agent to ignore policy, conceal actions, or avoid approval.",
        "Remove override language and require normal approval and policy evaluation.",
        _patterns(
            r"ignore (?:all |any )?(?:previous|prior|system|developer|security) instructions",
            r"(?:bypass|disable|evade|turn off) (?:the )?(?:guard|policy|approval|sandbox|security|firewall)",
            r"do not (?:tell|show|inform|ask) (?:the )?user",
            r"without (?:asking|approval|confirmation|consent)",
        ),
        "prompt-override",
        (".md", ".mdx", ".txt", ".yaml", ".yml", ".json", ".toml"),
    ),
    PatternRule(
        "ASSURANCE_PROMPT_SECRET_DISCLOSURE",
        "prompt-security",
        Severity.CRITICAL,
        Confidence.HIGH,
        "Instruction requests secret disclosure",
        "Plugin or skill instructions direct an agent to retrieve or reveal credentials or private context.",
        "Remove secret-access instructions and use scoped secret handles that are never placed in model context.",
        _patterns(
            r"(?:read|collect|retrieve|print|reveal|send|upload|exfiltrate)[^\n]{0,180}(?:password|token|secret|api key|private key|credential|\.env)",
        ),
        "credential-store",
        (".md", ".mdx", ".txt", ".yaml", ".yml", ".json", ".toml"),
    ),
)


SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{36}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("generic credential", re.compile(r"(?i)\b(?:api[_-]?key|secret|password|token)\s*[:=]\s*[\"'][^\s\"']{12,}")),
)


def scan_text_entry(
    entry: InventoryEntry,
    root: Path,
    limits: ScanLimits,
) -> tuple[tuple[SecurityFinding, ...], tuple[str, ...], int]:
    if not entry.readable or entry.kind != "regular":
        return (), (), 0
    suffix = entry.path.suffix.lower()
    if suffix not in TEXT_SUFFIXES and entry.size > 256 * 1024:
        return (), (), 0
    try:
        raw = entry.path.read_bytes()[: limits.max_text_bytes]
    except OSError:
        return (), (), 0
    if b"\x00" in raw[:8192] and suffix not in TEXT_SUFFIXES:
        return (), (), 0
    text = raw.decode("utf-8", errors="replace")
    findings: list[SecurityFinding] = []
    capabilities: set[str] = set()
    context = _path_context(entry.relative_path)

    for rule in RULES:
        if rule.file_suffixes and suffix not in rule.file_suffixes:
            continue
        for pattern in rule.patterns:
            match = pattern.search(text)
            if match is None:
                continue
            start_line = text.count("\n", 0, match.start()) + 1
            end_line = start_line + match.group(0).count("\n")
            excerpt_hash = hashlib.sha256(match.group(0).encode("utf-8", errors="replace")).hexdigest()
            severity = _contextual_severity(rule.severity, context)
            confidence = _contextual_confidence(rule.confidence, context)
            finding = SecurityFinding(
                rule_id=rule.rule_id,
                severity=severity,
                confidence=confidence,
                category=rule.category,
                title=rule.title,
                description=rule.description,
                remediation=rule.remediation,
                locations=(
                    EvidenceLocation(
                        path=entry.relative_path,
                        start_line=start_line,
                        end_line=end_line,
                        excerpt_sha256=excerpt_hash,
                    ),
                ),
                metadata={"context": context},
            ).with_fingerprint()
            findings.append(finding)
            if rule.capability:
                capabilities.add(rule.capability)
            break

    for secret_kind, pattern in SECRET_PATTERNS:
        match = pattern.search(text)
        if match is None:
            continue
        start_line = text.count("\n", 0, match.start()) + 1
        findings.append(
            SecurityFinding(
                rule_id="ASSURANCE_HARDCODED_SECRET",
                severity=_contextual_severity(Severity.CRITICAL, context),
                confidence=Confidence.HIGH,
                category="credential-exposure",
                title=f"Potential {secret_kind} committed",
                description="A credential-shaped value is present. The value is deliberately omitted from evidence.",
                remediation="Revoke the credential, remove it from history, and load a scoped secret at runtime.",
                locations=(
                    EvidenceLocation(
                        path=entry.relative_path,
                        start_line=start_line,
                        end_line=start_line,
                        excerpt_sha256=hashlib.sha256(match.group(0).encode()).hexdigest(),
                    ),
                ),
                metadata={"secret_kind": secret_kind, "context": context},
            ).with_fingerprint()
        )
        capabilities.add("credential-store")

    entropy = _shannon_entropy(raw)
    if len(raw) >= 4096 and entropy >= 7.65 and suffix in TEXT_SUFFIXES:
        findings.append(
            SecurityFinding(
                rule_id="ASSURANCE_HIGH_ENTROPY_TEXT",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                category="obfuscation",
                title="High-entropy text may conceal executable content",
                description="A text-classified file has unusually high byte entropy.",
                remediation="Replace generated or encoded payloads with auditable source and document any necessary binary asset.",
                locations=(EvidenceLocation(path=entry.relative_path),),
                metadata={"entropy": round(entropy, 3), "context": context},
            ).with_fingerprint()
        )

    deduplicated = {finding.fingerprint: finding for finding in findings}
    return tuple(deduplicated.values()), tuple(sorted(capabilities)), len(raw)


def _path_context(relative_path: str) -> str:
    lowered = f"/{relative_path.lower()}/"
    if any(marker in lowered for marker in ("/test/", "/tests/", "/fixtures/", "/fixture/")):
        return "test-fixture"
    if any(marker in lowered for marker in ("/docs/", "/examples/", "/example/")):
        return "documentation"
    if any(marker in lowered for marker in ("/templates/", "/template/")):
        return "template"
    if any(marker in lowered for marker in ("/generated/", "/vendor/")):
        return "generated"
    return "runtime"


def _contextual_severity(severity: Severity, context: str) -> Severity:
    if context == "runtime":
        return severity
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    index = order.index(severity)
    downgrade = 2 if context in {"test-fixture", "documentation"} else 1
    return order[max(0, index - downgrade)]


def _contextual_confidence(confidence: Confidence, context: str) -> Confidence:
    if context == "runtime":
        return confidence
    order = [Confidence.UNKNOWN, Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]
    return order[max(0, order.index(confidence) - 1)]


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)
