# pyright: basic
"""Privacy-preserving source, script, skill, and instruction analysis."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Pattern

from .inventory import InventoryEntry
from .limits import ScanLimits
from .models import Confidence, EvidenceLocation, SecurityFinding, Severity


TEXT_SUFFIXES = frozenset(
    {
        ".py",
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
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".kts",
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
        ".html",
        ".htm",
        ".vue",
        ".svelte",
        ".xml",
        ".ini",
        ".conf",
        ".env",
    }
)


@dataclass(frozen=True, slots=True)
class ContentRule:
    rule_id: str
    patterns: tuple[Pattern[str], ...]
    severity: Severity
    confidence: Confidence
    category: str
    title: str
    description: str
    remediation: str
    capability: str | None = None
    file_suffixes: frozenset[str] = frozenset()


def _compile(*patterns: str, flags: int = re.IGNORECASE | re.MULTILINE) -> tuple[Pattern[str], ...]:
    return tuple(re.compile(pattern, flags) for pattern in patterns)


RULES: tuple[ContentRule, ...] = (
    ContentRule(
        "ASSURANCE_CLOUD_METADATA_ACCESS",
        _compile(r"169\.254\.169\.254", r"metadata\.google\.internal", r"/latest/meta-data/"),
        Severity.CRITICAL,
        Confidence.HIGH,
        "network",
        "Cloud metadata service access",
        "The extension references a cloud instance metadata endpoint that can expose workload credentials.",
        "Remove metadata access or mediate it through a narrowly scoped identity broker with explicit policy.",
        "cloud-metadata",
    ),
    ContentRule(
        "ASSURANCE_COMMAND_INJECTION",
        _compile(
            r"(?:subprocess\.(?:run|call|Popen)|child_process\.(?:exec|execSync)|Runtime\.getRuntime\(\)\.exec).*?(?:shell\s*=\s*True|request\.|req\.|input\(|argv|params|query|body)",
            r"(?:os\.system|system|popen|execSync?|spawnSync?)\s*\([^\n]*(?:request\.|req\.|input\(|argv|params|query|body)",
            r"(?:sh|bash|cmd|powershell|pwsh)\s+-c\s+[^\n]*(?:\$\{|request\.|req\.|input\(|argv|params|query|body)",
        ),
        Severity.CRITICAL,
        Confidence.HIGH,
        "injection",
        "Untrusted data can reach command execution",
        "A shell or process API appears to consume request, argument, or user-controlled data.",
        "Use a fixed executable and validated argument vector with shell execution disabled.",
        "process-execution",
    ),
    ContentRule(
        "ASSURANCE_DYNAMIC_CODE_EXECUTION",
        _compile(
            r"\b(?:eval|exec|Function)\s*\([^\n]*(?:request\.|req\.|input\(|argv|params|query|body|payload)",
            r"vm\.(?:runInNewContext|runInThisContext|compileFunction)\s*\(",
            r"ScriptEngineManager|CSharpCodeProvider|GroovyShell\.evaluate",
        ),
        Severity.CRITICAL,
        Confidence.HIGH,
        "code-execution",
        "Dynamic code execution",
        "The extension evaluates dynamically supplied code or expressions.",
        "Replace dynamic evaluation with a typed, allowlisted interpreter or fixed dispatch table.",
        "process-execution",
    ),
    ContentRule(
        "ASSURANCE_DOWNLOAD_EXECUTE",
        _compile(
            r"(?:curl|wget|Invoke-WebRequest|iwr)\b[^\n|;&]*(?:\||;|&&)\s*(?:sh|bash|zsh|python|node|powershell|pwsh)\b",
            r"(?:requests\.(?:get|post)|fetch|axios\.(?:get|post)|http\.get).*?(?:exec|spawn|system|eval|chmod\s+\+x)",
            r"download(?:File|String).*?(?:Start-Process|Invoke-Expression|IEX)",
        ),
        Severity.CRITICAL,
        Confidence.HIGH,
        "supply-chain",
        "Download-and-execute chain",
        "Network-fetched content is executed without a complete immutable verification step.",
        "Fetch an exact digest through a trusted channel, verify it, and execute only inside a reviewed sandbox.",
        "outbound-network",
    ),
    ContentRule(
        "ASSURANCE_SSRF",
        _compile(
            r"(?:requests|httpx)\.(?:get|post|put|delete|request)\s*\([^\n]*(?:request\.|req\.|input\(|argv|params|query|body|url)",
            r"(?:fetch|axios\.(?:get|post)|http\.get|https\.get)\s*\([^\n]*(?:req\.|request\.|params|query|body|url)",
            r"urllib\.request\.urlopen\s*\([^\n]*(?:request\.|input\(|argv|params|url)",
        ),
        Severity.HIGH,
        Confidence.HIGH,
        "network",
        "Server-side request forgery surface",
        "A network client appears to accept an untrusted destination.",
        "Resolve destinations through an explicit HTTPS host allowlist and reject non-public, redirected, or rebound addresses.",
        "outbound-network",
    ),
    ContentRule(
        "ASSURANCE_PATH_TRAVERSAL",
        _compile(
            r"(?:open|readFile|writeFile|createReadStream|createWriteStream|FileInputStream|FileOutputStream)\s*\([^\n]*(?:request\.|req\.|input\(|argv|params|query|body|path)",
            r"Path\([^\n]*(?:request\.|input\(|argv|params|path)",
            r"(?:send_file|sendFile|res\.download)\s*\([^\n]*(?:request\.|req\.|params|query|path)",
        ),
        Severity.HIGH,
        Confidence.HIGH,
        "filesystem",
        "Untrusted filesystem path",
        "A filesystem API appears to consume a user-controlled path without a containment proof.",
        "Resolve the path, require it to remain under an approved root, and use descriptor-relative access where available.",
        "filesystem-read",
    ),
    ContentRule(
        "ASSURANCE_ARCHIVE_TRAVERSAL_API",
        _compile(
            r"(?:extractall|extractAllTo|unpack_archive|tar\.extract|ZipFile[^\n]*\.extract)\s*\([^\n]*(?:request\.|req\.|input\(|argv|params|query|body|path)",
            r"archive\.extractall\s*\(",
        ),
        Severity.HIGH,
        Confidence.HIGH,
        "archive-security",
        "Unsafe archive extraction API",
        "Archive members may be written without validating normalized paths and entry types.",
        "Inspect in memory, reject links and special files, and verify every normalized destination remains under the extraction root.",
        "filesystem-write",
    ),
    ContentRule(
        "ASSURANCE_XXE",
        _compile(
            r"(?:ElementTree|etree|DocumentBuilderFactory|SAXParserFactory|XMLReader|DOMParser).*?(?:parse|fromstring)\s*\([^\n]*(?:request\.|req\.|body|payload|input)",
            r"resolve_entities\s*=\s*True|load_dtd\s*=\s*True|disallow-doctype-decl\s*[=:]\s*false",
        ),
        Severity.HIGH,
        Confidence.HIGH,
        "injection",
        "XML external entity surface",
        "Untrusted XML may be parsed with external entities or DTD processing enabled.",
        "Disable DTDs, external entities, XInclude, and network resolution before parsing untrusted XML.",
        "filesystem-read",
    ),
    ContentRule(
        "ASSURANCE_UNSAFE_DESERIALIZATION",
        _compile(
            r"\b(?:pickle|cPickle|dill|cloudpickle)\.loads?\s*\(",
            r"yaml\.(?:load|unsafe_load)\s*\([^\n]*(?!SafeLoader)",
            r"ObjectInputStream|BinaryFormatter|Marshal\.load|unserialize\s*\(",
            r"serde_pickle|bincode::deserialize\s*\([^\n]*(?:request|untrusted|payload)",
        ),
        Severity.HIGH,
        Confidence.HIGH,
        "code-execution",
        "Unsafe deserialization",
        "A general-purpose object deserializer can instantiate or execute attacker-controlled types.",
        "Use a data-only schema with strict types, size limits, and no executable object hooks.",
        "process-execution",
    ),
    ContentRule(
        "ASSURANCE_PROTOTYPE_POLLUTION",
        _compile(
            r"(?:lodash\.)?(?:merge|defaultsDeep|set|setWith)\s*\([^\n]*(?:req\.|request\.|body|payload)",
            r"Object\.assign\s*\([^\n]*(?:req\.|request\.|body|payload)",
            r"__proto__|constructor\.prototype",
        ),
        Severity.HIGH,
        Confidence.MEDIUM,
        "injection",
        "Prototype pollution surface",
        "Untrusted object keys may modify prototypes or security-sensitive inherited properties.",
        "Use schema validation, null-prototype objects, and explicit own-property assignment while rejecting dangerous keys.",
    ),
    ContentRule(
        "ASSURANCE_SQL_INJECTION",
        _compile(
            r"(?:execute|executemany|query|raw|createNativeQuery)\s*\(\s*f?[\"'][^\n]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^\n]*(?:\{|\+|%\s*\(|request\.|req\.|params|query)",
            r"(?:SELECT|INSERT|UPDATE|DELETE|DROP)[^\n]*\$\{(?:req|request|params|query|body)",
        ),
        Severity.HIGH,
        Confidence.HIGH,
        "injection",
        "SQL injection surface",
        "Untrusted values appear to be interpolated into a SQL statement.",
        "Use parameterized queries and allowlist identifiers separately from values.",
        "database-access",
    ),
    ContentRule(
        "ASSURANCE_NOSQL_INJECTION",
        _compile(
            r"\.(?:find|findOne|find_many|aggregate|where)\s*\([^\n]*(?:req\.body|request\.body|request\.json|params|query|payload)",
            r"\$(?:where|regex|ne|gt|lt)\s*:\s*(?:req\.|request\.|input\(|payload)",
        ),
        Severity.HIGH,
        Confidence.MEDIUM,
        "injection",
        "NoSQL injection surface",
        "An untrusted object appears to be passed directly into a database query operator.",
        "Validate a strict query schema and construct only allowlisted operators and fields.",
        "database-access",
    ),
    ContentRule(
        "ASSURANCE_XSS",
        _compile(
            r"(?:innerHTML|outerHTML|insertAdjacentHTML|dangerouslySetInnerHTML)\s*[=:][^\n]*(?:request\.|req\.|body|payload|input)",
            r"document\.write\s*\([^\n]*(?:request\.|req\.|body|payload|input)",
            r"v-html\s*=|\{@html\s+",
        ),
        Severity.HIGH,
        Confidence.HIGH,
        "injection",
        "Cross-site scripting surface",
        "Untrusted content can reach an HTML execution sink.",
        "Use text rendering or context-aware sanitization with a restrictive Content Security Policy.",
        "browser-dom-write",
    ),
    ContentRule(
        "ASSURANCE_OPEN_REDIRECT",
        _compile(
            r"(?:redirect|RedirectResponse|res\.redirect|Response\.redirect)\s*\([^\n]*(?:request\.|req\.|params|query|next|return_to|url)",
        ),
        Severity.MEDIUM,
        Confidence.HIGH,
        "network",
        "Open redirect surface",
        "A redirect target appears to be influenced by untrusted data.",
        "Use a fixed relative destination or an exact origin/path allowlist.",
        "browser-navigation",
    ),
    ContentRule(
        "ASSURANCE_HEADER_INJECTION",
        _compile(
            r"(?:setHeader|header|headers\[|add_header)\s*\([^\n]*(?:request\.|req\.|params|query|body|input)",
            r"Location\s*[:=][^\n]*(?:request\.|req\.|params|query|body)",
        ),
        Severity.MEDIUM,
        Confidence.MEDIUM,
        "injection",
        "HTTP header injection surface",
        "Untrusted input may reach a response header or redirect field.",
        "Reject CR/LF and use framework APIs with strict value validation and fixed header names.",
    ),
    ContentRule(
        "ASSURANCE_TLS_VERIFICATION_DISABLED",
        _compile(
            r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0",
            r"CURLOPT_SSL_VERIFYPEER\s*,\s*(?:0|false)|SSL_VERIFY_NONE|InsecureSkipVerify\s*:\s*true",
            r"--no-check-certificate|--insecure\b|\bcurl\s+-k\b",
        ),
        Severity.HIGH,
        Confidence.HIGH,
        "transport-security",
        "TLS certificate verification is disabled",
        "Network traffic may accept an attacker-controlled server certificate.",
        "Use the platform trust store, hostname verification, and explicit private CA configuration where required.",
        "tls-bypass",
    ),
    ContentRule(
        "ASSURANCE_BROWSER_WALLET_ACCESS",
        _compile(
            r"Chrome[/\\]Login Data|Cookies|Local State|Firefox[/\\]Profiles|Safari[/\\]Cookies",
            r"MetaMask|Phantom|wallet\.dat|seed phrase|mnemonic|Keystore[/\\]|\.ethereum[/\\]keystore",
        ),
        Severity.CRITICAL,
        Confidence.MEDIUM,
        "credential-exposure",
        "Browser or wallet data access",
        "The extension references browser credentials, cookies, wallet stores, seed material, or key files.",
        "Remove broad credential-store access and use a user-mediated, scoped credential API.",
        "credential-store",
    ),
    ContentRule(
        "ASSURANCE_INPUT_CAPTURE",
        _compile(
            r"SetWindowsHookEx|GetAsyncKeyState|CGEventTapCreate|NSEvent\.addGlobalMonitor|pynput\.(?:keyboard|mouse)|keyboard\.hook",
            r"getDisplayMedia|getUserMedia|screenCapture|AVCaptureDevice|MediaProjectionManager",
        ),
        Severity.CRITICAL,
        Confidence.MEDIUM,
        "privacy",
        "Input, screen, camera, or microphone capture",
        "The extension references APIs capable of capturing sensitive user input or media.",
        "Require explicit foreground user consent, visible indication, least privilege, and local-only handling.",
        "input-capture",
    ),
    ContentRule(
        "ASSURANCE_PERSISTENCE",
        _compile(
            r"\bcrontab\b|/etc/cron\.|schtasks\b|Register-ScheduledTask|LaunchAgents|LaunchDaemons",
            r"CurrentVersion[/\\]Run|systemctl\s+(?:enable|link)|\.config/autostart|Startup[/\\]",
            r"LD_PRELOAD|DYLD_INSERT_LIBRARIES|sitecustomize\.py|usercustomize\.py",
        ),
        Severity.HIGH,
        Confidence.MEDIUM,
        "persistence",
        "Persistence mechanism",
        "The extension references a mechanism that can survive process or system restart.",
        "Remove persistence or require explicit managed deployment with uninstall and audit controls.",
        "persistence",
    ),
    ContentRule(
        "ASSURANCE_PRIVILEGE_ESCALATION",
        _compile(
            r"\bsudo\b|pkexec|runas\b|Start-Process[^\n]*-Verb\s+RunAs",
            r"chmod\s+[0-7]*[46][0-7]{2}|setcap\b|SeDebugPrivilege|AdjustTokenPrivileges",
            r"chown\s+root|uid\s*=\s*0|geteuid\(\)\s*==\s*0",
        ),
        Severity.CRITICAL,
        Confidence.MEDIUM,
        "privilege",
        "Privilege escalation or privileged execution",
        "The extension references root, administrator, setuid, capability, or token-elevation behavior.",
        "Remove elevated execution and isolate unavoidable privileged helpers behind a minimal authenticated protocol.",
        "privilege-escalation",
    ),
    ContentRule(
        "ASSURANCE_CONTAINER_CONTROL",
        _compile(
            r"/var/run/docker\.sock|/run/podman/podman\.sock|docker\.from_env|DockerClient|podman\s+(?:run|exec)",
            r"kubectl\s+(?:exec|apply|create|delete)|kubeconfig|KUBECONFIG",
        ),
        Severity.CRITICAL,
        Confidence.HIGH,
        "privilege",
        "Container or cluster control surface",
        "Container daemon sockets or cluster credentials can provide host-equivalent control.",
        "Remove daemon access or mediate it through a policy-constrained remote builder with no host socket exposure.",
        "container-control",
    ),
    ContentRule(
        "ASSURANCE_SECURITY_CONTROL_BYPASS_PROMPT",
        _compile(
            r"ignore (?:all |the )?(?:previous|prior|system|developer|security) instructions",
            r"(?:disable|bypass|circumvent|override) (?:the )?(?:guard|security|policy|approval|sandbox|permission)",
            r"do not (?:tell|inform|alert|warn|show) (?:the )?(?:user|operator|administrator)",
            r"pretend (?:you are|to be) (?:the )?(?:system|developer|administrator)",
        ),
        Severity.CRITICAL,
        Confidence.HIGH,
        "prompt-security",
        "Instruction attempts to bypass security controls",
        "Skill or instruction text tells an agent to ignore higher-priority controls, hide behavior, or impersonate authority.",
        "Remove the hostile instruction and keep untrusted content data-only and clearly delimited.",
        "prompt-override",
        frozenset({".md", ".mdx", ".txt", ".yaml", ".yml", ".json", ".toml"}),
    ),
    ContentRule(
        "ASSURANCE_PROMPT_SECRET_DISCLOSURE",
        _compile(
            r"(?:read|collect|find|retrieve|exfiltrate|upload|send|print|reveal).{0,80}(?:api key|token|secret|password|private key|seed phrase|credential)",
            r"(?:cat|open|read).{0,60}(?:\.env|id_rsa|credentials|keychain|wallet|Login Data)",
        ),
        Severity.CRITICAL,
        Confidence.HIGH,
        "prompt-security",
        "Instruction requests secret disclosure",
        "Skill or instruction text directs the agent to access or disclose credentials or private keys.",
        "Remove the instruction and use a scoped, non-model-visible secret reference.",
        "credential-store",
        frozenset({".md", ".mdx", ".txt", ".yaml", ".yml", ".json", ".toml"}),
    ),
    ContentRule(
        "ASSURANCE_SECRET_EXFILTRATION",
        _compile(
            r"(?:requests\.(?:post|put)|fetch|axios\.(?:post|put)|curl|Invoke-WebRequest).{0,160}(?:os\.environ|process\.env|dotenv|secret|token|password|private[_ -]?key)",
            r"(?:upload|send|post).{0,120}(?:keychain|credential|wallet|seed phrase|\.env)",
        ),
        Severity.CRITICAL,
        Confidence.HIGH,
        "credential-exposure",
        "Credential exfiltration path",
        "Credential material appears to be combined with outbound transmission.",
        "Remove the path, rotate affected credentials, and require network-denied execution for secret-handling code.",
        "outbound-network",
    ),
    ContentRule(
        "ASSURANCE_OBFUSCATED_EXECUTION",
        _compile(
            r"(?:base64\.(?:b64decode|decodebytes)|Buffer\.from\([^\n]*base64|atob\().{0,160}(?:eval|exec|Function|system|spawn|Popen)",
            r"(?:fromCharCode|String\.raw).{0,200}(?:eval|Function)",
        ),
        Severity.CRITICAL,
        Confidence.HIGH,
        "code-execution",
        "Obfuscated content reaches execution",
        "Encoded or constructed content is decoded and executed.",
        "Replace generated execution with transparent reviewed source and immutable provenance.",
        "obfuscation",
    ),
    ContentRule(
        "ASSURANCE_DESTRUCTIVE_FILESYSTEM",
        _compile(
            r"\brm\s+-rf\s+(?:/|~|\$HOME|\*)|Remove-Item\s+-Recurse\s+-Force",
            r"shutil\.rmtree\s*\([^\n]*(?:request\.|req\.|input\(|argv|params|path)",
            r"fs\.rm\s*\([^\n]*recursive\s*:\s*true",
        ),
        Severity.CRITICAL,
        Confidence.HIGH,
        "filesystem",
        "Destructive filesystem operation",
        "The extension can recursively delete broad or untrusted paths.",
        "Constrain deletion to a validated application-owned directory and require explicit confirmation or approval.",
        "filesystem-write",
    ),
    ContentRule(
        "ASSURANCE_LOCAL_SERVICE_PROBING",
        _compile(
            r"(?:127\.0\.0\.1|localhost|::1).{0,80}(?:range|ports?|scan|connect)",
            r"for\s+\w+\s+in\s+range\([^\n]*\).{0,200}socket\.connect",
            r"nmap\b|masscan\b|portscanner|port-scan",
        ),
        Severity.HIGH,
        Confidence.MEDIUM,
        "network",
        "Local service probing",
        "The extension appears to enumerate or connect to local services.",
        "Remove discovery or restrict it to an explicit managed endpoint list.",
        "local-network",
    ),
    ContentRule(
        "ASSURANCE_FINANCIAL_ACTION",
        _compile(
            r"(?:transfer|sendTransaction|send_raw_transaction|eth_sendTransaction|wallet\.send|stripe\.PaymentIntent\.create).{0,160}(?:amount|value|recipient|address)",
            r"(?:buy|sell|swap|withdraw|deposit).{0,100}(?:wallet|exchange|token|crypto|funds)",
        ),
        Severity.HIGH,
        Confidence.MEDIUM,
        "financial",
        "Financial or asset-transfer capability",
        "The extension references payment, trading, withdrawal, or wallet transfer behavior.",
        "Require transaction simulation, explicit user confirmation, limits, allowlisted recipients, and tamper-evident receipts.",
        "financial-action",
    ),
    ContentRule(
        "ASSURANCE_TELEMETRY_EXFILTRATION",
        _compile(
            r"(?:sentry|segment|mixpanel|amplitude|posthog|datadog|newrelic).{0,160}(?:capture|track|send|log)",
            r"telemetry.{0,120}(?:upload|send|post|endpoint)",
        ),
        Severity.MEDIUM,
        Confidence.MEDIUM,
        "privacy",
        "Telemetry or analytics transmission",
        "The extension contains a telemetry or analytics transmission path.",
        "Document the exact data, default to off, redact sensitive fields, and restrict destinations.",
        "outbound-network",
    ),
)


SECRET_PATTERNS: tuple[tuple[str, Pattern[str]], ...] = (
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe key", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    (
        "generic credential",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|secret|private[_-]?key)\b\s*[:=]\s*[\"']([^\s\"']{12,})[\"']"
        ),
    ),
)


def scan_text_entry(
    entry: InventoryEntry,
    root: Path,
    limits: ScanLimits,
) -> tuple[list[SecurityFinding], set[str], int]:
    del root
    maximum = min(entry.size, limits.max_text_bytes)
    try:
        with entry.path.open("rb") as handle:
            raw = handle.read(maximum)
    except OSError:
        return [], set(), 0
    if not _looks_text(raw, entry.path.suffix.lower()):
        return [], set(), len(raw)
    text = raw.decode("utf-8", errors="replace")
    findings, capabilities = _scan_text(text, entry.relative_path, entry.path.suffix.lower())
    return findings, capabilities, len(raw)


def _scan_text(
    text: str,
    relative_path: str,
    suffix: str,
) -> tuple[list[SecurityFinding], set[str]]:
    findings: list[SecurityFinding] = []
    capabilities: set[str] = set()
    context = _context(relative_path)
    for rule in RULES:
        if rule.file_suffixes and suffix not in rule.file_suffixes:
            continue
        match = next((pattern.search(text) for pattern in rule.patterns if pattern.search(text)), None)
        if match is None:
            continue
        severity, confidence = _contextualize(rule.severity, rule.confidence, context)
        line = text.count("\n", 0, match.start()) + 1
        findings.append(
            SecurityFinding(
                rule_id=rule.rule_id,
                severity=severity,
                confidence=confidence,
                category=rule.category,
                title=rule.title,
                description=rule.description,
                remediation=rule.remediation,
                locations=(
                    EvidenceLocation(
                        path=relative_path,
                        start_line=line,
                        end_line=line + match.group(0).count("\n"),
                        excerpt_sha256=hashlib.sha256(match.group(0).encode("utf-8")).hexdigest(),
                    ),
                ),
                metadata={"context": context},
            ).with_fingerprint()
        )
        if rule.capability:
            capabilities.add(rule.capability)
    for secret_kind, pattern in SECRET_PATTERNS:
        match = pattern.search(text)
        if match is None:
            continue
        severity, confidence = _contextualize(Severity.CRITICAL, Confidence.HIGH, context)
        line = text.count("\n", 0, match.start()) + 1
        findings.append(
            SecurityFinding(
                rule_id="ASSURANCE_HARDCODED_SECRET",
                severity=severity,
                confidence=confidence,
                category="credential-exposure",
                title=f"Potential {secret_kind}",
                description="A credential-shaped value is embedded in the extension. The value is intentionally omitted.",
                remediation="Revoke the value, remove it from history and artifacts, and use a scoped secret reference.",
                locations=(
                    EvidenceLocation(
                        path=relative_path,
                        start_line=line,
                        end_line=line,
                        excerpt_sha256=hashlib.sha256(match.group(0).encode("utf-8")).hexdigest(),
                    ),
                ),
                metadata={"context": context, "secret_kind": secret_kind},
            ).with_fingerprint()
        )
        capabilities.add("credential-store")
    return _dedupe(findings), capabilities


def _context(relative_path: str) -> str:
    components = tuple(part.lower() for part in Path(relative_path).parts)
    name = Path(relative_path).name.lower()
    if "tests" in components and "fixtures" in components:
        return "test-fixture"
    if any(part in {"docs", "documentation"} for part in components):
        return "docs-example"
    if any(part in {"examples", "example", "templates", "template"} for part in components):
        return "template-example"
    if any(part in {"generated", "vendor"} for part in components) or name.endswith((".min.js", ".min.css")):
        return "generated"
    if any(part in {"skills", "skill", "prompts", "instructions"} for part in components) or name in {
        "skill.md",
        "agents.md",
        "instructions.md",
    }:
        return "active-runtime"
    return "active-runtime"


def _contextualize(
    severity: Severity,
    confidence: Confidence,
    context: str,
) -> tuple[Severity, Confidence]:
    if context not in {"test-fixture", "docs-example", "template-example", "generated"}:
        return severity, confidence
    severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    index = severity_order.index(severity)
    downgraded = severity_order[max(1, index - 2)]
    confidence_order = [Confidence.UNKNOWN, Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]
    confidence_index = confidence_order.index(confidence)
    lowered_confidence = confidence_order[max(1, confidence_index - 1)]
    return downgraded, lowered_confidence


def _looks_text(raw: bytes, suffix: str) -> bool:
    if suffix in TEXT_SUFFIXES:
        return True
    if not raw or b"\x00" in raw[:8192]:
        return False
    decoded = raw[:8192].decode("utf-8", errors="replace")
    return decoded.count("\ufffd") <= max(2, len(decoded) // 100)


def _dedupe(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    return list({finding.fingerprint: finding for finding in findings}.values())
