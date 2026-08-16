"""Dependency, lockfile, registry, and lifecycle-script analysis."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .limits import ScanLimits
from .models import Confidence, EvidenceLocation, SecurityFinding, Severity


MUTABLE_SOURCE_RE = re.compile(
    r"(?i)(?:git\+|git@|github:|https?://[^\s#]+\.git)(?![^\s]*#[0-9a-f]{40}(?:\b|$))"
)
INSECURE_REGISTRY_RE = re.compile(r"(?i)\bhttp://(?!localhost\b|127\.0\.0\.1\b|\[::1\])")
UNPINNED_REQUIREMENT_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:\[[^]]+\])?\s*(?:$|[><~=!]=?)")
EXACT_PYTHON_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:\[[^]]+\])?==[^\s;]+(?:\s*;.*)?$")
SEMVER_EXACT_RE = re.compile(r"^(?:v)?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
HEX_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")

POPULAR_PACKAGE_NAMES = frozenset(
    {
        "requests",
        "urllib3",
        "fastapi",
        "pydantic",
        "numpy",
        "pandas",
        "django",
        "flask",
        "pytest",
        "cryptography",
        "openai",
        "anthropic",
        "langchain",
        "react",
        "express",
        "lodash",
        "axios",
        "typescript",
        "webpack",
        "vite",
        "eslint",
        "prettier",
        "next",
        "vue",
        "svelte",
    }
)


@dataclass(frozen=True, slots=True)
class DependencyRecord:
    ecosystem: str
    name: str
    version: str | None
    source: str | None
    manifest: str
    direct: bool
    pinned: bool
    integrity: str | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "manifest": self.manifest,
            "direct": self.direct,
            "pinned": self.pinned,
            "integrity": self.integrity,
        }


@dataclass(frozen=True, slots=True)
class DependencyResult:
    records: tuple[DependencyRecord, ...]
    findings: tuple[SecurityFinding, ...]
    capabilities: tuple[str, ...]
    manifests: tuple[str, ...]
    complete: bool
    osv: dict[str, Any] | None = None


def scan_dependencies(root: Path, limits: ScanLimits, *, osv: bool = False) -> DependencyResult:
    records: list[DependencyRecord] = []
    findings: list[SecurityFinding] = []
    capabilities: set[str] = set()
    manifests: list[str] = []
    complete = True

    package_json = root / "package.json"
    if package_json.is_file():
        manifests.append("package.json")
        node_records, node_findings, node_capabilities, node_complete = _scan_package_json(package_json, root)
        records.extend(node_records)
        findings.extend(node_findings)
        capabilities.update(node_capabilities)
        complete = complete and node_complete
        lock = next(
            (root / name for name in ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb") if (root / name).is_file()),
            None,
        )
        if lock is None:
            findings.append(
                _finding(
                    "ASSURANCE_DEPENDENCY_LOCK_MISSING",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "supply-chain",
                    "Node dependency lockfile is missing",
                    "package.json is present without a reproducible dependency snapshot.",
                    "Commit one package-manager lockfile and enforce frozen installation.",
                    "package.json",
                )
            )
        else:
            manifests.append(lock.relative_to(root).as_posix())
            lock_findings, lock_complete = _scan_node_lock(lock, root)
            findings.extend(lock_findings)
            complete = complete and lock_complete

    pyproject = root / "pyproject.toml"
    requirements = root / "requirements.txt"
    if pyproject.is_file():
        manifests.append("pyproject.toml")
        py_records, py_findings, py_complete = _scan_pyproject(pyproject, root)
        records.extend(py_records)
        findings.extend(py_findings)
        complete = complete and py_complete
        lock = next((root / name for name in ("uv.lock", "poetry.lock", "Pipfile.lock") if (root / name).is_file()), None)
        if lock is None and not requirements.is_file():
            findings.append(
                _finding(
                    "ASSURANCE_DEPENDENCY_LOCK_MISSING",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "supply-chain",
                    "Python dependency lockfile is missing",
                    "pyproject.toml declares dependencies without a recognized lock or requirements snapshot.",
                    "Commit uv.lock, poetry.lock, Pipfile.lock, or fully hashed requirements.",
                    "pyproject.toml",
                )
            )
        elif lock is not None:
            manifests.append(lock.relative_to(root).as_posix())
    if requirements.is_file():
        manifests.append("requirements.txt")
        req_records, req_findings, req_complete = _scan_requirements(requirements, root)
        records.extend(req_records)
        findings.extend(req_findings)
        complete = complete and req_complete

    cargo_toml = root / "Cargo.toml"
    if cargo_toml.is_file():
        manifests.append("Cargo.toml")
        cargo_records, cargo_findings, cargo_complete = _scan_cargo(cargo_toml, root)
        records.extend(cargo_records)
        findings.extend(cargo_findings)
        complete = complete and cargo_complete
        cargo_lock = root / "Cargo.lock"
        if not cargo_lock.is_file():
            findings.append(
                _finding(
                    "ASSURANCE_DEPENDENCY_LOCK_MISSING",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "supply-chain",
                    "Cargo.lock is missing",
                    "The Rust package does not provide a reproducible dependency snapshot.",
                    "Commit Cargo.lock for distributed applications and scanner components.",
                    "Cargo.toml",
                )
            )
        else:
            manifests.append("Cargo.lock")

    go_mod = root / "go.mod"
    if go_mod.is_file():
        manifests.append("go.mod")
        go_records, go_findings = _scan_go_mod(go_mod, root)
        records.extend(go_records)
        findings.extend(go_findings)
        go_sum = root / "go.sum"
        if not go_sum.is_file():
            findings.append(
                _finding(
                    "ASSURANCE_DEPENDENCY_LOCK_MISSING",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "supply-chain",
                    "go.sum is missing",
                    "Go module checksums are not committed.",
                    "Commit go.sum and verify modules through the checksum database or an approved proxy.",
                    "go.mod",
                )
            )
        else:
            manifests.append("go.sum")

    for record in records:
        if record.source and INSECURE_REGISTRY_RE.search(record.source):
            findings.append(
                _finding(
                    "ASSURANCE_INSECURE_DEPENDENCY_SOURCE",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "supply-chain",
                    "Dependency uses an insecure source",
                    "A dependency source uses plaintext HTTP.",
                    "Use an authenticated HTTPS registry and pin the resolved artifact digest.",
                    record.manifest,
                    {"package": record.name},
                )
            )
        if record.source and MUTABLE_SOURCE_RE.search(record.source):
            findings.append(
                _finding(
                    "ASSURANCE_MUTABLE_VCS_DEPENDENCY",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "supply-chain",
                    "Dependency uses a mutable VCS reference",
                    "The VCS dependency is not pinned to a complete immutable commit identifier.",
                    "Pin a reviewed full commit digest and retain provenance for the fetched tree.",
                    record.manifest,
                    {"package": record.name},
                )
            )
        if not record.pinned and record.direct:
            findings.append(
                _finding(
                    "ASSURANCE_UNPINNED_DIRECT_DEPENDENCY",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    "supply-chain",
                    "Direct dependency is not exactly pinned",
                    "The manifest permits dependency drift between scans and installs.",
                    "Use a committed lockfile and an immutable install mode; pin high-risk tools exactly.",
                    record.manifest,
                    {"package": record.name},
                )
            )
        typo_target = _possible_typosquat(record.name)
        if typo_target:
            findings.append(
                _finding(
                    "ASSURANCE_DEPENDENCY_TYPOSQUAT",
                    Severity.HIGH,
                    Confidence.MEDIUM,
                    "supply-chain",
                    "Dependency name resembles a popular package",
                    "The dependency name is one edit away from a commonly used package.",
                    "Confirm publisher identity and intended package name before installation.",
                    record.manifest,
                    {"package": record.name, "resembles": typo_target},
                )
            )

    osv_payload: dict[str, Any] | None = None
    if osv and records:
        try:
            osv_payload = query_osv(records, limits)
        except (OSError, ValueError, urllib.error.URLError) as exc:
            complete = False
            findings.append(
                _finding(
                    "ASSURANCE_OSV_LOOKUP_FAILED",
                    Severity.LOW,
                    Confidence.HIGH,
                    "supply-chain",
                    "OSV vulnerability lookup failed",
                    "Optional online vulnerability evidence could not be retrieved.",
                    "Retry through an approved egress path or ingest a signed offline advisory snapshot.",
                    None,
                    {"error": type(exc).__name__},
                )
            )

    findings = list({finding.fingerprint: finding for finding in findings}.values())
    return DependencyResult(
        records=tuple(records),
        findings=tuple(findings),
        capabilities=tuple(sorted(capabilities)),
        manifests=tuple(dict.fromkeys(manifests)),
        complete=complete,
        osv=osv_payload,
    )


def _scan_package_json(
    path: Path, root: Path
) -> tuple[list[DependencyRecord], list[SecurityFinding], set[str], bool]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return [], [
            _finding(
                "ASSURANCE_PACKAGE_MANIFEST_INVALID",
                Severity.HIGH,
                Confidence.HIGH,
                "supply-chain",
                "package.json is invalid",
                "The Node package manifest cannot be parsed.",
                "Fix the manifest and regenerate the lockfile.",
                path.relative_to(root).as_posix(),
            )
        ], set(), False
    if not isinstance(payload, dict):
        return [], [], set(), False
    records: list[DependencyRecord] = []
    findings: list[SecurityFinding] = []
    capabilities: set[str] = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        values = payload.get(section)
        if not isinstance(values, dict):
            continue
        for name, spec in values.items():
            if not isinstance(name, str) or not isinstance(spec, str):
                continue
            pinned = bool(SEMVER_EXACT_RE.fullmatch(spec)) or bool(HEX_COMMIT_RE.fullmatch(spec.removeprefix("git+")))
            records.append(
                DependencyRecord(
                    ecosystem="npm",
                    name=name,
                    version=spec,
                    source=spec if "://" in spec or spec.startswith(("git+", "github:", "file:")) else None,
                    manifest="package.json",
                    direct=section == "dependencies",
                    pinned=pinned,
                )
            )
    scripts = payload.get("scripts")
    if isinstance(scripts, dict):
        lifecycle = {
            key: value
            for key, value in scripts.items()
            if isinstance(key, str)
            and isinstance(value, str)
            and key.lower() in {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishonly"}
        }
        for name, command in lifecycle.items():
            severity = Severity.CRITICAL if _download_execute(command) else Severity.HIGH
            findings.append(
                _finding(
                    "ASSURANCE_PACKAGE_LIFECYCLE_SCRIPT",
                    severity,
                    Confidence.HIGH,
                    "supply-chain",
                    f"Node lifecycle script: {name}",
                    "Package-manager lifecycle scripts execute automatically during installation.",
                    "Remove automatic lifecycle execution or require an isolated, reviewed build step.",
                    "package.json",
                    {"script": name, "command_sha256": hashlib.sha256(command.encode()).hexdigest()},
                )
            )
            capabilities.add("install-execution")
    publish_config = payload.get("publishConfig")
    if isinstance(publish_config, dict) and isinstance(publish_config.get("registry"), str):
        registry = str(publish_config["registry"])
        if INSECURE_REGISTRY_RE.search(registry):
            findings.append(
                _finding(
                    "ASSURANCE_INSECURE_REGISTRY",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "supply-chain",
                    "Node registry uses plaintext HTTP",
                    "publishConfig.registry is not protected by TLS.",
                    "Use a trusted HTTPS registry.",
                    "package.json",
                )
            )
    return records, findings, capabilities, True


def _scan_node_lock(path: Path, root: Path) -> tuple[list[SecurityFinding], bool]:
    relative = path.relative_to(root).as_posix()
    if path.suffix == ".json":
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return [
                _finding(
                    "ASSURANCE_LOCKFILE_INVALID",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "supply-chain",
                    "Node lockfile is invalid",
                    "The lockfile cannot be parsed.",
                    "Regenerate the lockfile using the declared package manager.",
                    relative,
                )
            ], False
        insecure = _find_json_strings(payload, INSECURE_REGISTRY_RE)
        missing_integrity = 0
        if isinstance(payload, dict) and isinstance(payload.get("packages"), dict):
            for key, value in payload["packages"].items():
                if not key or not isinstance(value, dict):
                    continue
                resolved = value.get("resolved")
                if isinstance(resolved, str) and (resolved.startswith("file:") or resolved.startswith("link:")):
                    continue
                if "integrity" not in value and isinstance(resolved, str):
                    missing_integrity += 1
        findings: list[SecurityFinding] = []
        if insecure:
            findings.append(
                _finding(
                    "ASSURANCE_INSECURE_LOCK_SOURCE",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "supply-chain",
                    "Lockfile contains an insecure source",
                    "A resolved package URL uses plaintext HTTP.",
                    "Regenerate the lockfile through an HTTPS registry.",
                    relative,
                )
            )
        if missing_integrity:
            findings.append(
                _finding(
                    "ASSURANCE_LOCK_INTEGRITY_MISSING",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    "supply-chain",
                    "Lockfile entries lack integrity digests",
                    "Resolved packages are not all bound to content integrity metadata.",
                    "Regenerate with a package manager that records integrity digests.",
                    relative,
                    {"count": missing_integrity},
                )
            )
        return findings, True
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], False
    findings = []
    if INSECURE_REGISTRY_RE.search(text):
        findings.append(
            _finding(
                "ASSURANCE_INSECURE_LOCK_SOURCE",
                Severity.HIGH,
                Confidence.HIGH,
                "supply-chain",
                "Lockfile contains an insecure source",
                "A package URL uses plaintext HTTP.",
                "Regenerate the lockfile through an HTTPS registry.",
                relative,
            )
        )
    return findings, True


def _scan_pyproject(path: Path, root: Path) -> tuple[list[DependencyRecord], list[SecurityFinding], bool]:
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return [], [
            _finding(
                "ASSURANCE_PACKAGE_MANIFEST_INVALID",
                Severity.HIGH,
                Confidence.HIGH,
                "supply-chain",
                "pyproject.toml is invalid",
                "The Python package manifest cannot be parsed.",
                "Fix the TOML document and regenerate the lockfile.",
                "pyproject.toml",
            )
        ], False
    records: list[DependencyRecord] = []
    project = payload.get("project")
    if isinstance(project, dict):
        for dependency in project.get("dependencies", []) if isinstance(project.get("dependencies"), list) else []:
            if isinstance(dependency, str):
                records.append(_python_record(dependency, "pyproject.toml", direct=True))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for values in optional.values():
                if isinstance(values, list):
                    for dependency in values:
                        if isinstance(dependency, str):
                            records.append(_python_record(dependency, "pyproject.toml", direct=False))
    return records, [], True


def _python_record(spec: str, manifest: str, *, direct: bool) -> DependencyRecord:
    name = re.split(r"[<>=!~;\s\[]", spec, maxsplit=1)[0]
    source = spec if "@" in spec and ("://" in spec or "git+" in spec) else None
    pinned = bool(EXACT_PYTHON_RE.fullmatch(spec.strip())) or (
        source is not None and bool(re.search(r"@[0-9a-fA-F]{40}(?:#|$)", source))
    )
    return DependencyRecord("pypi", name, spec, source, manifest, direct, pinned)


def _scan_requirements(path: Path, root: Path) -> tuple[list[DependencyRecord], list[SecurityFinding], bool]:
    records: list[DependencyRecord] = []
    findings: list[SecurityFinding] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return [], [], False
    for line_number, raw in enumerate(lines, start=1):
        value = raw.strip()
        if not value or value.startswith("#") or value.startswith(("-r", "--requirement")):
            continue
        if value.startswith(("--index-url", "--extra-index-url", "--trusted-host")):
            if "http://" in value or value.startswith("--trusted-host"):
                findings.append(
                    _finding(
                        "ASSURANCE_INSECURE_PYPI_CONFIGURATION",
                        Severity.HIGH,
                        Confidence.HIGH,
                        "supply-chain",
                        "Python installer trust is weakened",
                        "Requirements configuration uses plaintext transport or trusted-host bypass.",
                        "Use an authenticated HTTPS index without trusted-host bypass.",
                        "requirements.txt",
                        {"line": line_number},
                    )
                )
            continue
        records.append(_python_record(value, "requirements.txt", direct=True))
    return records, findings, True


def _scan_cargo(path: Path, root: Path) -> tuple[list[DependencyRecord], list[SecurityFinding], bool]:
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return [], [
            _finding(
                "ASSURANCE_PACKAGE_MANIFEST_INVALID",
                Severity.HIGH,
                Confidence.HIGH,
                "supply-chain",
                "Cargo.toml is invalid",
                "The Rust manifest cannot be parsed.",
                "Fix the manifest and regenerate Cargo.lock.",
                path.relative_to(root).as_posix(),
            )
        ], False
    records: list[DependencyRecord] = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        values = payload.get(section)
        if not isinstance(values, dict):
            continue
        for name, spec in values.items():
            if isinstance(spec, str):
                records.append(
                    DependencyRecord("cargo", name, spec, None, "Cargo.toml", section == "dependencies", SEMVER_EXACT_RE.fullmatch(spec) is not None)
                )
            elif isinstance(spec, dict):
                version = spec.get("version") if isinstance(spec.get("version"), str) else None
                git = spec.get("git") if isinstance(spec.get("git"), str) else None
                rev = spec.get("rev") if isinstance(spec.get("rev"), str) else None
                source = f"{git}#{rev}" if git and rev else git
                pinned = bool(version and SEMVER_EXACT_RE.fullmatch(version)) or bool(rev and HEX_COMMIT_RE.fullmatch(rev))
                records.append(
                    DependencyRecord("cargo", name, version or rev, source, "Cargo.toml", section == "dependencies", pinned)
                )
    return records, [], True


def _scan_go_mod(path: Path, root: Path) -> tuple[list[DependencyRecord], list[SecurityFinding]]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return [], []
    records: list[DependencyRecord] = []
    findings: list[SecurityFinding] = []
    in_require = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        candidate = line.removeprefix("require ")
        if not in_require and candidate == line and not line.startswith("require "):
            if line.startswith("replace ") and " => " in line and ("../" in line or "./" in line):
                findings.append(
                    _finding(
                        "ASSURANCE_LOCAL_DEPENDENCY_REPLACEMENT",
                        Severity.HIGH,
                        Confidence.HIGH,
                        "supply-chain",
                        "Go module uses a local replacement",
                        "A replace directive redirects a dependency to local mutable content.",
                        "Remove local replacements from distributed extension manifests.",
                        "go.mod",
                    )
                )
            continue
        fields = candidate.split()
        if len(fields) >= 2:
            name, version = fields[0], fields[1]
            pinned = bool(re.fullmatch(r"v\d+\.\d+\.\d+(?:-[^\s]+)?", version))
            records.append(DependencyRecord("go", name, version, None, "go.mod", True, pinned))
    return records, findings


def query_osv(records: list[DependencyRecord], limits: ScanLimits) -> dict[str, Any]:
    queries = []
    indexes: list[DependencyRecord] = []
    ecosystem_map = {"npm": "npm", "pypi": "PyPI", "cargo": "crates.io", "go": "Go"}
    for record in records[:1000]:
        ecosystem = ecosystem_map.get(record.ecosystem)
        version = _normalized_exact_version(record)
        if ecosystem and version:
            queries.append({"package": {"ecosystem": ecosystem, "name": record.name}, "version": version})
            indexes.append(record)
    if not queries:
        return {"queried": 0, "vulnerabilities": []}
    body = json.dumps({"queries": queries}, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "hol-guard-assurance/1"},
    )
    opener = urllib.request.build_opener(_NoRedirect())
    with opener.open(request, timeout=limits.osv_timeout_seconds) as response:
        if response.status != 200:
            raise ValueError(f"OSV returned HTTP {response.status}")
        raw = response.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("OSV response exceeded limit")
    payload = json.loads(raw)
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list) or len(results) != len(indexes):
        raise ValueError("OSV response shape mismatch")
    vulnerabilities = []
    for record, result in zip(indexes, results, strict=True):
        vulns = result.get("vulns", []) if isinstance(result, dict) else []
        for vulnerability in vulns if isinstance(vulns, list) else []:
            if isinstance(vulnerability, dict) and isinstance(vulnerability.get("id"), str):
                vulnerabilities.append(
                    {
                        "id": vulnerability["id"],
                        "package": record.name,
                        "ecosystem": record.ecosystem,
                        "version": _normalized_exact_version(record),
                    }
                )
    return {"queried": len(indexes), "vulnerabilities": vulnerabilities}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: object, fp: object, code: int, msg: str, headers: object, newurl: str) -> None:
        raise urllib.error.HTTPError(newurl, code, "redirect rejected", headers, fp)


def _normalized_exact_version(record: DependencyRecord) -> str | None:
    if not record.version:
        return None
    value = record.version.strip()
    if record.ecosystem == "pypi":
        match = re.search(r"==([^\s;]+)", value)
        return match.group(1) if match else None
    if record.ecosystem in {"npm", "cargo", "go"}:
        return value.removeprefix("v") if record.pinned else None
    return None


def _download_execute(command: str) -> bool:
    lowered = command.lower()
    downloader = any(value in lowered for value in ("curl ", "wget ", "invoke-webrequest", "fetch("))
    executor = any(value in lowered for value in ("| sh", "| bash", "iex", "eval", "node ", "python "))
    return downloader and executor


def _find_json_strings(value: object, pattern: re.Pattern[str]) -> bool:
    if isinstance(value, str):
        return pattern.search(value) is not None
    if isinstance(value, dict):
        return any(_find_json_strings(item, pattern) for item in value.values())
    if isinstance(value, list):
        return any(_find_json_strings(item, pattern) for item in value)
    return False


def _possible_typosquat(name: str) -> str | None:
    normalized = name.lower().split("/")[-1].replace("-", "").replace("_", "")
    for popular in POPULAR_PACKAGE_NAMES:
        target = popular.replace("-", "").replace("_", "")
        if normalized == target:
            return None
        if abs(len(normalized) - len(target)) <= 1 and _levenshtein_at_most_one(normalized, target):
            return popular
    return None


def _levenshtein_at_most_one(left: str, right: str) -> bool:
    if left == right or abs(len(left) - len(right)) > 1:
        return left == right
    if len(left) == len(right):
        return sum(a != b for a, b in zip(left, right, strict=True)) == 1
    shorter, longer = (left, right) if len(left) < len(right) else (right, left)
    index_short = index_long = differences = 0
    while index_short < len(shorter) and index_long < len(longer):
        if shorter[index_short] == longer[index_long]:
            index_short += 1
            index_long += 1
        else:
            differences += 1
            index_long += 1
            if differences > 1:
                return False
    return True


def _finding(
    rule_id: str,
    severity: Severity,
    confidence: Confidence,
    category: str,
    title: str,
    description: str,
    remediation: str,
    path: str | None,
    metadata: dict[str, Any] | None = None,
) -> SecurityFinding:
    locations = (EvidenceLocation(path=path),) if path else ()
    return SecurityFinding(
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        category=category,
        title=title,
        description=description,
        remediation=remediation,
        locations=locations,
        metadata=metadata or {},
    ).with_fingerprint()
