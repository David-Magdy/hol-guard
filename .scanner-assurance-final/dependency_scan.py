# pyright: basic
"""Dependency and package-manager supply-chain intelligence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

from .limits import ScanLimits
from .models import Confidence, EvidenceLocation, SecurityFinding, Severity


SEMVER_EXACT_RE = re.compile(r"^(?:v)?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
PEP440_EXACT_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[^=\s;]+(?:\s*;.*)?$")
FULL_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40,64}$")
MUTABLE_SOURCE_RE = re.compile(
    r"(?i)(?:^|[+#@/])(?:main|master|head|latest|dev|develop|next|nightly)$|"
    r"(?:git\+|https?://|ssh://|git@).*(?:#(?:main|master|head|latest|dev|develop|next|nightly))?$"
)
INSECURE_SOURCE_RE = re.compile(r"(?i)^http://|--trusted-host|trusted-host|strict-ssl\s*=\s*false")
LIFECYCLE_SCRIPTS = frozenset({"preinstall", "install", "postinstall", "prepare", "prepublish", "prepack"})
COMMON_PACKAGES = frozenset(
    {
        "requests",
        "urllib3",
        "numpy",
        "pandas",
        "flask",
        "django",
        "fastapi",
        "pydantic",
        "pytest",
        "cryptography",
        "boto3",
        "axios",
        "express",
        "react",
        "typescript",
        "lodash",
        "chalk",
        "commander",
        "semver",
        "webpack",
        "esbuild",
        "vite",
        "serde",
        "tokio",
        "reqwest",
        "clap",
        "anyhow",
        "tracing",
    }
)


@dataclass(frozen=True, slots=True)
class DependencyRecord:
    ecosystem: str
    name: str
    version: str | None
    source: str | None
    integrity: str | None
    direct: bool
    pinned: bool
    manifest: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "ecosystem": self.ecosystem,
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "integrity": self.integrity,
            "direct": self.direct,
            "pinned": self.pinned,
            "manifest": self.manifest,
        }


@dataclass(frozen=True, slots=True)
class DependencyResult:
    records: tuple[DependencyRecord, ...]
    findings: tuple[SecurityFinding, ...]
    capabilities: tuple[str, ...]
    complete: bool
    osv: dict[str, Any] | None = None


def scan_dependencies(root: Path, limits: ScanLimits, *, osv: bool = False) -> DependencyResult:
    records: list[DependencyRecord] = []
    findings: list[SecurityFinding] = []
    capabilities: set[str] = set()
    complete = True

    package_json = root / "package.json"
    if package_json.is_file():
        node_records, node_findings, node_capabilities, node_complete = _scan_package_json(
            root, package_json, limits
        )
        records.extend(node_records)
        findings.extend(node_findings)
        capabilities.update(node_capabilities)
        complete = complete and node_complete

    pyproject = root / "pyproject.toml"
    requirements = root / "requirements.txt"
    if pyproject.is_file():
        parsed_records, parsed_findings, parsed_complete = _scan_pyproject(root, pyproject)
        records.extend(parsed_records)
        findings.extend(parsed_findings)
        complete = complete and parsed_complete
    if requirements.is_file():
        parsed_records, parsed_findings, parsed_complete = _scan_requirements(requirements)
        records.extend(parsed_records)
        findings.extend(parsed_findings)
        complete = complete and parsed_complete

    cargo = root / "Cargo.toml"
    if cargo.is_file():
        parsed_records, parsed_findings, parsed_complete = _scan_cargo(root, cargo)
        records.extend(parsed_records)
        findings.extend(parsed_findings)
        complete = complete and parsed_complete

    go_mod = root / "go.mod"
    if go_mod.is_file():
        parsed_records, parsed_findings, parsed_complete = _scan_go_mod(root, go_mod)
        records.extend(parsed_records)
        findings.extend(parsed_findings)
        complete = complete and parsed_complete

    for record in records:
        source = record.source or ""
        mutable_vcs = source and (
            MUTABLE_SOURCE_RE.search(source)
            or source.startswith(("git+", "git@", "ssh://")) and not record.pinned
            or record.ecosystem == "cargo" and source.startswith(("http://", "https://")) and not record.pinned
        )
        if mutable_vcs:
            findings.append(
                _finding(
                    "ASSURANCE_MUTABLE_VCS_DEPENDENCY",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "supply-chain",
                    "Dependency source is mutable",
                    "The dependency can resolve different code without a manifest change.",
                    "Pin a complete commit or immutable package version and verify the lockfile integrity.",
                    record.manifest,
                    {"ecosystem": record.ecosystem, "package": record.name},
                )
            )
        if source and INSECURE_SOURCE_RE.search(source):
            findings.append(
                _finding(
                    "ASSURANCE_INSECURE_DEPENDENCY_SOURCE",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "supply-chain",
                    "Dependency source uses an insecure transport or trust bypass",
                    "The package source can be intercepted or bypasses certificate validation.",
                    "Use an HTTPS registry with strict certificate validation and immutable integrity metadata.",
                    record.manifest,
                    {"ecosystem": record.ecosystem, "package": record.name},
                )
            )
        if record.direct and not record.pinned:
            findings.append(
                _finding(
                    "ASSURANCE_UNPINNED_DIRECT_DEPENDENCY",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    "supply-chain",
                    "Direct dependency is not exactly pinned",
                    "The direct dependency range can resolve different code over time.",
                    "Use an exact version or complete immutable commit and commit the lockfile.",
                    record.manifest,
                    {"ecosystem": record.ecosystem, "package": record.name},
                )
            )
        if _looks_like_typosquat(record.name):
            findings.append(
                _finding(
                    "ASSURANCE_DEPENDENCY_TYPOSQUAT",
                    Severity.MEDIUM,
                    Confidence.MEDIUM,
                    "supply-chain",
                    "Dependency name resembles a common package",
                    "The name is one edit or adjacent transposition away from a widely used package.",
                    "Verify the package owner, registry page, source repository, and intended spelling.",
                    record.manifest,
                    {"ecosystem": record.ecosystem, "package": record.name},
                )
            )

    osv_payload: dict[str, Any] | None = None
    if osv and records:
        try:
            osv_payload = query_osv(records, limits)
            vulnerabilities = osv_payload.get("vulnerabilities", [])
            if isinstance(vulnerabilities, list):
                for vulnerability in vulnerabilities[:10_000]:
                    if not isinstance(vulnerability, dict):
                        continue
                    findings.append(
                        _finding(
                            "ASSURANCE_KNOWN_VULNERABLE_DEPENDENCY",
                            Severity.HIGH,
                            Confidence.HIGH,
                            "supply-chain",
                            "Dependency has a known OSV advisory",
                            "An exact dependency version matched a vulnerability advisory.",
                            "Upgrade to a fixed version and regenerate the immutable lockfile.",
                            None,
                            {
                                "advisory_id": str(vulnerability.get("id", "unknown")),
                                "package": str(vulnerability.get("package", "unknown")),
                                "ecosystem": vulnerability.get("ecosystem"),
                            },
                        )
                    )
        except (OSError, ValueError, urllib.error.URLError) as exc:
            findings.append(
                _finding(
                    "ASSURANCE_OSV_UNAVAILABLE",
                    Severity.LOW,
                    Confidence.HIGH,
                    "coverage",
                    "OSV dependency intelligence was unavailable",
                    "The optional vulnerability feed could not be queried within strict network bounds.",
                    "Retry from an approved network path or rely on an independently mirrored advisory feed.",
                    None,
                    {"error": type(exc).__name__},
                )
            )
            complete = False

    return DependencyResult(
        records=tuple(_dedupe_records(records)),
        findings=tuple(_dedupe_findings(findings)),
        capabilities=tuple(sorted(capabilities)),
        complete=complete,
        osv=osv_payload,
    )


def _scan_package_json(
    root: Path,
    path: Path,
    limits: ScanLimits,
) -> tuple[list[DependencyRecord], list[SecurityFinding], set[str], bool]:
    findings: list[SecurityFinding] = []
    capabilities: set[str] = set()
    try:
        payload = _load_json(path, limits.max_manifest_bytes)
    except (OSError, ValueError, json.JSONDecodeError):
        return (
            [],
            [
                _finding(
                    "ASSURANCE_PACKAGE_JSON_INVALID",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "supply-chain",
                    "package.json is invalid or ambiguous",
                    "The dependency and lifecycle surface cannot be trusted.",
                    "Fix package.json and validate it against an exact package schema.",
                    path.name,
                )
            ],
            capabilities,
            False,
        )
    if not isinstance(payload, dict):
        return [], findings, capabilities, False
    records: list[DependencyRecord] = []
    for field_name in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        dependencies = payload.get(field_name)
        if not isinstance(dependencies, dict):
            continue
        for name, raw_version in dependencies.items():
            if not isinstance(name, str) or not isinstance(raw_version, str):
                continue
            records.append(
                DependencyRecord(
                    ecosystem="npm",
                    name=name,
                    version=raw_version,
                    source=raw_version if _looks_like_source(raw_version) else None,
                    integrity=None,
                    direct=True,
                    pinned=_node_version_pinned(raw_version),
                    manifest=path.name,
                )
            )
    scripts = payload.get("scripts")
    if isinstance(scripts, dict):
        for name, command in scripts.items():
            if str(name).lower() not in LIFECYCLE_SCRIPTS or not isinstance(command, str):
                continue
            command_digest = hashlib.sha256(command.encode()).hexdigest()
            findings.append(
                _finding(
                    "ASSURANCE_PACKAGE_LIFECYCLE_SCRIPT",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "supply-chain",
                    "Package executes code during installation or publication",
                    "A lifecycle script runs automatically in common package-manager flows.",
                    "Remove automatic execution or require a reviewed, sandboxed, immutable build step.",
                    path.name,
                    {"script": str(name), "command_sha256": command_digest},
                )
            )
            capabilities.add("install-execution")

    lock = next(
        (root / name for name in ("npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb") if (root / name).is_file()),
        None,
    )
    if lock is None:
        findings.append(
            _finding(
                "ASSURANCE_DEPENDENCY_LOCK_MISSING",
                Severity.MEDIUM,
                Confidence.HIGH,
                "supply-chain",
                "Node dependency lockfile is missing",
                "Package resolution is not reproducibly bound to exact transitive versions.",
                "Commit a lockfile generated from a trusted registry and review its integrity fields.",
                path.name,
            )
        )
    elif lock.name in {"package-lock.json", "npm-shrinkwrap.json"}:
        findings.extend(_scan_node_lock(lock, limits))
    findings.extend(_scan_npm_config(root))
    return records, findings, capabilities, True


def _scan_node_lock(path: Path, limits: ScanLimits) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    try:
        payload = _load_json(path, min(limits.max_manifest_bytes * 16, 64 * 1024 * 1024))
    except (OSError, ValueError, json.JSONDecodeError):
        return [
            _finding(
                "ASSURANCE_DEPENDENCY_LOCK_INVALID",
                Severity.HIGH,
                Confidence.HIGH,
                "supply-chain",
                "Node dependency lockfile is invalid",
                "The exact dependency graph cannot be trusted.",
                "Regenerate the lockfile with a trusted package manager and review the diff.",
                path.name,
            )
        ]
    packages = payload.get("packages") if isinstance(payload, dict) else None
    if isinstance(packages, dict):
        for package_path, record in list(packages.items())[:100_000]:
            if not isinstance(record, dict):
                continue
            resolved = record.get("resolved")
            integrity = record.get("integrity")
            if isinstance(resolved, str) and resolved.startswith("http://"):
                findings.append(
                    _finding(
                        "ASSURANCE_INSECURE_LOCK_SOURCE",
                        Severity.HIGH,
                        Confidence.HIGH,
                        "supply-chain",
                        "Lockfile resolves a package over plaintext HTTP",
                        "The locked package archive can be intercepted.",
                        "Use HTTPS and verify the package integrity digest.",
                        path.name,
                        {"package_path_sha256": hashlib.sha256(str(package_path).encode()).hexdigest()},
                    )
                )
            if resolved is not None and not integrity and not str(resolved).startswith(("file:", "link:")):
                findings.append(
                    _finding(
                        "ASSURANCE_LOCK_INTEGRITY_MISSING",
                        Severity.MEDIUM,
                        Confidence.HIGH,
                        "supply-chain",
                        "Lockfile package lacks integrity metadata",
                        "The package archive is not independently bound to a cryptographic digest.",
                        "Regenerate a modern lockfile that includes integrity for registry artifacts.",
                        path.name,
                        {"package_path_sha256": hashlib.sha256(str(package_path).encode()).hexdigest()},
                    )
                )
    return findings


def _scan_npm_config(root: Path) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    for name in (".npmrc", ".yarnrc", ".yarnrc.yml", "pnpm-workspace.yaml"):
        path = root / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if re.search(r"(?im)^\s*strict-ssl\s*=\s*false\s*$", text):
            findings.append(
                _finding(
                    "ASSURANCE_PACKAGE_TLS_DISABLED",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "supply-chain",
                    "Package-manager TLS verification is disabled",
                    "Registry certificate verification is explicitly disabled.",
                    "Remove the override and use a trusted CA configuration.",
                    name,
                )
            )
        for match in re.finditer(r"(?im)^\s*registry\s*=\s*(http://\S+)", text):
            findings.append(
                _finding(
                    "ASSURANCE_INSECURE_DEPENDENCY_SOURCE",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "supply-chain",
                    "Package registry uses plaintext HTTP",
                    "The configured registry can be intercepted.",
                    "Use an HTTPS registry with strict certificate validation.",
                    name,
                    {"registry_sha256": hashlib.sha256(match.group(1).encode()).hexdigest()},
                )
            )
    return findings


def _scan_pyproject(
    root: Path,
    path: Path,
) -> tuple[list[DependencyRecord], list[SecurityFinding], bool]:
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return [], [
            _finding(
                "ASSURANCE_PYPROJECT_INVALID",
                Severity.HIGH,
                Confidence.HIGH,
                "supply-chain",
                "pyproject.toml is invalid",
                "Python dependency metadata cannot be parsed.",
                "Fix the TOML document before distribution.",
                path.name,
            )
        ], False
    records: list[DependencyRecord] = []
    project = payload.get("project")
    if isinstance(project, dict):
        dependencies = project.get("dependencies")
        if isinstance(dependencies, list):
            for dependency in dependencies:
                if isinstance(dependency, str):
                    records.append(_python_record(dependency, path.name, direct=True))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for values in optional.values():
                if isinstance(values, list):
                    for dependency in values:
                        if isinstance(dependency, str):
                            records.append(_python_record(dependency, path.name, direct=True))
    poetry = payload.get("tool")
    if isinstance(poetry, dict):
        poetry_section = poetry.get("poetry")
        if isinstance(poetry_section, dict):
            dependencies = poetry_section.get("dependencies")
            if isinstance(dependencies, dict):
                for name, value in dependencies.items():
                    if str(name).lower() == "python":
                        continue
                    records.append(_poetry_record(str(name), value, path.name))
    lock_present = any((root / name).is_file() for name in ("uv.lock", "poetry.lock", "Pipfile.lock"))
    findings: list[SecurityFinding] = []
    if records and not lock_present:
        findings.append(
            _finding(
                "ASSURANCE_DEPENDENCY_LOCK_MISSING",
                Severity.MEDIUM,
                Confidence.HIGH,
                "supply-chain",
                "Python dependency lockfile is missing",
                "The transitive graph is not reproducibly bound.",
                "Commit an uv, Poetry, or Pipenv lockfile with hashes where supported.",
                path.name,
            )
        )
    return records, findings, True


def _scan_requirements(path: Path) -> tuple[list[DependencyRecord], list[SecurityFinding], bool]:
    try:
        lines = path.read_text(encoding="utf-8", errors="strict").splitlines()
    except (OSError, UnicodeDecodeError):
        return [], [
            _finding(
                "ASSURANCE_REQUIREMENTS_INVALID",
                Severity.HIGH,
                Confidence.HIGH,
                "supply-chain",
                "requirements.txt could not be read as UTF-8",
                "Dependency directives cannot be parsed safely.",
                "Regenerate a UTF-8 requirements file with exact versions and hashes.",
                path.name,
            )
        ], False
    records: list[DependencyRecord] = []
    findings: list[SecurityFinding] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(("--trusted-host", "--index-url http://", "--extra-index-url http://")):
            findings.append(
                _finding(
                    "ASSURANCE_INSECURE_PYPI_CONFIGURATION",
                    Severity.HIGH,
                    Confidence.HIGH,
                    "supply-chain",
                    "Python package source weakens transport trust",
                    "The requirements file trusts a host or uses a plaintext index.",
                    "Use HTTPS with certificate validation and a controlled package mirror.",
                    path.name,
                )
            )
            continue
        if stripped.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
            findings.append(
                _finding(
                    "ASSURANCE_INDIRECT_REQUIREMENTS_FILE",
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    "coverage",
                    "Requirements file includes another dependency file",
                    "The included file must be independently inventoried and parsed.",
                    "Ensure every included file is contained, digest-bound, and exactly pinned.",
                    path.name,
                    {"directive_sha256": hashlib.sha256(stripped.encode()).hexdigest()},
                )
            )
            continue
        records.append(_python_record(stripped, path.name, direct=True))
    return records, findings, True


def _scan_cargo(
    root: Path,
    path: Path,
) -> tuple[list[DependencyRecord], list[SecurityFinding], bool]:
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return [], [
            _finding(
                "ASSURANCE_CARGO_TOML_INVALID",
                Severity.HIGH,
                Confidence.HIGH,
                "supply-chain",
                "Cargo.toml is invalid",
                "Rust dependency metadata cannot be parsed.",
                "Fix the manifest before distribution.",
                path.name,
            )
        ], False
    records: list[DependencyRecord] = []
    for section_name in ("dependencies", "dev-dependencies", "build-dependencies"):
        section = payload.get(section_name)
        if not isinstance(section, dict):
            continue
        for name, value in section.items():
            version: str | None = None
            source: str | None = None
            integrity: str | None = None
            pinned = False
            if isinstance(value, str):
                version = value
                pinned = _semver_pinned(value)
            elif isinstance(value, dict):
                raw_version = value.get("version")
                version = str(raw_version) if isinstance(raw_version, str) else None
                git = value.get("git")
                rev = value.get("rev")
                tag = value.get("tag")
                branch = value.get("branch")
                path_value = value.get("path")
                if isinstance(git, str):
                    source = git
                    if isinstance(rev, str):
                        source += f"#{rev}"
                    elif isinstance(tag, str):
                        source += f"#tag:{tag}"
                    elif isinstance(branch, str):
                        source += f"#branch:{branch}"
                    pinned = isinstance(rev, str) and bool(FULL_COMMIT_RE.fullmatch(rev))
                elif isinstance(path_value, str):
                    source = f"path:{path_value}"
                    pinned = False
                else:
                    pinned = bool(version and _semver_pinned(version))
            records.append(
                DependencyRecord(
                    ecosystem="cargo",
                    name=str(name),
                    version=version,
                    source=source,
                    integrity=integrity,
                    direct=True,
                    pinned=pinned,
                    manifest=path.name,
                )
            )
    findings: list[SecurityFinding] = []
    if records and not (root / "Cargo.lock").is_file():
        findings.append(
            _finding(
                "ASSURANCE_DEPENDENCY_LOCK_MISSING",
                Severity.MEDIUM,
                Confidence.HIGH,
                "supply-chain",
                "Cargo.lock is missing",
                "The exact Rust dependency graph is not committed.",
                "Commit Cargo.lock for distributed applications and review source overrides.",
                path.name,
            )
        )
    patch = payload.get("patch")
    if isinstance(patch, dict):
        findings.append(
            _finding(
                "ASSURANCE_CARGO_SOURCE_OVERRIDE",
                Severity.MEDIUM,
                Confidence.HIGH,
                "supply-chain",
                "Cargo source patch overrides registry packages",
                "Patch sections can redirect dependencies to alternate code.",
                "Review and pin every patch source to a complete immutable commit.",
                path.name,
            )
        )
    return records, findings, True


def _scan_go_mod(
    root: Path,
    path: Path,
) -> tuple[list[DependencyRecord], list[SecurityFinding], bool]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return [], [], False
    records: list[DependencyRecord] = []
    findings: list[SecurityFinding] = []
    in_require = False
    for raw in lines:
        line = raw.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        candidate = line.removeprefix("require ")
        if not in_require and candidate == line and not line.startswith("require "):
            if line.startswith("replace ") and "=>" in line:
                findings.append(
                    _finding(
                        "ASSURANCE_GO_REPLACE_DIRECTIVE",
                        Severity.MEDIUM,
                        Confidence.HIGH,
                        "supply-chain",
                        "Go module uses a replace directive",
                        "Replace directives can redirect modules to local or mutable sources.",
                        "Remove local replacements from distributed builds or pin and attest the replacement.",
                        path.name,
                        {"directive_sha256": hashlib.sha256(line.encode()).hexdigest()},
                    )
                )
            continue
        fields = candidate.split()
        if len(fields) >= 2:
            name, version = fields[0], fields[1]
            records.append(
                DependencyRecord(
                    ecosystem="go",
                    name=name,
                    version=version,
                    source=None,
                    integrity=None,
                    direct=True,
                    pinned=bool(version.startswith("v") and version != "v0.0.0-latest"),
                    manifest=path.name,
                )
            )
    if records and not (root / "go.sum").is_file():
        findings.append(
            _finding(
                "ASSURANCE_DEPENDENCY_LOCK_MISSING",
                Severity.MEDIUM,
                Confidence.HIGH,
                "supply-chain",
                "go.sum is missing",
                "Go module content hashes are not committed.",
                "Commit go.sum and verify the configured proxy and checksum database.",
                path.name,
            )
        )
    return records, findings, True


def query_osv(records: Iterable[DependencyRecord], limits: ScanLimits) -> dict[str, Any]:
    queries: list[dict[str, Any]] = []
    record_order: list[DependencyRecord] = []
    ecosystem_map = {"npm": "npm", "pypi": "PyPI", "cargo": "crates.io", "go": "Go"}
    for record in records:
        if len(queries) >= limits.max_osv_queries:
            break
        if not record.version or not record.pinned:
            continue
        ecosystem = ecosystem_map.get(record.ecosystem)
        if ecosystem is None:
            continue
        version = _clean_version(record.version)
        if not version:
            continue
        queries.append({"package": {"name": record.name, "ecosystem": ecosystem}, "version": version})
        record_order.append(record)
    if not queries:
        return {"queried": 0, "vulnerabilities": []}
    body = json.dumps({"queries": queries}, separators=(",", ":")).encode("utf-8")
    if len(body) > 2 * 1024 * 1024:
        raise ValueError("OSV request exceeds size limit")
    request = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "hol-guard-assurance/1"},
    )
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(request, timeout=limits.osv_timeout_seconds) as response:
        if response.status != 200:
            raise urllib.error.HTTPError(request.full_url, response.status, "OSV query failed", response.headers, None)
        raw = response.read(limits.max_osv_response_bytes + 1)
    if len(raw) > limits.max_osv_response_bytes:
        raise ValueError("OSV response exceeds size limit")
    payload = json.loads(raw, object_pairs_hook=_reject_duplicates)
    results = payload.get("results") if isinstance(payload, dict) else None
    vulnerabilities: list[dict[str, Any]] = []
    if isinstance(results, list):
        for index, result in enumerate(results[: len(record_order)]):
            if not isinstance(result, dict):
                continue
            record = record_order[index]
            vulnerabilities_for_query = result.get("vulns")
            if not isinstance(vulnerabilities_for_query, list):
                continue
            for vulnerability in vulnerabilities_for_query[:1000]:
                if not isinstance(vulnerability, dict):
                    continue
                vulnerabilities.append(
                    {
                        "id": str(vulnerability.get("id", "unknown")),
                        "package": record.name,
                        "ecosystem": record.ecosystem,
                    }
                )
    return {"queried": len(queries), "vulnerabilities": vulnerabilities}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(  # type: ignore[override]
        self,
        req: object,
        fp: object,
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        raise urllib.error.HTTPError(str(getattr(req, "full_url", "")), code, "redirect refused", headers, fp)


def _load_json(path: Path, maximum_bytes: int) -> object:
    if path.stat().st_size > maximum_bytes:
        raise ValueError("JSON file exceeds limit")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates)


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _node_version_pinned(value: str) -> bool:
    normalized = value.strip()
    if normalized.startswith(("file:", "link:", "workspace:")):
        return False
    if normalized.startswith(("git+", "git@", "ssh://", "http://", "https://")):
        fragment = normalized.rsplit("#", 1)[1] if "#" in normalized else ""
        return bool(FULL_COMMIT_RE.fullmatch(fragment))
    return bool(SEMVER_EXACT_RE.fullmatch(normalized))


def _python_record(dependency: str, manifest: str, *, direct: bool) -> DependencyRecord:
    stripped = dependency.strip()
    source = stripped if " @ " in stripped or stripped.startswith(("git+", "http://", "https://")) else None
    name_match = re.match(r"^([A-Za-z0-9_.-]+)", stripped)
    name = name_match.group(1) if name_match else stripped[:128]
    version = None
    pinned = False
    exact_match = re.match(r"^[A-Za-z0-9_.-]+(?:\[[^]]+\])?==([^;\s]+)", stripped)
    if exact_match:
        version = exact_match.group(1)
        pinned = True
    elif " @ " in stripped:
        source_value = stripped.split(" @ ", 1)[1]
        fragment = source_value.rsplit("@", 1)[-1] if "@" in source_value else source_value.rsplit("#", 1)[-1]
        pinned = bool(FULL_COMMIT_RE.fullmatch(fragment))
    return DependencyRecord("pypi", name, version or stripped, source, None, direct, pinned, manifest)


def _poetry_record(name: str, value: object, manifest: str) -> DependencyRecord:
    if isinstance(value, str):
        return DependencyRecord("pypi", name, value, None, None, True, _semver_pinned(value), manifest)
    if isinstance(value, dict):
        version = value.get("version")
        git = value.get("git")
        rev = value.get("rev")
        branch = value.get("branch")
        tag = value.get("tag")
        source = str(git) if isinstance(git, str) else None
        if source and isinstance(rev, str):
            source += f"#{rev}"
        elif source and isinstance(branch, str):
            source += f"#branch:{branch}"
        elif source and isinstance(tag, str):
            source += f"#tag:{tag}"
        pinned = bool(isinstance(rev, str) and FULL_COMMIT_RE.fullmatch(rev)) or bool(
            isinstance(version, str) and _semver_pinned(version)
        )
        return DependencyRecord("pypi", name, str(version) if version is not None else None, source, None, True, pinned, manifest)
    return DependencyRecord("pypi", name, str(value), None, None, True, False, manifest)


def _semver_pinned(value: str) -> bool:
    normalized = value.strip().removeprefix("=")
    return bool(SEMVER_EXACT_RE.fullmatch(normalized))


def _looks_like_source(value: str) -> bool:
    return value.startswith(("git+", "git@", "ssh://", "http://", "https://", "file:", "link:"))


def _looks_like_typosquat(name: str) -> bool:
    normalized = name.lower().split("/")[-1].replace("_", "-")
    for common in COMMON_PACKAGES:
        if normalized == common:
            return False
        if _damerau_levenshtein_at_most_one(normalized, common):
            return True
    return False


def _damerau_levenshtein_at_most_one(left: str, right: str) -> bool:
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        differences = [index for index, (a, b) in enumerate(zip(left, right, strict=True)) if a != b]
        if len(differences) == 1:
            return True
        return (
            len(differences) == 2
            and differences[1] == differences[0] + 1
            and left[differences[0]] == right[differences[1]]
            and left[differences[1]] == right[differences[0]]
        )
    shorter, longer = (left, right) if len(left) < len(right) else (right, left)
    index_short = index_long = differences = 0
    while index_short < len(shorter) and index_long < len(longer):
        if shorter[index_short] == longer[index_long]:
            index_short += 1
            index_long += 1
            continue
        differences += 1
        if differences > 1:
            return False
        index_long += 1
    return True


def _clean_version(value: str) -> str:
    normalized = value.strip().lstrip("=v")
    return normalized if re.fullmatch(r"[0-9A-Za-z.+_-]+", normalized) else ""


def _dedupe_records(records: list[DependencyRecord]) -> list[DependencyRecord]:
    unique = {
        (record.ecosystem, record.name, record.version, record.source, record.manifest): record
        for record in records
    }
    return sorted(unique.values(), key=lambda item: (item.ecosystem, item.name, item.version or "", item.manifest))


def _dedupe_findings(findings: list[SecurityFinding]) -> list[SecurityFinding]:
    return list({finding.fingerprint: finding for finding in findings}.values())


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
    return SecurityFinding(
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        category=category,
        title=title,
        description=description,
        remediation=remediation,
        locations=(EvidenceLocation(path=path),) if path else (),
        metadata=metadata or {},
    ).with_fingerprint()
