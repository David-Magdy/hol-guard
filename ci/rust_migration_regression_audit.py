#!/usr/bin/env python3
"""Privacy-safe regression contract for the HOL Guard Rust P0-P2 migration."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

BLOCKING = frozenset({"critical", "high"})
CATEGORY_PATTERNS: Mapping[str, re.Pattern[str]] = {
    "native_runtime": re.compile(r"(?:native|rust|resident|runtime|supervisor|resilien|protocol)", re.I),
    "command_extensions": re.compile(r"(?:command|extension|pattern|pretool|pre_tool)", re.I),
    "package_supply_chain": re.compile(r"(?:package|supply[_-]?chain|shim|firewall|lockfile|manifest|archive)", re.I),
    "filesystem_integrity": re.compile(r"(?:path|filesystem|secure[_-]?fs|symlink|hash|integrity|walk)", re.I),
    "security_regressions": re.compile(r"(?:security|secret|exfil|prompt[_-]?inject|destruct|tamper|approval|policy)", re.I),
    "installed_artifacts": re.compile(r"(?:installed|wheel|publish|packag|artifact|provenance|sbom)", re.I),
}
TEMP_WORKFLOW = re.compile(r"(?:^tmp-|temporary|rust.*(?:export|transfer|apply[-_]?patch|bundle))", re.I)
UNSAFE_RUST = re.compile(r"(?m)^\s*(?:pub\s+)?unsafe\s+(?:fn|impl|trait)\b|\bunsafe\s*\{")
NETWORK_RUST = re.compile(r"\b(?:reqwest|hyper|ureq|curl|TcpStream::connect|UdpSocket::connect)\b")


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    title: str
    detail: str
    paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuditResult:
    findings: tuple[Finding, ...]
    test_counts: Mapping[str, int]

    @property
    def blocking(self) -> tuple[Finding, ...]:
        return tuple(item for item in self.findings if item.severity in BLOCKING)

    def jsonable(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "blocking_count": len(self.blocking),
            "finding_counts": dict(Counter(item.severity for item in self.findings)),
            "findings": [asdict(item) for item in self.findings],
            "test_counts": dict(self.test_counts),
        }


def repository_root(start: Path | None = None) -> Path:
    path = (start or Path(__file__)).resolve()
    for candidate in (path, *path.parents):
        if (candidate / "pyproject.toml").is_file() and (candidate / ".github").is_dir():
            return candidate
    raise RuntimeError("unable to locate repository root")


def relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def definitions(path: Path) -> set[str]:
    try:
        tree = ast.parse(text(path))
    except SyntaxError:
        return set()
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }


def nested_strings(value: Any, key: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for nested_key, nested in value.items():
            yield from nested_strings(nested, str(nested_key))
    elif isinstance(value, list):
        for nested in value:
            yield from nested_strings(nested, key)
    elif isinstance(value, str):
        yield key, value


def test_count(path: Path) -> int:
    try:
        tree = ast.parse(text(path))
    except SyntaxError:
        return 0
    return sum(
        1
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
    )


def test_inventory(root: Path) -> dict[str, int]:
    counts: Counter[str] = Counter()
    files: set[Path] = set()
    for base_name in ("tests", "ci"):
        base = root / base_name
        if base.is_dir():
            files.update(base.rglob("test*.py"))
    for path in sorted(files):
        count = test_count(path)
        if not count:
            continue
        name = relative(root, path)
        for category, pattern in CATEGORY_PATTERNS.items():
            if pattern.search(name):
                counts[category] += count
    return dict(sorted(counts.items()))


def temporary_assets(root: Path) -> tuple[str, ...]:
    found: set[str] = set()
    github = root / ".github"
    if not github.is_dir():
        return ()
    for path in github.iterdir():
        if not path.name.startswith("rust-required-"):
            continue
        if path.is_file():
            found.add(relative(root, path))
        else:
            found.update(relative(root, item) for item in path.rglob("*") if item.is_file())
    workflows = github / "workflows"
    if workflows.is_dir():
        found.update(relative(root, path) for path in workflows.glob("*.y*ml") if TEMP_WORKFLOW.search(path.name))
    return tuple(sorted(found))


def ownership_findings(root: Path) -> list[Finding]:
    contracts = sorted((root / "docs/guard/contracts").glob("*rust*ownership*.json"))
    if not contracts:
        return [Finding("critical", "RUST-REG-002", "Rust/Python ownership contract is missing", "Duplicate Python evaluators can return unnoticed.", ("docs/guard/contracts",))]
    invalid: list[str] = []
    retired: list[tuple[str, str]] = []
    for contract_path in contracts:
        try:
            contract = json.loads(text(contract_path))
        except json.JSONDecodeError:
            invalid.append(relative(root, contract_path))
            continue
        for key, value in nested_strings(contract):
            if not any(token in key.lower() for token in ("removed", "forbidden", "retired", "absent")):
                continue
            if "::" in value:
                retired.append(tuple(value.split("::", 1)))
            elif value.endswith(".py") or value.startswith(("src/", "ci/", "tests/")):
                retired.append((value, ""))
    findings: list[Finding] = []
    if invalid:
        findings.append(Finding("critical", "RUST-REG-003", "Ownership contract is invalid JSON", "The ownership gate cannot run.", tuple(invalid)))
    violations: list[str] = []
    for path_value, symbol in retired:
        path = root / path_value
        if path.exists() and (not symbol or symbol in definitions(path)):
            violations.append(f"{path_value}::{symbol}" if symbol else path_value)
    if violations:
        findings.append(Finding("critical", "RUST-REG-004", "Retired Python enforcement code is present", "A second evaluator can diverge from Rust and weaken or broaden a decision.", tuple(sorted(set(violations)))))
    return findings


def rust_findings(root: Path) -> list[Finding]:
    files = sorted((root / "rust").rglob("*.rs"))
    if not files:
        return [Finding("critical", "RUST-REG-005", "First-party Rust workspace is absent", "The native authority contract cannot be satisfied.", ("rust",))]
    unsafe: list[str] = []
    network: list[str] = []
    for path in files:
        source = text(path)
        path_value = relative(root, path)
        if UNSAFE_RUST.search(source):
            unsafe.append(path_value)
        if NETWORK_RUST.search(source) and "resident" not in path_value.lower() and "transport" not in path_value.lower():
            network.append(path_value)
    findings: list[Finding] = []
    if unsafe:
        findings.append(Finding("critical", "RUST-REG-006", "First-party Rust uses unsafe code", "The native security data plane must remain unsafe-forbidden.", tuple(sorted(set(unsafe)))))
    if network:
        findings.append(Finding("high", "RUST-REG-007", "Unexpected Rust network capability is present", "Only the authenticated local resident transport may use networking.", tuple(sorted(set(network)))))
    return findings


def native_discovery_findings(root: Path) -> list[Finding]:
    hits: list[str] = []
    guard = root / "src/codex_plugin_scanner/guard"
    if not guard.is_dir():
        return []
    for path in guard.rglob("*native*.py"):
        source = text(path)
        if re.search(r"\bshutil\.which\s*\([^\n]*(?:hol-guard-runtime|cargo)", source):
            hits.append(relative(root, path))
        if re.search(r"(?i)(?:urlopen|requests\.|httpx\.|download|fetch)[^\n]{0,160}(?:hol-guard-runtime|runtime-manifest)", source):
            hits.append(relative(root, path))
    return [] if not hits else [Finding("critical", "RUST-REG-008", "Native runtime uses an untrusted discovery surface", "The runtime must remain package-bound and must never be found through PATH or downloaded.", tuple(sorted(set(hits))))]


def workflow_findings(root: Path) -> list[Finding]:
    workflows = " ".join(path.name.lower() for path in (root / ".github/workflows").glob("*.y*ml"))
    required = {"native Rust": ("rust", "native"), "security": ("security", "codeql"), "artifact/wheel": ("wheel", "publish"), "fuzz": ("fuzz",)}
    missing = tuple(name for name, tokens in required.items() if not any(token in workflows for token in tokens))
    return [] if not missing else [Finding("high", "RUST-REG-009", "Required security workflow family is missing", "Native, security, artifact, CodeQL, and fuzz gates must stay executable.", missing)]


def baseline_findings(counts: Mapping[str, int], baseline: Mapping[str, Any]) -> list[Finding]:
    minimums = baseline.get("minimum_test_counts", {})
    if not isinstance(minimums, dict):
        return [Finding("high", "RUST-REG-010", "Regression baseline is malformed", "minimum_test_counts must be an object.")]
    regressions = tuple(f"{name}:{counts.get(name, 0)}<{minimum}" for name, minimum in sorted(minimums.items()) if isinstance(minimum, int) and counts.get(name, 0) < minimum)
    return [] if not regressions else [Finding("high", "RUST-REG-011", "Security or DX regression-test inventory decreased", "Coverage for native runtime, extensions, patterns, package shims, filesystem integrity, security, or installed artifacts was removed.", regressions)]


def audit(root: Path, baseline: Mapping[str, Any] | None = None) -> AuditResult:
    root = root.resolve()
    findings: list[Finding] = []
    temporary = temporary_assets(root)
    if temporary:
        findings.append(Finding("high", "RUST-REG-001", "Temporary Rust migration assets remain", "Transfer chunks and temporary workflows cause noisy CI and preserve obsolete patch state.", temporary))
    findings.extend(ownership_findings(root))
    findings.extend(rust_findings(root))
    findings.extend(native_discovery_findings(root))
    findings.extend(workflow_findings(root))
    counts = test_inventory(root)
    if baseline is not None:
        findings.extend(baseline_findings(counts, baseline))
    return AuditResult(tuple(findings), counts)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--baseline", type=Path, default=Path("ci/rust-migration-regression-baseline.json"))
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args(argv)
    root = args.root.resolve() if args.root else repository_root()
    baseline_path = args.baseline if args.baseline.is_absolute() else root / args.baseline
    baseline = json.loads(baseline_path.read_text(encoding="utf-8")) if baseline_path.is_file() else None
    result = audit(root, baseline)
    serialized = json.dumps(result.jsonable(), indent=2, sort_keys=True) + "\n"
    if args.json_output:
        output = args.json_output if args.json_output.is_absolute() else root / args.json_output
        output.write_text(serialized, encoding="utf-8")
    sys.stdout.write(serialized)
    return 1 if result.blocking else 0


if __name__ == "__main__":
    raise SystemExit(main())
