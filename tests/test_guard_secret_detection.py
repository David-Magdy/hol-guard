from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.secrets import scan_repository_secrets, scan_secret_text, secret_rule_catalog


def _github_token() -> str:
    return "ghp_" + ("A" * 40)


def _generic_secret() -> str:
    return "Q7v9K2mX4pR8sT6wY3nB5cD1fG0hJ9kL"


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def test_provider_secret_is_detected_without_public_candidate() -> None:
    secret = _github_token()
    result = scan_secret_text(f"GITHUB_TOKEN={secret}\n", path="src/config.py")

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "github-token"
    assert finding.severity == "critical"
    assert finding.confidence == "high"
    payload = result.to_public_dict()
    encoded = json.dumps(payload)
    assert secret not in encoded
    assert "candidate" not in encoded


def test_provider_secret_remains_detectable_in_documentation() -> None:
    secret = _github_token()
    result = scan_secret_text(f"token = {secret}\n", path="docs/example.md")

    assert [finding.rule_id for finding in result.findings] == ["github-token"]


def test_contextual_high_entropy_assignment_is_detected() -> None:
    secret = _generic_secret()
    result = scan_secret_text(f"PAYMENTS_API_SECRET={secret}\n", path="app/settings.py")

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "credential-assignment"
    assert result.findings[0].confidence in {"medium", "high"}


def test_generic_random_value_without_credential_context_is_not_detected() -> None:
    secret = _generic_secret()
    result = scan_secret_text(f"BUILD_CACHE_KEY={secret}\n", path="app/settings.py")

    assert result.findings == ()


def test_obvious_documentation_placeholder_is_suppressed() -> None:
    result = scan_secret_text(
        "API_SECRET=replace_me_with_your_secret\n",
        path="docs/configuration.md",
    )

    assert result.findings == ()


def test_database_url_password_is_contextually_detected() -> None:
    password = _generic_secret()
    result = scan_secret_text(
        f"DATABASE_URL=postgres://service:{password}@db.internal/app\n",
        path=".env.production",
    )

    assert any(finding.rule_id == "database-url-password" for finding in result.findings)
    assert password not in json.dumps(result.to_public_dict())


def test_fingerprint_is_scoped_to_caller_key() -> None:
    secret = _github_token()
    finding = scan_secret_text(f"TOKEN={secret}\n").findings[0]

    first = finding.fingerprint(b"tenant-a")
    second = finding.fingerprint(b"tenant-b")
    assert first != second
    assert secret not in first
    assert secret not in second
    with pytest.raises(ValueError):
        finding.fingerprint(b"")


def test_rule_catalog_contains_validatable_provider_families() -> None:
    rules = secret_rule_catalog()
    validation_kinds = {str(rule["validation"]) for rule in rules}

    assert {"github", "gitlab", "aws", "slack", "stripe", "openai", "anthropic", "npm", "pypi"} <= validation_kinds


def test_repository_scan_skips_binary_and_does_not_emit_absolute_path(tmp_path: Path) -> None:
    secret = _github_token()
    (tmp_path / "config.py").write_text(f"TOKEN={secret}\n")
    (tmp_path / "image.png").write_bytes(b"\x89PNG\x00" + secret.encode())

    result = scan_repository_secrets(tmp_path)
    payload = result.to_public_dict()
    encoded = json.dumps(payload)

    assert result.findings
    assert all(not finding.path.startswith(str(tmp_path)) for finding in result.findings)
    assert secret not in encoded
    assert "image.png" not in encoded


def test_history_scan_finds_secret_removed_from_head(tmp_path: Path) -> None:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "guard@example.invalid")
    _git(tmp_path, "config", "user.name", "Guard Test")
    secret = _github_token()
    target = tmp_path / "config.py"
    target.write_text(f"TOKEN={secret}\n")
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-m", "add config")
    target.write_text("TOKEN_FROM_ENV = True\n")
    _git(tmp_path, "add", "config.py")
    _git(tmp_path, "commit", "-m", "remove credential")

    head_only = scan_repository_secrets(tmp_path, include_history=False)
    history = scan_repository_secrets(tmp_path, include_history=True, max_commits=10)

    assert head_only.findings == ()
    assert any(finding.source == "git_history" for finding in history.findings)
    assert secret not in json.dumps(history.to_public_dict())


def test_repository_scan_respects_finding_limit(tmp_path: Path) -> None:
    for index in range(5):
        (tmp_path / f"secret-{index}.txt").write_text(f"TOKEN={_github_token()}{index}\n")

    result = scan_repository_secrets(tmp_path, max_findings=2)

    assert len(result.findings) <= 2
    assert result.truncated is True
