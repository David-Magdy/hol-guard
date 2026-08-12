from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.secrets.secret_detection import scan_secret_text


def _github_token() -> str:
    return "ghp_" + "Ab3dEf5hIj7lMn9pQr2tUv4xYz6Bcd8Fgh1Jkl3N"


def _google_api_key() -> str:
    return "AIza" + "Ab3dEf5hIj7lMn9pQr2tUv4xYz6Bcd8Fgh1"


@pytest.mark.parametrize(
    ("source", "path"),
    [
        (
            "export type GuardSecretsOverview = Awaited<ReturnType<typeof loadSecretOverview>>;",
            "src/contracts.ts",
        ),
        (
            "const GUARD_SECRET_API_VERSION = 'guard-secrets-api.v1' as const;",
            "src/contracts.ts",
        ),
        (
            "const passwordInputId = 'email-auth-password';",
            "src/login.tsx",
        ),
        (
            "const TOKEN_URL = 'https://oauth.example.test/token';",
            "src/oauth.ts",
        ),
        (
            "secretName: points-staging-tls-secret",
            "deploy/ingress.yaml",
        ),
        (
            'implementation "androidx.credentials:credentials:1.5.0"',
            "android/app/build.gradle",
        ),
        (
            "handoff_token = $script:HANDOFF_TOKEN",
            "public/install.ps1",
        ),
    ],
)
def test_contextual_detector_ignores_metadata_and_code_expressions(source: str, path: str) -> None:
    assert scan_secret_text(source, path=path).findings == ()


@pytest.mark.parametrize(
    "source",
    [
        'POSTGRES_PASSWORD: "<password>"',
        'API_KEY: "replace-with-api-key"',
        'SESSION_TOKEN_SECRET: "super-secret-session-key"',
        'AUTH_TOKEN: "invalid-token"',
        'PASSWORD: "Password123!"',
    ],
)
def test_contextual_detector_ignores_explicit_example_placeholders(source: str) -> None:
    assert scan_secret_text(source, path="deploy/secret.example.yaml").findings == ()


def test_contextual_detector_keeps_random_secret_values_in_configuration() -> None:
    secret = "a9F3c7E1b5D8f2A6c4E9b7D1f5A8c2E6"
    result = scan_secret_text(f'SECRET_KEY: "{secret}"', path="deploy/secrets.yaml")

    assert [finding.rule_id for finding in result.findings] == ["credential-assignment"]


def test_contextual_detector_keeps_random_quoted_code_literal() -> None:
    secret = "v1_R4nd0mCred3ntial_8Zk9Qp2Lm7"
    result = scan_secret_text(f'const clientSecret = "{secret}";', path="src/auth.ts")

    assert [finding.rule_id for finding in result.findings] == ["credential-assignment"]


def test_contextual_detector_ignores_public_protocol_identifier() -> None:
    result = scan_secret_text(
        "const INDEXNOW_API_KEY = '5098d5ba65ef838bbd6d3f293327884b';",
        path="src/indexnow.ts",
    )

    assert result.findings == ()


def test_provider_fixture_is_suppressed_in_nearby_redaction_test_context() -> None:
    token = _github_token()
    result = scan_secret_text(
        "\n".join(
            (
                "describe('redaction', () => {",
                "  it('removes provider tokens', () => {",
                f"    expect(redact('token {token}')).not.toContain('{token}');",
                "  });",
                "});",
            )
        ),
        path="__tests__/redaction.test.ts",
    )

    assert result.findings == ()


def test_provider_fixture_without_test_context_remains_detectable() -> None:
    token = _github_token()
    result = scan_secret_text(f"GITHUB_TOKEN={token}", path="tests/accidental.env")

    assert [finding.rule_id for finding in result.findings] == ["github-token"]


def test_public_google_client_configuration_is_not_treated_as_server_secret() -> None:
    key = _google_api_key()

    assert scan_secret_text(f'{{"current_key": "{key}"}}', path="android/google-services.json").findings == ()
    assert [
        finding.rule_id for finding in scan_secret_text(f"GOOGLE_API_KEY={key}", path=".env.production").findings
    ] == ["google-api-key"]


def test_private_key_fixture_is_suppressed_but_production_header_is_detected() -> None:
    fixture = (
        "fixtureContents: {\n"
        "  key: '-----BEGIN OPENSSH PRIVATE KEY-----\\nfixture-not-real-key-content\\n"
        "-----END OPENSSH PRIVATE KEY-----',\n"
        "}"
    )
    assert scan_secret_text(fixture, path="src/benchmark-scenarios.ts").findings == ()

    result = scan_secret_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nAbCdEf1234567890AbCdEf1234567890\n-----END OPENSSH PRIVATE KEY-----",
        path="config/id_ed25519",
    )
    assert [finding.rule_id for finding in result.findings] == ["pem-private-key"]
