"""Public metadata for the built-in secret detectors.

This catalog is deliberately isolated from the executable detector rules.  The
CLI may serialize these descriptive fields, while detector patterns and scanned
candidate bytes never enter the output data flow.
"""

from __future__ import annotations

from .secret_detection import SecretRuleCatalogEntry

PUBLIC_SECRET_RULE_CATALOG: tuple[SecretRuleCatalogEntry, ...] = (
    {
        "rule_id": "github-token",
        "family": "GitHub token",
        "severity": "critical",
        "validation": "github",
        "strong_format": True,
        "description": "GitHub personal, OAuth, user, server, refresh, or fine-grained token.",
    },
    {
        "rule_id": "gitlab-token",
        "family": "GitLab token",
        "severity": "critical",
        "validation": "gitlab",
        "strong_format": True,
        "description": "GitLab personal/project/group access token.",
    },
    {
        "rule_id": "aws-access-key",
        "family": "AWS access key ID",
        "severity": "high",
        "validation": "aws",
        "strong_format": True,
        "description": "AWS long-lived or STS access key identifier.",
    },
    {
        "rule_id": "slack-token",
        "family": "Slack token",
        "severity": "critical",
        "validation": "slack",
        "strong_format": True,
        "description": "Slack bot, app, user, refresh, or service token.",
    },
    {
        "rule_id": "slack-webhook",
        "family": "Slack incoming webhook",
        "severity": "critical",
        "validation": "slack",
        "strong_format": True,
        "description": "Slack incoming webhook URL.",
    },
    {
        "rule_id": "stripe-secret-key",
        "family": "Stripe secret key",
        "severity": "critical",
        "validation": "stripe",
        "strong_format": True,
        "description": "Stripe secret or restricted API key.",
    },
    {
        "rule_id": "openai-api-key",
        "family": "OpenAI API key",
        "severity": "critical",
        "validation": "openai",
        "strong_format": True,
        "description": "OpenAI project/service/account API key.",
    },
    {
        "rule_id": "anthropic-api-key",
        "family": "Anthropic API key",
        "severity": "critical",
        "validation": "anthropic",
        "strong_format": True,
        "description": "Anthropic API key.",
    },
    {
        "rule_id": "huggingface-token",
        "family": "Hugging Face token",
        "severity": "high",
        "validation": "huggingface",
        "strong_format": True,
        "description": "Hugging Face user or organization token.",
    },
    {
        "rule_id": "npm-token",
        "family": "npm access token",
        "severity": "critical",
        "validation": "npm",
        "strong_format": True,
        "description": "npm granular or automation access token.",
    },
    {
        "rule_id": "pypi-token",
        "family": "PyPI API token",
        "severity": "critical",
        "validation": "pypi",
        "strong_format": True,
        "description": "PyPI scoped API token.",
    },
    {
        "rule_id": "google-api-key",
        "family": "Google API key",
        "severity": "high",
        "validation": "google",
        "strong_format": True,
        "description": "Google Cloud/Firebase API key.",
    },
    {
        "rule_id": "sendgrid-api-key",
        "family": "SendGrid API key",
        "severity": "critical",
        "validation": "sendgrid",
        "strong_format": True,
        "description": "SendGrid API key.",
    },
    {
        "rule_id": "pem-private-key",
        "family": "PEM private key",
        "severity": "critical",
        "validation": "none",
        "strong_format": True,
        "description": "Private-key material in PEM/OpenSSH-style form.",
    },
    {
        "rule_id": "database-url-password",
        "family": "Database URL password",
        "severity": "critical",
        "validation": "none",
        "strong_format": False,
        "description": "Password embedded in a database connection URL.",
    },
    {
        "rule_id": "basic-auth-url-password",
        "family": "Basic-auth URL password",
        "severity": "high",
        "validation": "none",
        "strong_format": False,
        "description": "Credential embedded in an HTTP(S) URL.",
    },
    {
        "rule_id": "jwt-token",
        "family": "JWT bearer token",
        "severity": "high",
        "validation": "none",
        "strong_format": False,
        "description": "JWT-like bearer token in credential context.",
    },
    {
        "rule_id": "credential-assignment",
        "family": "Contextual credential assignment",
        "severity": "high",
        "validation": "none",
        "strong_format": False,
        "description": "High-entropy credential assignment accepted only with contextual evidence.",
    },
)


__all__ = ["PUBLIC_SECRET_RULE_CATALOG"]
