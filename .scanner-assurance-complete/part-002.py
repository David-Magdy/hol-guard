def remove_legacy_enforcement() -> None:
    path = "src/codex_plugin_scanner/_scanner_commands.py"
    text = read(path)
    start = text.find("\ndef _assurance_disposition")
    end = text.find("\ndef _format_scan_json", start)
    if start != -1 and end != -1:
        text = text[:start] + text[end:]
    for block in (
        '''    assurance_disposition = _assurance_disposition(result)
    if _assurance_enforcement_enabled() and assurance_disposition in {"block", "error"}:
        print(
            f'Layered assurance produced a blocking disposition: {assurance_disposition}.',
            file=sys.stderr,
        )
        return 1
''',
        '''    assurance_disposition = _assurance_disposition(result)
    if _assurance_enforcement_enabled() and assurance_disposition in {"block", "error"}:
        return 1
''',
        '''    assurance_disposition = _assurance_disposition(result)
    if _assurance_enforcement_enabled() and assurance_disposition not in {"allow", "warn"}:
        print(
            "Submission blocked by layered assurance: only allow/warn evidence is publishable.",
            file=sys.stderr,
        )
        return 1
''',
        '''    assurance_disposition = _assurance_disposition(result)
    if _assurance_enforced() and assurance_disposition in {"block", "error"}:
        print(
            f'Layered assurance produced a blocking disposition: {assurance_disposition}.',
            file=sys.stderr,
        )
        return 1
''',
        '''    assurance_disposition = _assurance_disposition(result)
    if _assurance_enforced() and assurance_disposition in {"block", "error"}:
        return 1
''',
        '''    assurance_disposition = _assurance_disposition(result)
    if _assurance_enforced() and assurance_disposition not in {"allow", "warn"}:
        print(
            "Submission blocked by layered assurance: only allow/warn evidence is publishable.",
            file=sys.stderr,
        )
        return 1
''',
    ):
        text = text.replace(block, "")
    write(path, text)


def patch_pyproject() -> None:
    path = "pyproject.toml"
    text = read(path)
    start = text.index("dependencies = [")
    end = text.index("\n]", start)
    block = text[start:end]
    if '"fastapi==0.137.1"' not in block:
        anchor = '    "cryptography>=50.0.0",\n'
        if anchor not in text:
            raise RuntimeError("pyproject dependency anchor missing")
        text = text.replace(anchor, anchor + '    "fastapi==0.137.1",\n', 1)
    write(path, text)


def patch_rust_manifest() -> None:
    write(
        "rust/scanner-engine/Cargo.toml",
        '''[package]
name = "hol-guard-scanner-engine"
version = "0.1.0"
edition = "2021"
rust-version = "1.88"
license = "Apache-2.0"
description = "Bounded native and WebAssembly structural analysis for HOL Guard"
publish = false

[[bin]]
name = "hol-guard-scanner-engine"
path = "src/main.rs"

[dependencies]
anyhow = "1.0"
clap = { version = "4.5", features = ["derive"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
sha2 = "0.10"

[profile.release]
codegen-units = 1
lto = "thin"
panic = "abort"
strip = "symbols"

[workspace]
''',
    )


def patch_core_schemas_minimally() -> None:
    originals = {
        "schemas/scan-result.v1.json": Path("/tmp/scan-result.v1.json"),
        "schemas/plugin-quality.v1.json": Path("/tmp/plugin-quality.v1.json"),
    }
    for relative, original in originals.items():
        if original.is_file():
            text = original.read_text(encoding="utf-8")
        else:
            text = read(relative)
        if '    "assurance": {' not in text:
            anchor = '    "repository": {\n' if "scan-result" in relative else '    "verify": {\n'
            replacement = '    "assurance": {\n      "type": ["object", "null"]\n    },\n' + anchor
            if anchor not in text:
                raise RuntimeError(f"schema anchor missing: {relative}")
            text = text.replace(anchor, replacement, 1)
        write(relative, text)


def rewrite_workflow() -> None:
    write(
        ".github/workflows/scanner-assurance.yml",
        '''name: Scanner assurance

on:
  push:
    branches: [release/3.0]
    paths:
      - "src/codex_plugin_scanner/assurance/**"
      - "src/codex_plugin_scanner/assurance_cli.py"
      - "rust/scanner-engine/**"
      - "tests/test_assurance_*.py"
      - "schemas/assurance-*.json"
      - "schemas/extension-*.json"
      - "schemas/detonation-*.json"
      - "pyproject.toml"
      - "uv.lock"
      - ".github/workflows/scanner-assurance.yml"
  pull_request:
    branches: [release/3.0]
    paths:
      - "src/codex_plugin_scanner/assurance/**"
      - "src/codex_plugin_scanner/assurance_cli.py"
      - "rust/scanner-engine/**"
      - "tests/test_assurance_*.py"
      - "schemas/assurance-*.json"
      - "schemas/extension-*.json"
      - "schemas/detonation-*.json"
      - "pyproject.toml"
      - "uv.lock"
      - ".github/workflows/scanner-assurance.yml"
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: scanner-assurance-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true

jobs:
  assurance:
    runs-on: ubuntu-24.04
    timeout-minutes: 35
    env:
      CARGO_TARGET_DIR: ${{ github.workspace }}/rust/scanner-engine/target
      HOL_GUARD_SCANNER_ENGINE: ${{ github.workspace }}/rust/scanner-engine/target/release/hol-guard-scanner-engine
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10
        with:
          persist-credentials: false
      - uses: actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405
        with:
          python-version: "3.12"
      - uses: astral-sh/setup-uv@fac544c07dec837d0ccb6301d7b5580bf5edae39
        with:
          version: "0.9.26"
          enable-cache: true
          cache-dependency-glob: |
            pyproject.toml
            uv.lock
            rust/scanner-engine/Cargo.lock
      - name: Install pinned Rust toolchain
        shell: bash
        run: |
          set -euo pipefail
          rustup toolchain install 1.88.0 --profile minimal --component rustfmt --component clippy --no-self-update
          rustup default 1.88.0
      - name: Install Python environment
        run: uv sync --frozen --extra dev --python 3.12
      - name: Validate Rust hot path
        shell: bash
        run: |
          set -euo pipefail
          cargo fmt --manifest-path rust/scanner-engine/Cargo.toml -- --check
          cargo clippy --locked --manifest-path rust/scanner-engine/Cargo.toml --all-targets -- -D warnings
          cargo test --locked --manifest-path rust/scanner-engine/Cargo.toml
          cargo build --release --locked --manifest-path rust/scanner-engine/Cargo.toml
      - name: Validate assurance Python
        shell: bash
        run: |
          set -euo pipefail
          python -m compileall -q src/codex_plugin_scanner/assurance src/codex_plugin_scanner/assurance_cli.py
          uv run --no-sync ruff check \
            src/codex_plugin_scanner/assurance \
            src/codex_plugin_scanner/assurance_cli.py \
            tests/test_assurance_*.py
          uv run --no-sync ruff format --check \
            src/codex_plugin_scanner/assurance \
            src/codex_plugin_scanner/assurance_cli.py \
            tests/test_assurance_*.py
          uv run --no-sync basedpyright --level error \
            src/codex_plugin_scanner/assurance \
            src/codex_plugin_scanner/assurance_cli.py
      - name: Run hostile corpus and compatibility regressions
        run: >-
          uv run --no-sync pytest
          tests/test_assurance_*.py
          tests/test_policy.py
          tests/test_schema_contracts.py
          tests/test_security_ops.py
          tests/test_verification.py
          tests/test_cli.py
          --tb=short
      - name: Build and smoke-test installed wheel
        shell: bash
        run: |
          set -euo pipefail
          uv build --wheel
          rm -rf /tmp/assurance-wheel /tmp/benign-extension
          python -m venv /tmp/assurance-wheel
          /tmp/assurance-wheel/bin/pip install --disable-pip-version-check dist/*.whl
          /tmp/assurance-wheel/bin/hol-guard-extension-security --help
          mkdir -p /tmp/benign-extension
          printf '# benign extension\n' > /tmp/benign-extension/README.md
          /tmp/assurance-wheel/bin/hol-guard-extension-security scan \
            /tmp/benign-extension --output /tmp/installed-wheel-report.json
          test -s /tmp/installed-wheel-report.json
      - name: Self-inspect assurance implementation and validate schema
        shell: bash
        run: |
          set -euo pipefail
          set +e
          uv run --no-sync hol-guard-extension-security scan \
            src/codex_plugin_scanner --profile audit \
            --output assurance-self-scan.json
          status=$?
          set -e
          test "$status" -le 3
          uv run --no-sync python - <<'PY'
          import json
          from pathlib import Path
          from jsonschema import Draft202012Validator

          payload = json.loads(Path("assurance-self-scan.json").read_text())
          schema = json.loads(Path("schemas/assurance-report.v1.json").read_text())
          Draft202012Validator.check_schema(schema)
          Draft202012Validator(schema).validate(payload)
          assert payload["coverage"]["state"] != "error"
          assert payload["coverage"]["limitations"]
          assert payload["layers"]
          assert payload["evidence_digest"]
          PY
      - name: Upload scanner self-inspection
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a
        with:
          name: scanner-assurance-self-inspection
          path: assurance-self-scan.json
          if-no-files-found: warn
          retention-days: 14
''',
    )


def main() -> None:
    patch_content_scan()
    patch_drift()
    patch_surface_scan()
    patch_policy_test()
    remove_legacy_enforcement()
    patch_pyproject()
    patch_rust_manifest()
    patch_core_schemas_minimally()
    rewrite_workflow()


if __name__ == "__main__":
    main()
