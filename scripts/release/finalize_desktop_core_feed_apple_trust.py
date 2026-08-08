from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "desktop-core-alpha-feed.yml"
HELPER = ROOT / "scripts" / "release" / "desktop_core_alpha_feed.py"
TEST = ROOT / "tests" / "test_desktop_core_alpha_feed_security.py"
SELF = Path(__file__).resolve()
TEMP_WORKFLOW = ROOT / ".github" / "workflows" / "finalize-desktop-core-feed-apple-trust.yml"


def remove_step(text: str, name: str) -> str:
    pattern = re.compile(rf"(?ms)^      - name: {re.escape(name)}\n.*?(?=^      - name: |\Z)")
    updated, count = pattern.subn("", text)
    if count != 1:
        raise SystemExit(f"expected workflow step {name!r} exactly once, found {count}")
    return updated


def replace_step(text: str, name: str, replacement: str) -> str:
    pattern = re.compile(rf"(?ms)^      - name: {re.escape(name)}\n.*?(?=^      - name: |\Z)")
    updated, count = pattern.subn(replacement.rstrip() + "\n", text)
    if count != 1:
        raise SystemExit(f"expected workflow step {name!r} exactly once, found {count}")
    return updated


def replace_function(text: str, name: str, next_name: str, replacement: str) -> str:
    pattern = re.compile(
        rf"(?ms)^def {re.escape(name)}\(.*?(?=^def {re.escape(next_name)}\()"
    )
    updated, count = pattern.subn(replacement.rstrip() + "\n\n", text)
    if count != 1:
        raise SystemExit(f"expected function {name!r} exactly once, found {count}")
    return updated


def finalize_workflow() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    text = text.replace(
        "      - name: Require signing, notarization, and update-key configuration\n",
        "      - name: Require Apple signing and notarization configuration\n",
        1,
    )
    text = "\n".join(
        line
        for line in text.splitlines()
        if "CORE_UPDATE_PRIVATE_KEY" not in line
        and "CORE_UPDATE_PUBLIC_KEY" not in line
    ) + "\n"
    text = remove_step(text, "Set up Bun signer")
    text = remove_step(text, "Sign missing update manifest")
    text = remove_step(text, "Verify update manifest signature")

    text = replace_step(
        text,
        "Download existing Core assets",
        '''      - name: Download existing Core assets
        if: steps.release.outputs.available == 'true' && steps.existing.outputs.mode == 'verify_existing'
        env:
          CORE_TAG: ${{ steps.release.outputs.tag }}
          CORE_VERSION: ${{ steps.release.outputs.version }}
          GH_TOKEN: ${{ github.token }}
        shell: bash
        run: |
          set -euo pipefail
          DIST="$RUNNER_TEMP/dist"
          BASE="hol-guard-core-${CORE_VERSION}-${RELEASE_TARGET}"
          mkdir -p "$DIST"
          for asset in "$BASE" "$BASE.json" "$BASE.attested.json"; do
            gh release download "$CORE_TAG" --repo "$GITHUB_REPOSITORY" --pattern "$asset" --dir "$DIST"
          done''',
    )
    text = replace_step(
        text,
        "Verify prior feed provenance before reusing assets",
        '''      - name: Verify prior feed provenance before reusing assets
        if: steps.release.outputs.available == 'true' && steps.existing.outputs.mode == 'verify_existing'
        env:
          CORE_VERSION: ${{ steps.release.outputs.version }}
          CORE_TAG: ${{ steps.release.outputs.tag }}
          SOURCE_SHA: ${{ steps.source.outputs.sha }}
          APPLE_SIGNING_IDENTITY: ${{ secrets.APPLE_SIGNING_IDENTITY }}
          APPLE_TEAM_ID: ${{ secrets.APPLE_TEAM_ID }}
          GH_TOKEN: ${{ github.token }}
        shell: bash
        run: |
          set -euo pipefail
          BASE="$RUNNER_TEMP/dist/hol-guard-core-${CORE_VERSION}-${RELEASE_TARGET}"
          for asset in "$BASE" "$BASE.json" "$BASE.attested.json"; do
            gh attestation verify "$asset" --repo "$GITHUB_REPOSITORY" \
              --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/desktop-core-alpha-feed.yml" \
              --source-ref refs/heads/main --deny-self-hosted-runners >/dev/null
          done
          python3 -I scripts/release/desktop_core_alpha_feed.py validate-marker \
            --base "$BASE" --marker "$BASE.attested.json" --version "$CORE_VERSION" --source-commit "$SOURCE_SHA" \
            --source-tag "$CORE_TAG" --target "$RELEASE_TARGET" --apple-signing-identity "$APPLE_SIGNING_IDENTITY" \
            --apple-team-id "$APPLE_TEAM_ID"''',
    )
    text = replace_step(
        text,
        "Create or validate immutable marker",
        '''      - name: Create or validate immutable marker
        if: steps.release.outputs.available == 'true'
        env:
          CORE_VERSION: ${{ steps.release.outputs.version }}
          CORE_TAG: ${{ steps.release.outputs.tag }}
          SOURCE_SHA: ${{ steps.source.outputs.sha }}
          MODE: ${{ steps.existing.outputs.mode }}
          APPLE_SIGNING_IDENTITY: ${{ secrets.APPLE_SIGNING_IDENTITY }}
          APPLE_TEAM_ID: ${{ secrets.APPLE_TEAM_ID }}
        shell: bash
        run: |
          set -euo pipefail
          BASE="$RUNNER_TEMP/dist/hol-guard-core-${CORE_VERSION}-${RELEASE_TARGET}"
          MARKER="$BASE.attested.json"
          COMMON=(--base "$BASE" --marker "$MARKER" --version "$CORE_VERSION" --source-commit "$SOURCE_SHA" \
            --source-tag "$CORE_TAG" --target "$RELEASE_TARGET" --apple-signing-identity "$APPLE_SIGNING_IDENTITY" \
            --apple-team-id "$APPLE_TEAM_ID")
          if [[ "$MODE" == "build" ]]; then
            python3 -I scripts/release/desktop_core_alpha_feed.py create-marker "${COMMON[@]}" --workflow-run "$GITHUB_RUN_ID"
          else
            python3 -I scripts/release/desktop_core_alpha_feed.py validate-marker "${COMMON[@]}"
          fi''',
    )
    text = replace_step(
        text,
        "Attest complete hardened Core asset set",
        '''      - name: Attest complete hardened Core asset set
        if: steps.release.outputs.available == 'true' && steps.existing.outputs.mode == 'build'
        uses: actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373
        with:
          subject-path: |
            ${{ runner.temp }}/dist/hol-guard-core-${{ steps.release.outputs.version }}-${{ env.RELEASE_TARGET }}
            ${{ runner.temp }}/dist/hol-guard-core-${{ steps.release.outputs.version }}-${{ env.RELEASE_TARGET }}.json
            ${{ runner.temp }}/dist/hol-guard-core-${{ steps.release.outputs.version }}-${{ env.RELEASE_TARGET }}.attested.json''',
    )
    text = replace_step(
        text,
        "Publish new or repaired immutable assets",
        '''      - name: Publish new immutable assets
        if: steps.release.outputs.available == 'true' && steps.existing.outputs.mode == 'build'
        env:
          CORE_VERSION: ${{ steps.release.outputs.version }}
          CORE_TAG: ${{ steps.release.outputs.tag }}
          GH_TOKEN: ${{ github.token }}
        shell: bash
        run: |
          set -euo pipefail
          BASE="$RUNNER_TEMP/dist/hol-guard-core-${CORE_VERSION}-${RELEASE_TARGET}"
          gh release upload "$CORE_TAG" "$BASE" "$BASE.json" "$BASE.attested.json" \
            --repo "$GITHUB_REPOSITORY"''',
    )
    text = replace_step(
        text,
        "Verify final release assets and provenance",
        '''      - name: Verify final release assets and provenance
        if: steps.release.outputs.available == 'true'
        env:
          CORE_VERSION: ${{ steps.release.outputs.version }}
          CORE_TAG: ${{ steps.release.outputs.tag }}
          GH_TOKEN: ${{ github.token }}
        shell: bash
        run: |
          set -euo pipefail
          BASE="hol-guard-core-${CORE_VERSION}-${RELEASE_TARGET}"
          PUBLISHED="$RUNNER_TEMP/published-assets"
          rm -rf "$PUBLISHED"
          mkdir -p "$PUBLISHED"
          gh release view "$CORE_TAG" --repo "$GITHUB_REPOSITORY" --json assets --jq '.assets[].name' \
            > "$RUNNER_TEMP/final-assets.txt"
          for asset in "$BASE" "$BASE.json" "$BASE.attested.json"; do
            grep -Fx "$asset" "$RUNNER_TEMP/final-assets.txt"
            gh release download "$CORE_TAG" --repo "$GITHUB_REPOSITORY" --pattern "$asset" --dir "$PUBLISHED"
            test -f "$PUBLISHED/$asset"
            gh attestation verify "$PUBLISHED/$asset" \
              --repo "$GITHUB_REPOSITORY" \
              --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/desktop-core-alpha-feed.yml" \
              --source-ref refs/heads/main \
              --deny-self-hosted-runners >/dev/null
          done''',
    )
    WORKFLOW.write_text(text, encoding="utf-8")


def finalize_helper() -> None:
    text = HELPER.read_text(encoding="utf-8")
    text = text.replace("import base64\nimport binascii\n", "")
    text = text.replace('MARKER_SCHEMA = "hol-guard-core-attestation.v2"', 'MARKER_SCHEMA = "hol-guard-core-attestation.v3"')
    text = text.replace('SUPPORTED_TRAINS = frozenset({"3.0"})', 'SUPPORTED_TRAINS = frozenset({"3.0", "3.1"})')
    text = re.sub(
        r"(?ms)^def _decode_minisign_line\(.*?(?=^def _sha256\()",
        "",
        text,
        count=1,
    )
    text = replace_function(
        text,
        "inspect_assets",
        "verify_bootstrap",
        '''def inspect_assets(assets_file: Path, base: str) -> None:
    names = set(assets_file.read_text(encoding="utf-8").splitlines())
    expected = {
        "binary": base,
        "manifest": f"{base}.json",
        "marker": f"{base}.attested.json",
    }
    present = {key for key, name in expected.items() if name in names}
    for key in expected:
        _emit(f"{key}_present", key in present)
    if not present:
        _emit("mode", "build")
    elif present == set(expected):
        _emit("mode", "verify_existing")
    else:
        raise SystemExit(f"Refusing partial or ambiguous Core asset set: {sorted(present)}")''',
    )
    marker_block = '''def create_marker(
    base: Path,
    marker: Path,
    *,
    version: str,
    source_commit: str,
    source_tag: str,
    target: str,
    apple_signing_identity: str,
    apple_team_id: str,
    workflow_run: str,
) -> None:
    manifest = Path(f"{base}.json")
    payload: dict[str, object] = _marker_metadata(
        version=version,
        source_commit=source_commit,
        source_tag=source_tag,
        target=target,
        apple_signing_identity=apple_signing_identity,
        apple_team_id=apple_team_id,
    )
    payload.update(
        {
            "binarySha256": _sha256(base),
            "manifestSha256": _sha256(manifest),
            "workflowRun": workflow_run,
            "attestedAt": _utc_now(),
        }
    )
    _write_json(marker, payload)


def validate_marker(
    base: Path,
    marker_path: Path,
    *,
    version: str,
    source_commit: str,
    source_tag: str,
    target: str,
    apple_signing_identity: str,
    apple_team_id: str,
) -> None:
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    expected = _marker_metadata(
        version=version,
        source_commit=source_commit,
        source_tag=source_tag,
        target=target,
        apple_signing_identity=apple_signing_identity,
        apple_team_id=apple_team_id,
    )
    for key, value in expected.items():
        if marker.get(key) != value:
            if key == "schema":
                raise SystemExit(f"Unsupported marker schema: {marker.get(key)!r}")
            raise SystemExit(f"Marker mismatch for {key}")
    hashes = {
        "binarySha256": _sha256(base),
        "manifestSha256": _sha256(Path(f"{base}.json")),
    }
    for key, value in hashes.items():
        if marker.get(key) != value:
            raise SystemExit(f"Marker hash mismatch for {key}")'''
    text = re.sub(
        r"(?ms)^def create_marker\(.*?(?=^def _asset_arguments\()",
        marker_block + "\n\n",
        text,
        count=1,
    )
    text = re.sub(
        r"(?ms)^    verify_signature = subparsers\.add_parser\(\"verify-minisign\"\)\n.*?^    for name in \(\"create-manifest\", \"validate-manifest\"\):",
        '    for name in ("create-manifest", "validate-manifest"):',
        text,
        count=1,
    )
    text = text.replace(
        '    validate_marker_parser.add_argument("--mode", choices=("repair", "complete"), required=True)\n',
        "",
    )
    text = re.sub(
        r'(?ms)^    elif args\.command == "verify-minisign":\n        verify_minisign\(args\.file, args\.signature, args\.public_key\)\n',
        "",
        text,
        count=1,
    )
    text = text.replace(
        '            validate_marker(args.base, args.marker, mode=args.mode, **marker_kwargs)',
        '            validate_marker(args.base, args.marker, **marker_kwargs)',
    )
    HELPER.write_text(text, encoding="utf-8")


def finalize_tests() -> None:
    text = TEST.read_text(encoding="utf-8")
    for line in (
        "import base64\n",
        "import subprocess\n",
        "import sys\n",
        "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey\n",
        "from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat\n",
    ):
        text = text.replace(line, "")
    text = text.replace("import yaml\n", "import pytest\nimport yaml\n")
    text = text.replace('assert namespace["SUPPORTED_TRAINS"] == {"3.0"}', 'assert namespace["SUPPORTED_TRAINS"] == {"3.0", "3.1"}')
    text = re.sub(
        r"(?ms)^def test_release_discovery_ignores_inactive_3_1_train\(.*?(?=^def test_candidate_requires_trusted_publish_workflow_attestation\()",
        '''def test_release_discovery_selects_newest_supported_3x_train(tmp_path: Path, capsys) -> None:
    tags = tmp_path / "tags.txt"
    tags.write_text(
        "alpha/v3.0.0a8\\nalpha/v3.1.0a10\\nalpha/v3.0.0a9\\n",
        encoding="utf-8",
    )
    namespace = runpy.run_path(str(TOOL))
    namespace["discover_release"](tags)
    output = capsys.readouterr().out
    assert "available=true" in output
    assert "version=3.1.0a10" in output
    assert "tag=alpha/v3.1.0a10" in output
    assert "train=3.1" in output
    assert "branch=release/3.1" in output


''',
        text,
        count=1,
    )
    text = re.sub(
        r"(?ms)^def test_existing_assets_are_all_or_nothing_except_safe_signature_repair\(.*?(?=^def test_reused_binary_requires_prior_feed_provenance\()",
        '''def test_existing_assets_are_all_or_nothing() -> None:
    text = workflow_text()
    tool = TOOL.read_text(encoding="utf-8")
    assert "inspect-assets" in text
    assert 'present == set(expected)' in tool
    assert '"signature"' not in tool.split("def inspect_assets", 1)[1].split("def verify_bootstrap", 1)[0]
    assert "repair_signature" not in text
    assert "Refusing partial or ambiguous Core asset set" in tool


''',
        text,
        count=1,
    )
    text = re.sub(
        r"(?ms)^def test_reused_binary_requires_prior_feed_provenance\(.*?(?=^def test_apple_verification_pins_identity_team_and_notarized_gatekeeper_source\()",
        '''def test_reused_binary_requires_prior_feed_provenance() -> None:
    text = workflow_text()
    assert "Verify prior feed provenance before reusing assets" in text
    assert '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/desktop-core-alpha-feed.yml"' in text
    assert "--source-ref refs/heads/main" in text
    assert 'for asset in "$BASE" "$BASE.json" "$BASE.attested.json"; do' in text
    assert 'gh attestation verify "$asset"' in text


''',
        text,
        count=1,
    )
    text = re.sub(
        r"(?ms)^def test_manifest_signature_is_required_and_uses_independent_update_key\(.*?(?=^def test_complete_hardened_asset_set_is_attested_together\()",
        "",
        text,
        count=1,
    )
    text = re.sub(
        r"(?ms)^def test_complete_hardened_asset_set_is_attested_together\(.*?(?=^def test_final_verification_reloads_published_asset_bytes\()",
        '''def test_complete_apple_trusted_asset_set_is_attested_together() -> None:
    text = workflow_text()
    assert "Attest complete hardened Core asset set" in text
    assert "${{ env.RELEASE_TARGET }}.attested.json" in text
    assert "${{ env.RELEASE_TARGET }}.json.sig" not in text
    assert 'gh release upload "$CORE_TAG" "$BASE" "$BASE.json" "$BASE.attested.json"' in text


''',
        text,
        count=1,
    )
    text = re.sub(
        r"(?ms)^def test_manifest_and_marker_bind_exact_authorized_source_and_hashes\(.*?(?=^def test_privileged_inline_python_is_isolated_from_workspace_import_shadowing\()",
        '''def test_manifest_and_marker_bind_exact_authorized_source_and_hashes(tmp_path: Path) -> None:
    tool = TOOL.read_text(encoding="utf-8")
    namespace = runpy.run_path(str(TOOL))
    assert 'MARKER_SCHEMA = "hol-guard-core-attestation.v3"' in tool
    assert "signatureSha256" not in tool

    base = tmp_path / "core"
    manifest = Path(f"{base}.json")
    marker = Path(f"{base}.attested.json")
    base.write_bytes(b"binary")
    manifest.write_bytes(b"manifest")
    common = {
        "version": "3.1.0a1",
        "source_commit": "a" * 40,
        "source_tag": "alpha/v3.1.0a1",
        "target": "aarch64-apple-darwin",
        "apple_signing_identity": "Developer ID Application: HOL",
        "apple_team_id": "TEAMID",
    }
    namespace["create_marker"](base, marker, workflow_run="123456", **common)
    payload = json.loads(marker.read_text(encoding="utf-8"))
    assert payload["schema"] == "hol-guard-core-attestation.v3"
    assert set(payload) >= {"binarySha256", "manifestSha256", "workflowRun", "attestedAt"}
    assert "signatureSha256" not in payload
    namespace["validate_marker"](base, marker, **common)

    payload["binarySha256"] = "c" * 64
    marker.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SystemExit, match="Marker hash mismatch for binarySha256"):
        namespace["validate_marker"](base, marker, **common)


''',
        text,
        count=1,
    )
    TEST.write_text(text, encoding="utf-8")


def main() -> None:
    finalize_workflow()
    finalize_helper()
    finalize_tests()
    for path in (SELF, TEMP_WORKFLOW):
        if path.exists():
            path.unlink()


if __name__ == "__main__":
    main()
