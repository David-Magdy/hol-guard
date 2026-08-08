from __future__ import annotations

import re
from pathlib import Path

WORKFLOW = Path('.github/workflows/desktop-core-alpha-feed.yml')
HELPER = Path('scripts/release/desktop_core_alpha_feed.py')
TESTS = Path('tests/test_desktop_core_alpha_feed_security.py')

workflow = WORKFLOW.read_text(encoding='utf-8')

workflow = workflow.replace(
    '  workflow_dispatch:\n\npermissions:',
    '  workflow_dispatch:\n  workflow_run:\n    workflows: ["Publish to PyPI"]\n    types: [completed]\n    branches: [release/3.0]\n\npermissions:',
    1,
)
workflow = workflow.replace(
    "    if: github.event_name != 'pull_request'\n",
    "    if: >-\n      github.event_name != 'pull_request' &&\n      (github.event_name != 'workflow_run' || github.event.workflow_run.conclusion == 'success')\n",
    1,
)
workflow = workflow.replace(
    '      - name: Require signing, notarization, and update-key configuration\n',
    '      - name: Require Apple signing and notarization configuration\n',
    1,
)
for line in (
    '          CORE_UPDATE_PRIVATE_KEY: ${{ secrets.HOL_GUARD_CORE_UPDATE_PRIVATE_KEY }}\n',
    '          CORE_UPDATE_PRIVATE_KEY_PASSWORD: ${{ secrets.HOL_GUARD_CORE_UPDATE_PRIVATE_KEY_PASSWORD }}\n',
    '          CORE_UPDATE_PUBLIC_KEY: ${{ secrets.HOL_GUARD_CORE_UPDATE_PUBLIC_KEY }}\n',
    '          test -n "$CORE_UPDATE_PRIVATE_KEY"\n',
    '          test -n "$CORE_UPDATE_PRIVATE_KEY_PASSWORD"\n',
    '          test -n "$CORE_UPDATE_PUBLIC_KEY"\n',
):
    if line not in workflow:
        raise SystemExit(f'missing obsolete key line: {line.strip()}')
    workflow = workflow.replace(line, '', 1)

workflow, count = re.subn(
    r'\n      - name: Set up Bun signer\n.*?(?=\n      - name: Fetch exact authorized Core source)',
    '',
    workflow,
    count=1,
    flags=re.S,
)
if count != 1:
    raise SystemExit('failed to remove Bun signer setup')

old_download = '''          gh release download "$CORE_TAG" --repo "$GITHUB_REPOSITORY" --pattern "$BASE" --dir "$DIST"
          gh release download "$CORE_TAG" --repo "$GITHUB_REPOSITORY" --pattern "$BASE.json" --dir "$DIST"
          gh release download "$CORE_TAG" --repo "$GITHUB_REPOSITORY" --pattern "$BASE.attested.json" --dir "$DIST"
          if [[ "$MODE" == "verify_existing" ]]; then
            gh release download "$CORE_TAG" --repo "$GITHUB_REPOSITORY" --pattern "$BASE.json.sig" --dir "$DIST"
          fi
'''
new_download = '''          gh release download "$CORE_TAG" --repo "$GITHUB_REPOSITORY" --pattern "$BASE" --dir "$DIST"
          gh release download "$CORE_TAG" --repo "$GITHUB_REPOSITORY" --pattern "$BASE.json" --dir "$DIST"
          gh release download "$CORE_TAG" --repo "$GITHUB_REPOSITORY" --pattern "$BASE.attested.json" --dir "$DIST"
'''
if old_download not in workflow:
    raise SystemExit('existing asset download block not found')
workflow = workflow.replace(old_download, new_download, 1)
workflow = workflow.replace('          MODE: ${{ steps.existing.outputs.mode }}\n', '', 1)

start = workflow.index('      - name: Verify prior feed provenance before reusing assets\n')
end = workflow.index('      - name: Build standalone Core executable\n', start)
prior = '''      - name: Verify prior feed provenance before reusing assets
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
            --apple-team-id "$APPLE_TEAM_ID"
'''
workflow = workflow[:start] + prior + workflow[end:]

sign_start = workflow.index('      - name: Sign missing update manifest\n')
sign_end = workflow.index('      - name: Create or validate immutable marker\n', sign_start)
workflow = workflow[:sign_start] + workflow[sign_end:]

marker_start = workflow.index('      - name: Create or validate immutable marker\n')
marker_end = workflow.index('      - name: Attest complete hardened Core asset set\n', marker_start)
marker = '''      - name: Create or validate immutable marker
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
          fi
'''
workflow = workflow[:marker_start] + marker + workflow[marker_end:]

workflow = workflow.replace(
    "        if: steps.release.outputs.available == 'true' && steps.existing.outputs.mode != 'verify_existing'\n",
    "        if: steps.release.outputs.available == 'true' && steps.existing.outputs.mode == 'build'\n",
    2,
)
workflow = workflow.replace(
    '            ${{ runner.temp }}/dist/hol-guard-core-${{ steps.release.outputs.version }}-${{ env.RELEASE_TARGET }}.json.sig\n',
    '',
    1,
)

pub_start = workflow.index('      - name: Publish new or repaired immutable assets\n')
pub_end = workflow.index('      - name: Verify final release assets and provenance\n', pub_start)
publish = '''      - name: Publish immutable Core assets
        if: steps.release.outputs.available == 'true' && steps.existing.outputs.mode == 'build'
        env:
          CORE_VERSION: ${{ steps.release.outputs.version }}
          CORE_TAG: ${{ steps.release.outputs.tag }}
          GH_TOKEN: ${{ github.token }}
        shell: bash
        run: |
          set -euo pipefail
          BASE="$RUNNER_TEMP/dist/hol-guard-core-${CORE_VERSION}-${RELEASE_TARGET}"
          gh release upload "$CORE_TAG" "$BASE" "$BASE.json" "$BASE.attested.json" --repo "$GITHUB_REPOSITORY"
'''
workflow = workflow[:pub_start] + publish + workflow[pub_end:]
workflow = workflow.replace('          MODE: ${{ steps.existing.outputs.mode }}\n', '', 1)
workflow = workflow.replace(
    '          for asset in "$BASE" "$BASE.json" "$BASE.json.sig" "$BASE.attested.json"; do\n',
    '          for asset in "$BASE" "$BASE.json" "$BASE.attested.json"; do\n',
    1,
)
WORKFLOW.write_text(workflow, encoding='utf-8')

HELPER.write_text('''"""Deterministic helpers for the privileged Desktop Core alpha feed workflow."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

BOOTSTRAP_SCHEMA = "guard-desktop-bootstrap.v1"
MANIFEST_SCHEMA = "hol-guard-core-update.v1"
MARKER_SCHEMA = "hol-guard-core-attestation.v3"
SUPPORTED_TRAINS = frozenset({"3.0"})
_ALPHA_TAG = re.compile(r"^alpha/v(3\\.(\\d+)\\.(\\d+)a(\\d+))$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\\n", encoding="utf-8")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _emit(key: str, value: str | bool) -> None:
    if isinstance(value, bool):
        value = "true" if value else "false"
    print(f"{key}={value}")


def discover_release(tags_file: Path) -> None:
    candidates: list[tuple[tuple[int, int, int], str, str, str]] = []
    for raw in tags_file.read_text(encoding="utf-8").splitlines():
        tag = raw.strip()
        match = _ALPHA_TAG.fullmatch(tag)
        if match is None:
            continue
        train = f"3.{match.group(2)}"
        if train not in SUPPORTED_TRAINS:
            continue
        order = (int(match.group(2)), int(match.group(3)), int(match.group(4)))
        candidates.append((order, match.group(1), tag, train))
    if not candidates:
        _emit("available", False)
        return
    _, version, tag, train = max(candidates)
    _emit("available", True)
    _emit("version", version)
    _emit("tag", tag)
    _emit("train", train)
    _emit("branch", f"release/{train}")


def inspect_assets(assets_file: Path, base: str) -> None:
    names = set(assets_file.read_text(encoding="utf-8").splitlines())
    expected = {base, f"{base}.json", f"{base}.attested.json"}
    present = expected & names
    if not present:
        _emit("mode", "build")
    elif present == expected:
        _emit("mode", "verify_existing")
    else:
        raise SystemExit(f"Refusing partial or ambiguous Core asset set: {sorted(present)}")


def verify_bootstrap(payload_file: Path, version: str, subject: str) -> None:
    payload = json.loads(payload_file.read_text(encoding="utf-8"))
    if payload.get("schema") != BOOTSTRAP_SCHEMA:
        raise SystemExit(f"{subject} does not expose the Desktop bootstrap contract")
    if payload.get("coreVersion") != version:
        raise SystemExit(f"{subject} returned the wrong version")


def _manifest_expected(binary: Path, *, version: str, source_commit: str, source_tag: str, target: str, minimum_desktop_version: str) -> dict[str, object]:
    return {"schema": MANIFEST_SCHEMA, "channel": "alpha", "version": version, "sourceCommit": source_commit, "sourceTag": source_tag, "target": target, "artifact": binary.name, "sha256": _sha256(binary), "size": binary.stat().st_size, "bootstrapSchema": BOOTSTRAP_SCHEMA, "minimumDesktopVersion": minimum_desktop_version}


def create_manifest(binary: Path, manifest: Path, **kwargs: str) -> None:
    payload = _manifest_expected(binary, **kwargs)
    payload["publishedAt"] = _utc_now()
    _write_json(manifest, payload)


def validate_manifest(binary: Path, manifest: Path, **kwargs: str) -> None:
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    for key, value in _manifest_expected(binary, **kwargs).items():
        if payload.get(key) != value:
            raise SystemExit(f"Manifest mismatch for {key}")
    if not isinstance(payload.get("publishedAt"), str) or not payload["publishedAt"]:
        raise SystemExit("Manifest is missing publishedAt")


def _marker_metadata(*, version: str, source_commit: str, source_tag: str, target: str, apple_signing_identity: str, apple_team_id: str) -> dict[str, str]:
    return {"schema": MARKER_SCHEMA, "version": version, "sourceCommit": source_commit, "sourceTag": source_tag, "target": target, "appleSigningIdentity": apple_signing_identity, "appleTeamId": apple_team_id}


def create_marker(base: Path, marker: Path, *, workflow_run: str, **kwargs: str) -> None:
    payload: dict[str, object] = _marker_metadata(**kwargs)
    payload.update({"binarySha256": _sha256(base), "manifestSha256": _sha256(Path(f"{base}.json")), "workflowRun": workflow_run, "attestedAt": _utc_now()})
    _write_json(marker, payload)


def validate_marker(base: Path, marker_path: Path, **kwargs: str) -> None:
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    for key, value in _marker_metadata(**kwargs).items():
        if marker.get(key) != value:
            if key == "schema":
                raise SystemExit(f"Unsupported marker schema: {marker.get(key)!r}")
            raise SystemExit(f"Marker mismatch for {key}")
    expected_hashes = {"binarySha256": _sha256(base), "manifestSha256": _sha256(Path(f"{base}.json"))}
    for key, value in expected_hashes.items():
        if marker.get(key) != value:
            raise SystemExit(f"Marker hash mismatch for {key}")


def _asset_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tag", required=True)
    parser.add_argument("--target", required=True)


def _marker_arguments(parser: argparse.ArgumentParser) -> None:
    _asset_arguments(parser)
    parser.add_argument("--marker", type=Path, required=True)
    parser.add_argument("--apple-signing-identity", required=True)
    parser.add_argument("--apple-team-id", required=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    discover = subparsers.add_parser("discover-release"); discover.add_argument("--tags", type=Path, required=True)
    inspect = subparsers.add_parser("inspect-assets"); inspect.add_argument("--assets", type=Path, required=True); inspect.add_argument("--base", required=True)
    bootstrap = subparsers.add_parser("verify-bootstrap"); bootstrap.add_argument("--payload", type=Path, required=True); bootstrap.add_argument("--version", required=True); bootstrap.add_argument("--subject", required=True)
    for name in ("create-manifest", "validate-manifest"):
        command = subparsers.add_parser(name); _asset_arguments(command); command.add_argument("--manifest", type=Path, required=True); command.add_argument("--minimum-desktop-version", required=True)
    create_marker_parser = subparsers.add_parser("create-marker"); _marker_arguments(create_marker_parser); create_marker_parser.add_argument("--workflow-run", required=True)
    validate_marker_parser = subparsers.add_parser("validate-marker"); _marker_arguments(validate_marker_parser)
    args = parser.parse_args()
    if args.command == "discover-release": discover_release(args.tags)
    elif args.command == "inspect-assets": inspect_assets(args.assets, args.base)
    elif args.command == "verify-bootstrap": verify_bootstrap(args.payload, args.version, args.subject)
    elif args.command in {"create-manifest", "validate-manifest"}:
        kwargs = {"version": args.version, "source_commit": args.source_commit, "source_tag": args.source_tag, "target": args.target, "minimum_desktop_version": args.minimum_desktop_version}
        (create_manifest if args.command == "create-manifest" else validate_manifest)(args.base, args.manifest, **kwargs)
    elif args.command in {"create-marker", "validate-marker"}:
        kwargs = {"version": args.version, "source_commit": args.source_commit, "source_tag": args.source_tag, "target": args.target, "apple_signing_identity": args.apple_signing_identity, "apple_team_id": args.apple_team_id}
        if args.command == "create-marker": create_marker(args.base, args.marker, workflow_run=args.workflow_run, **kwargs)
        else: validate_marker(args.base, args.marker, **kwargs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
''', encoding='utf-8')

TESTS.write_text('''"""Security contracts for the privileged Desktop Core alpha feed."""

from __future__ import annotations

import hashlib
import json
import runpy
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "desktop-core-alpha-feed.yml"
TOOL = ROOT / "scripts" / "release" / "desktop_core_alpha_feed.py"


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def workflow() -> dict[object, object]:
    value = yaml.safe_load(workflow_text())
    assert isinstance(value, dict)
    return value


def publish_job() -> dict[str, object]:
    jobs = workflow()["jobs"]
    assert isinstance(jobs, dict)
    job = jobs["publish-macos-arm64"]
    assert isinstance(job, dict)
    return job


def test_feed_is_release_3_0_only_and_wakes_after_publisher() -> None:
    text = workflow_text()
    namespace = runpy.run_path(str(TOOL))
    assert namespace["SUPPORTED_TRAINS"] == {"3.0"}
    assert 'branches: [release/3.0]' in text
    assert 'workflows: ["Publish to PyPI"]' in text
    assert "workflow_run.conclusion == 'success'" in text


def test_release_discovery_ignores_3_1(tmp_path: Path, capsys) -> None:
    tags = tmp_path / "tags.txt"
    tags.write_text("alpha/v3.0.0a26\\nalpha/v3.1.0a99\\nalpha/v3.0.0a27\\n", encoding="utf-8")
    namespace = runpy.run_path(str(TOOL))
    namespace["discover_release"](tags)
    output = capsys.readouterr().out
    assert "version=3.0.0a27" in output
    assert "tag=alpha/v3.0.0a27" in output
    assert "branch=release/3.0" in output
    assert "3.1" not in output


def test_privileged_feed_is_main_bound_and_pins_candidate_provenance() -> None:
    text = workflow_text()
    job = publish_job()
    assert job["permissions"] == {"contents": "write", "id-token": "write", "attestations": "write"}
    assert 'test "$GITHUB_REF" = "refs/heads/main"' in text
    assert 'ref: ${{ github.sha }}' in text
    assert 'persist-credentials: false' in text
    assert 'refs/tags/${CORE_TAG}^{commit}' in text
    assert 'refs/remotes/origin/${RELEASE_BRANCH}' in text
    assert 'merge-base --is-ancestor' in text
    assert '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/publish.yml"' in text
    assert '--signer-digest "$SOURCE_SHA"' in text
    assert '--source-ref "refs/heads/${RELEASE_BRANCH}"' in text


def test_feed_uses_apple_trust_and_no_redundant_manifest_key() -> None:
    text = workflow_text()
    helper = TOOL.read_text(encoding="utf-8")
    assert "HOL_GUARD_CORE_UPDATE_PRIVATE_KEY" not in text
    assert "HOL_GUARD_CORE_UPDATE_PUBLIC_KEY" not in text
    assert "json.sig" not in text
    assert "minisign" not in helper.lower()
    assert "bunx @tauri-apps/cli" not in text
    assert 'grep -Fx "Authority=$APPLE_SIGNING_IDENTITY"' in text
    assert 'grep -Fx "TeamIdentifier=$APPLE_TEAM_ID"' in text
    assert 'grep -F "source=Notarized Developer ID"' in text


def test_existing_asset_set_is_all_or_nothing(tmp_path: Path, capsys) -> None:
    namespace = runpy.run_path(str(TOOL))
    assets = tmp_path / "assets.txt"
    base = "hol-guard-core-3.0.0a27-aarch64-apple-darwin"
    assets.write_text("", encoding="utf-8")
    namespace["inspect_assets"](assets, base)
    assert "mode=build" in capsys.readouterr().out
    assets.write_text(f"{base}\\n{base}.json\\n{base}.attested.json\\n", encoding="utf-8")
    namespace["inspect_assets"](assets, base)
    assert "mode=verify_existing" in capsys.readouterr().out


def test_manifest_and_marker_bind_source_and_hashes(tmp_path: Path) -> None:
    namespace = runpy.run_path(str(TOOL))
    base = tmp_path / "core"
    manifest = Path(f"{base}.json")
    marker = Path(f"{base}.attested.json")
    base.write_bytes(b"binary")
    common = dict(version="3.0.0a27", source_commit="a" * 40, source_tag="alpha/v3.0.0a27", target="aarch64-apple-darwin", minimum_desktop_version="0.1.0-alpha.0")
    namespace["create_manifest"](base, manifest, **common)
    namespace["validate_manifest"](base, manifest, **common)
    marker_common = {key: common[key] for key in ("version", "source_commit", "source_tag", "target")}
    marker_common.update(apple_signing_identity="Developer ID Application: HOL", apple_team_id="TEAMID")
    namespace["create_marker"](base, marker, workflow_run="123", **marker_common)
    namespace["validate_marker"](base, marker, **marker_common)
    payload = json.loads(marker.read_text(encoding="utf-8"))
    assert payload["binarySha256"] == hashlib.sha256(b"binary").hexdigest()
    assert payload["manifestSha256"] == hashlib.sha256(manifest.read_bytes()).hexdigest()
    assert "signatureSha256" not in payload


def test_complete_feed_assets_are_attested_uploaded_and_reloaded() -> None:
    text = workflow_text()
    assert "Attest complete hardened Core asset set" in text
    assert "Publish immutable Core assets" in text
    assert 'gh release upload "$CORE_TAG" "$BASE" "$BASE.json" "$BASE.attested.json"' in text
    assert 'for asset in "$BASE" "$BASE.json" "$BASE.attested.json"; do' in text
    assert 'PUBLISHED="$RUNNER_TEMP/published-assets"' in text
    assert 'gh attestation verify "$PUBLISHED/$asset"' in text
''', encoding='utf-8')
