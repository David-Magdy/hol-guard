from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BATCH_DIRECTORY = ROOT / "docs" / "guard" / "managed-controls" / "batches"
REQUIRED_CAPABILITIES = {
    "extension-catalog.v1",
    "extension-control-layer.v1",
    "policy-extension-targets.v1",
    "managed-controls-atomic-apply.v1",
}


def main() -> int:
    manifests = []
    for path in sorted(BATCH_DIRECTORY.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("target_branch") != "release/3.0":
            raise SystemExit(f"invalid target branch in {path}")
        if not payload.get("evidence"):
            raise SystemExit(f"missing evidence in {path}")
        for evidence in payload["evidence"]:
            if not (ROOT / evidence).exists():
                raise SystemExit(f"missing evidence path: {evidence}")
        manifests.append(payload)
    expected_batches = set(range(3, 18))
    actual_batches = {item["batch"] for item in manifests}
    if actual_batches != expected_batches:
        raise SystemExit(
            f"managed controls Local batches incomplete: {sorted(actual_batches)}"
        )
    capability_source = (
        ROOT
        / "src"
        / "codex_plugin_scanner"
        / "guard"
        / "managed_controls"
        / "capabilities.py"
    ).read_text(encoding="utf-8")
    missing = sorted(
        capability for capability in REQUIRED_CAPABILITIES if capability not in capability_source
    )
    if missing:
        raise SystemExit(f"missing managed controls capabilities: {missing}")
    print("Managed Controls Local release gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
