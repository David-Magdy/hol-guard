#!/usr/bin/env python3
"""Expand the compact Canary Commons source corpus into case JSONL."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
DEFAULT_SOURCE = ROOT / "corpus.v1.json"
DEFAULT_OUTPUT = ROOT / "cases.v1.jsonl"

LIMITATIONS = [
    "Synthetic and defanged; not evidence of real-world exploitability.",
    "Expected outcome applies only to this excerpt and test policy.",
]
SAFETY = {
    "synthetic_only": True,
    "defanged": True,
    "contains_live_secret": False,
    "executable": False,
}


def load_source(path: Path = DEFAULT_SOURCE) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Canary Commons source must be a JSON object")
    return value


def expand_cases(source: dict[str, Any]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    categories = source.get("categories")
    if not isinstance(categories, list):
        raise ValueError("categories must be an array")
    for spec in categories:
        if not isinstance(spec, dict):
            raise ValueError("category spec must be an object")
        count = int(spec["count"])
        held_out_count = int(spec["held_out_count"])
        templates = spec["templates"]
        if not isinstance(templates, list) or not templates:
            raise ValueError("category templates must be a non-empty array")
        train_count = count - held_out_count
        for offset in range(count):
            template = templates[offset % len(templates)]
            if not isinstance(template, dict):
                raise ValueError("template must be an object")
            case_id = f"CC-{spec['id_prefix']}-{offset + 1:03d}"
            cases.append(
                {
                    "schema_version": source["case_schema_version"],
                    "id": case_id,
                    "category": spec["category"],
                    "split": "train" if offset < train_count else "held_out",
                    "title": f"{template['title']} #{offset + 1}",
                    "artifact_excerpt": f"{template['artifact_excerpt']} Synthetic case marker: {case_id}.",
                    "expected_outcome": template["expected_outcome"],
                    "reason_code": template["reason_code"],
                    "benchmark_family": spec["benchmark_family"],
                    "limitations": LIMITATIONS,
                    "safety": SAFETY,
                }
            )
    return cases


def write_jsonl(cases: list[dict[str, Any]], path: Path) -> None:
    path.write_text(
        "".join(json.dumps(case, sort_keys=True, separators=(",", ":")) + "\n" for case in cases),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    cases = expand_cases(load_source(args.source))
    write_jsonl(cases, args.output)
    print(f"Wrote {len(cases)} Canary Commons cases to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
