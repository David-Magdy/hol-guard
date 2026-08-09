from __future__ import annotations

import importlib.util
import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMMONS = ROOT / "canary-commons"
SOURCE = COMMONS / "corpus.v1.json"
SCHEMA = COMMONS / "schema.v1.json"
EXPORTER = COMMONS / "export.py"


def _exporter_module():
    spec = importlib.util.spec_from_file_location("canary_commons_export", EXPORTER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _cases():
    module = _exporter_module()
    return module.expand_cases(module.load_source(SOURCE))


def test_canary_commons_has_required_case_counts_and_split() -> None:
    cases = _cases()

    assert len(cases) == 100
    assert Counter(case["category"] for case in cases) == {
        "documentation": 25,
        "pr_issue": 20,
        "mcp": 20,
        "skill": 15,
        "package_install": 10,
        "memory_workspace": 10,
    }
    assert Counter(case["split"] for case in cases) == {"train": 80, "held_out": 20}
    assert len({case["id"] for case in cases}) == 100


def test_canary_commons_cases_are_synthetic_defanged_and_non_executable() -> None:
    cases = _cases()

    for case in cases:
        assert case["schema_version"] == "canary-commons/v1"
        assert case["expected_outcome"] in {"allow", "review", "block"}
        assert case["limitations"]
        assert case["benchmark_family"]
        assert case["safety"] == {
            "synthetic_only": True,
            "defanged": True,
            "contains_live_secret": False,
            "executable": False,
        }
        excerpt = case["artifact_excerpt"]
        assert "http://" not in excerpt.lower()
        assert "https://" not in excerpt.lower()
        assert "BEGIN PRIVATE KEY" not in excerpt
        assert not re.search(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", excerpt)
        assert not re.search(r"gh[pousr]_[A-Za-z0-9]{30,}", excerpt)


def test_canary_commons_source_and_schema_are_versioned_and_strict() -> None:
    source = json.loads(SOURCE.read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))

    assert source["schema_version"] == "canary-commons-source/v1"
    assert source["case_schema_version"] == "canary-commons/v1"
    assert schema["properties"]["schema_version"]["const"] == "canary-commons/v1"
    assert schema["additionalProperties"] is False
    assert schema["properties"]["safety"]["additionalProperties"] is False


def test_canary_commons_export_is_deterministic(tmp_path: Path) -> None:
    module = _exporter_module()
    cases = module.expand_cases(module.load_source(SOURCE))
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    module.write_jsonl(cases, left)
    module.write_jsonl(cases, right)

    assert left.read_bytes() == right.read_bytes()
    assert len(left.read_text(encoding="utf-8").splitlines()) == 100
