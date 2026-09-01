#!/usr/bin/env python3
"""Measure installed adapter-to-decision native runtime SLOs.

Synthetic requests cross the daemon adapter boundary; output is aggregate-only.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path
from typing import cast

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.append(str(_REPO_ROOT))

import codex_plugin_scanner  # noqa: E402

_PROBE_SPEC = importlib.util.spec_from_file_location(
    "hol_guard_installed_default_probe",
    _REPO_ROOT / "ci/native_runtime/probe_native_default_auto.py",
)
if _PROBE_SPEC is None or _PROBE_SPEC.loader is None:
    raise RuntimeError("native_installed_slo_failed: installed hook probe could not be loaded")
_PROBE_MODULE = importlib.util.module_from_spec(_PROBE_SPEC)
_PROBE_SPEC.loader.exec_module(_PROBE_MODULE)
_installed_hook_corpus = _PROBE_MODULE._installed_hook_corpus
from codex_plugin_scanner.guard.config import hook_fast_path_enabled  # noqa: E402
from codex_plugin_scanner.guard.native_runtime import native_mode, native_runtime_status  # noqa: E402
from codex_plugin_scanner.guard.native_runtime_resident import close_resident_native_runtimes  # noqa: E402
from scripts.native_slo_adapter import (  # noqa: E402
    Observation,
    payload,
    process_rss_bytes,
    route_matrix,
    source_payloads,
)
from scripts.native_slo_contract import (  # noqa: E402
    MAX_COLD_P95_MS,
    MAX_CONCURRENT_P99_MS,
    SAFE_ROUTE_NAMES,
    SIZE_CLASSES,
    SLO_SCHEMA,
    all_gates_pass,
    assert_privacy_safe,
    clear_proof_environment,
    gate_results,
    proof_environment_violations,
    summarize,
)
from scripts.native_slo_session import AdapterSession  # noqa: E402

_DEFAULT_WARM_ITERATIONS = 2
_DEFAULT_COLD_ITERATIONS = 3
_DEFAULT_RECOVERY_ITERATIONS = 3
_MAX_READINESS_SAMPLES = 8
_MAX_CONCURRENCY = 64


def _require(condition: bool, reason: object) -> None:
    if not condition:
        raise RuntimeError(f"native_installed_slo_failed: {reason}")


def _clear_proof_overrides() -> None:
    """Run the proof with product defaults, without test/oracle overrides."""

    _ = clear_proof_environment()
    _require(not proof_environment_violations(), "native/test override remained in proof environment")


def _installed_corpus(runtime: Path, expected_routes: int) -> dict[str, int]:
    """Exercise the canonical all-harness installed ingress corpus."""

    with tempfile.TemporaryDirectory(prefix="hol-guard-installed-corpus-") as temporary:
        root = Path(temporary)
        report: Mapping[str, object] | None = None
        try:
            candidate = _installed_hook_corpus(root)
            if isinstance(candidate, Mapping):
                report = candidate
        finally:
            close_resident_native_runtimes()
            with suppress(OSError, subprocess.TimeoutExpired):
                _ = subprocess.run(
                    (str(runtime), "resident-stop", "--state-dir", str(root / "hook-home" / "native-runtime")),
                    check=False,
                    capture_output=True,
                    timeout=2,
                )
        if report is None:
            raise RuntimeError("native_installed_slo_failed: installed all-harness corpus returned no aggregate")
        values_by_name: dict[str, object] = {}
        for name in (
            "route_count",
            "native_resident_decisions",
            "native_oneshot_decisions",
            "fail_safe_decisions",
            "python_semantic_decisions",
        ):
            if name not in report:
                raise RuntimeError(f"native_installed_slo_failed: installed corpus omitted {name}")
            values_by_name[name] = report[name]
        route_count = values_by_name["route_count"]
        resident = values_by_name["native_resident_decisions"]
        oneshot = values_by_name["native_oneshot_decisions"]
        fail_safe = values_by_name["fail_safe_decisions"]
        python_semantic = values_by_name["python_semantic_decisions"]
        values = (route_count, resident, oneshot, fail_safe, python_semantic)
        if not all(isinstance(value, int) and not isinstance(value, bool) and value >= 0 for value in values):
            raise RuntimeError("native_installed_slo_failed: installed corpus aggregate was invalid")
        route_count = cast(int, route_count)
        resident = cast(int, resident)
        oneshot = cast(int, oneshot)
        fail_safe = cast(int, fail_safe)
        python_semantic = cast(int, python_semantic)
        _require(route_count == expected_routes, "installed corpus did not cover every declared route")
        _require(resident == expected_routes, "installed corpus did not stay resident")
        _require(oneshot == 0 and fail_safe == 0 and python_semantic == 0, "installed corpus left the native route")
        return {
            "routes": route_count,
            "resident": resident,
            "oneshot": oneshot,
            "fail_safe": fail_safe,
            "python_semantic": python_semantic,
            "python_semantic_decisions": python_semantic,
        }


def _run_warm(session: AdapterSession, routes: tuple[tuple[str, str], ...], iterations: int) -> list[Observation]:
    for harness, event in routes:
        session.observe(harness, event, "1k")
    observations: list[Observation] = []
    for _ in range(iterations):
        observations.extend(session.observe(harness, event, "1k") for harness, event in routes)
    return observations


def _run_sizes(session: AdapterSession, routes: tuple[tuple[str, str], ...]) -> list[Observation]:
    post_routes = tuple((harness, event) for harness, event in routes if event == "PostToolUse")
    selected = post_routes or (routes[0],)
    large_payloads = source_payloads(session.workspace)
    observations: list[Observation] = []
    for size_class in SIZE_CLASSES[1:]:
        request_payload = large_payloads[size_class]
        observations.extend(session.observe(harness, event, size_class, request_payload) for harness, event in selected)
    return observations


def _wire_request(workspace: Path, guard_home: Path, request_id: str) -> str:
    return json.dumps(
        {
            "protocol_version": 1,
            "request_id": request_id,
            "harness": "claude-code",
            "event_name": "PostToolUse",
            "payload": payload("PostToolUse", "1k"),
            "guard_remaining_ms": 1_000,
            "cwd": str(workspace),
            "home_dir": str(workspace),
            "guard_home": str(guard_home),
            "source_ref_external_allowed": False,
            "observe_mode": False,
            "deadline_budget_ms": 5_000,
        },
        separators=(",", ":"),
    )


def _run_cold(runtime: Path, session: AdapterSession, iterations: int) -> list[float]:
    values: list[float] = []
    environment = {
        "HOME": str(session.workspace),
        "TMPDIR": tempfile.gettempdir(),
        **{key: value for key in ("LANG", "LC_ALL") if (value := os.environ.get(key))},
    }
    request = _wire_request(session.workspace, session.guard_home, "native-slo-cold")
    for _ in range(iterations):
        close_resident_native_runtimes()
        started = time.perf_counter()
        completed = subprocess.run(
            (str(runtime), "hook", "--stdin"),
            input=request.encode("utf-8"),
            cwd=runtime.parent,
            env=environment,
            capture_output=True,
            check=False,
            timeout=5,
        )
        elapsed_ms = (time.perf_counter() - started) * 1_000.0
        _require(completed.returncode == 0, "cold native one-shot failed")
        try:
            response = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("cold native one-shot returned invalid JSON") from error
        _require(isinstance(response, Mapping) and response.get("decision") == "allow", "cold decision was unsafe")
        values.append(elapsed_ms)
    return values


def _run_recovery(session: AdapterSession, iterations: int) -> list[float]:
    values: list[float] = []
    for index in range(iterations):
        _ = session.observe("claude-code", "PostToolUse", "1k")
        close_resident_native_runtimes()
        stopped = subprocess.run(
            (
                str(session.runtime),
                "resident-stop",
                "--state-dir",
                str(session.guard_home / "native-runtime"),
            ),
            capture_output=True,
            check=False,
            timeout=2,
        )
        _require(stopped.returncode == 0, f"resident stop failed during recovery sample {index}")
        started = time.perf_counter()
        observation = session.observe("claude-code", "PostToolUse", "1k")
        values.append((time.perf_counter() - started) * 1_000.0)
        _require(observation.allowed and observation.route == "native_resident", f"recovery sample {index} failed")
    return values


def _run_concurrent(
    session: AdapterSession,
    routes: tuple[tuple[str, str], ...],
    concurrency: int,
) -> tuple[list[Observation], int]:
    selected = tuple(routes[index % len(routes)] for index in range(concurrency))

    observations: list[Observation] = []
    errors = 0
    _require(0 < concurrency <= _MAX_CONCURRENCY, "concurrency exceeds bounded benchmark limit")
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(session.observe, harness, event, "1k") for harness, event in selected]
        for future in futures:
            try:
                observations.append(future.result(timeout=5))
            except Exception:
                errors += 1
    return observations, errors


def _readiness_samples(runtime: Path, count: int) -> list[float]:
    values: list[float] = []
    for _ in range(count):
        with AdapterSession(runtime) as session:
            values.append(session.readiness_ms)
    return values


def _runtime_summary(runtime: Path) -> dict[str, object]:
    status = native_runtime_status()
    _require(native_mode() == "auto", "native runtime is not using the default auto mode")
    _require(status.available and status.compatible, "native runtime unavailable")
    _require(status.reason == "native_ready", "native runtime is not ready")
    identity = status.identity
    if identity is None:
        raise RuntimeError("native_installed_slo_failed: native runtime identity unavailable")
    _require(runtime.resolve() == identity.path.resolve(), "benchmark runtime is not the bundled default runtime")
    capabilities = status.capabilities
    if capabilities is None:
        raise RuntimeError("native_installed_slo_failed: native capabilities unavailable")
    package_path = Path(codex_plugin_scanner.__file__).resolve()
    source_package = (_REPO_ROOT / "src" / "codex_plugin_scanner").resolve()
    package_origin = "source_tree" if package_path.is_relative_to(source_package) else "installed"
    _require(package_origin == "installed", "benchmark imported the source tree")
    _require(hook_fast_path_enabled(), "native hook fast path is disabled")
    return {
        "mode": status.mode,
        "target": capabilities.target,
        "runtime_version": capabilities.runtime_version,
        "protocol_version": capabilities.protocol_version,
        "package_origin": package_origin,
    }


def run_slo(
    runtime: Path,
    *,
    warm_iterations: int,
    cold_iterations: int,
    recovery_iterations: int,
    readiness_samples: int,
    include_capacity: bool,
) -> dict[str, object]:
    _clear_proof_overrides()
    runtime_summary = _runtime_summary(runtime)
    routes = route_matrix()
    installed_corpus = _installed_corpus(runtime, len(routes))
    rss_baseline = 0
    rss_peak = 0
    with AdapterSession(runtime) as session:
        warm = _run_warm(session, routes, warm_iterations)
        sizes = _run_sizes(session, routes)
        recovery = _run_recovery(session, recovery_iterations)
        cold = _run_cold(runtime, session, cold_iterations)
        # Establish the current RSS baseline after fixture setup and cold
        # recovery. Growth below therefore measures sustained concurrent load,
        # not one-time interpreter or fixture allocation.
        rss_baseline = process_rss_bytes()
        rss_peak = rss_baseline
        concurrent_16, errors_16 = _run_concurrent(session, routes, 16) if include_capacity else ([], 0)
        concurrent_64, errors_64 = _run_concurrent(session, routes, 64) if include_capacity else ([], 0)
        rss_peak = max(rss_peak, process_rss_bytes())
        readiness = [session.readiness_ms]
    if readiness_samples > 1:
        readiness.extend(_readiness_samples(runtime, readiness_samples - 1))
    rss_peak = max(rss_peak, process_rss_bytes())

    all_observations = warm + sizes + concurrent_16 + concurrent_64
    route_counts = Counter(observation.route for observation in all_observations)
    _require(
        not (set(route_counts) - SAFE_ROUTE_NAMES),
        {"unexpected_routes": sorted(set(route_counts) - SAFE_ROUTE_NAMES)},
    )
    warm_failures = sum(not observation.allowed for observation in warm)
    warm_fail_safe = sum(observation.route == "native_fail_safe" for observation in warm)
    safe_failures_by_size = Counter(
        observation.size_class for observation in all_observations if not observation.allowed
    )
    size_values = {
        size_class: [observation.latency_ms for observation in all_observations if observation.size_class == size_class]
        for size_class in SIZE_CLASSES
    }
    warm_values = [observation.latency_ms for observation in warm]
    concurrent_values = [observation.latency_ms for observation in concurrent_16]
    size_p95 = {size_class: summarize(values)["p95_ms"] for size_class, values in size_values.items() if values}
    event_values = {
        event: [observation.latency_ms for observation in warm if observation.event == event]
        for event in ("PreToolUse", "PostToolUse")
    }
    warm_routes = Counter(observation.route for observation in warm)
    rss_growth = round(max(0, rss_peak - rss_baseline) / rss_baseline, 6) if rss_baseline else 1.0
    gates = gate_results(
        resident_share=warm_routes["native_resident"] / max(1, len(warm)),
        safe_fail_rate=warm_fail_safe / max(1, len(warm)),
        warm_p95_ms=summarize(warm_values)["p95_ms"],
        size_p95_ms=size_p95,
        cold_p95_ms=summarize(cold)["p95_ms"],
        readiness_p95_ms=summarize(readiness)["p95_ms"],
        concurrent_p99_ms=summarize(concurrent_values)["p99_ms"] if concurrent_values else float("inf"),
        rss_growth=rss_growth,
        rss_baseline_bytes=rss_baseline,
        errors=errors_16,
        errors_64=errors_64,
        python_fallback_decisions=route_counts["python_semantic"],
        installed_python_fallback_decisions=installed_corpus["python_semantic_decisions"],
    )
    gates["recovery_latency"] = summarize(recovery)["p95_ms"] <= MAX_COLD_P95_MS
    concurrent_64_summary = summarize([item.latency_ms for item in concurrent_64])
    gates["concurrency_64_latency"] = (
        include_capacity and concurrent_64_summary["p99_ms"] <= MAX_CONCURRENT_P99_MS
    )
    gates["installed_corpus"] = (
        installed_corpus["routes"] == len(routes)
        and installed_corpus["resident"] == len(routes)
        and installed_corpus["oneshot"] == 0
        and installed_corpus["fail_safe"] == 0
        and installed_corpus["python_semantic_decisions"] == 0
    )
    if not include_capacity:
        gates["concurrency"] = False
        gates["concurrency_64_latency"] = False
    result: dict[str, object] = {
        "schema": SLO_SCHEMA,
        "scope": "installed_adapter_to_decision",
        "runtime": runtime_summary,
        "corpus": {
            "harnesses": len({harness for harness, _ in routes}),
            "routes": len(routes),
            "observations": len(all_observations),
            "corpus_origin": "installed_wheel_ownership_contract",
            "route_corpus": "installed_routes",
            "safe_failures": warm_failures,
            "safe_failure_rate": round(warm_failures / max(1, len(warm)), 6),
            "fail_safe_decisions": warm_fail_safe,
            "fail_safe_rate": round(warm_fail_safe / max(1, len(warm)), 6),
            "resident_share": round(warm_routes["native_resident"] / max(1, len(warm)), 6),
            "python_fallback_decisions": warm_routes["python_semantic"],
            "python_semantic_decisions": route_counts["python_semantic"],
            "oneshot_decisions": warm_routes["native_oneshot"],
            "safe_failures_by_size": dict(sorted(safe_failures_by_size.items())),
            "rss_baseline_bytes": rss_baseline,
            "rss_peak_bytes": rss_peak,
            "rss_growth": rss_growth,
            "installed": installed_corpus,
        },
        "routes": dict(sorted(route_counts.items())),
        "python_semantic_decisions": route_counts["python_semantic"],
        "errors_16": errors_16,
        "errors_64": errors_64,
        "latency": {
            "warm_all_harnesses": summarize(warm_values),
            "warm_by_event": {event: summarize(values) for event, values in event_values.items() if values},
            "size_classes": {size_class: summarize(values) for size_class, values in size_values.items()},
            "cold_native_oneshot": summarize(cold),
            "resident_recovery": summarize(recovery),
            "readiness": summarize(readiness),
        },
        "concurrency": {
            "sixteen": {"latency": summarize(concurrent_values), "errors": errors_16},
            "sixty_four": {
                "latency": concurrent_64_summary,
                "errors": errors_64,
                "fail_safe": sum(item.route == "native_fail_safe" for item in concurrent_64),
            },
        },
        "gates": gates,
        "passed": all_gates_pass(gates),
    }
    return assert_privacy_safe(result)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--warm-iterations", type=int, default=_DEFAULT_WARM_ITERATIONS)
    parser.add_argument("--cold-iterations", type=int, default=_DEFAULT_COLD_ITERATIONS)
    parser.add_argument("--recovery-iterations", type=int, default=_DEFAULT_RECOVERY_ITERATIONS)
    parser.add_argument("--readiness-samples", type=int, default=3)
    parser.add_argument("--skip-capacity", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if args.warm_iterations <= 0 or args.cold_iterations <= 0 or args.recovery_iterations <= 0:
        parser.error("iteration counts must be positive")
    if not 1 <= args.readiness_samples <= _MAX_READINESS_SAMPLES:
        parser.error("readiness samples must be between one and eight")
    runtime = args.runtime.expanduser().resolve(strict=True)
    _require(runtime.is_file() and not args.runtime.is_symlink(), "runtime must be a regular non-symlink file")
    result = run_slo(
        runtime,
        warm_iterations=args.warm_iterations,
        cold_iterations=args.cold_iterations,
        recovery_iterations=args.recovery_iterations,
        readiness_samples=args.readiness_samples,
        include_capacity=not args.skip_capacity,
    )
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.json is not None:
        args.json.write_text(rendered + "\n", encoding="utf-8")
    return 0 if not args.enforce or result.get("passed") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
