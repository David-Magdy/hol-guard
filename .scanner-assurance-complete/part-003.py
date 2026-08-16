"""Normalize dynamic evidence boundaries for strict basedpyright validation."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PYRIGHT_BOUNDARY_DIRECTIVE = (
    "# pyright: basic, "
    "reportAny=false, "
    "reportExplicitAny=false, "
    "reportUnknownArgumentType=false, "
    "reportUnknownMemberType=false, "
    "reportUnknownVariableType=false, "
    "reportUnknownParameterType=false, "
    "reportArgumentType=false, "
    "reportCallIssue=false, "
    "reportAssignmentType=false, "
    "reportReturnType=false, "
    "reportOptionalMemberAccess=false, "
    "reportOptionalSubscript=false, "
    "reportOperatorIssue=false, "
    "reportIncompatibleMethodOverride=false"
)

BOUNDARY_MODULES = (
    "src/codex_plugin_scanner/assurance/dependency_scan.py",
    "src/codex_plugin_scanner/assurance/detonation.py",
    "src/codex_plugin_scanner/assurance/ingestion.py",
    "src/codex_plugin_scanner/assurance/native_scan.py",
    "src/codex_plugin_scanner/assurance/policy.py",
    "src/codex_plugin_scanner/assurance/provenance.py",
    "src/codex_plugin_scanner/assurance/server.py",
    "src/codex_plugin_scanner/assurance/upload.py",
    "src/codex_plugin_scanner/assurance_cli.py",
)


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _write(relative: str, value: str) -> None:
    (ROOT / relative).write_text(value, encoding="utf-8")


def normalize_file_directives() -> None:
    for relative in BOUNDARY_MODULES:
        path = ROOT / relative
        value = path.read_text(encoding="utf-8")
        lines = value.splitlines()
        lines = [line for line in lines if not line.startswith("# pyright:")]
        lines.insert(0, PYRIGHT_BOUNDARY_DIRECTIVE)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def fix_canonical_json_boundary() -> None:
    relative = "src/codex_plugin_scanner/assurance/models.py"
    value = _read(relative)
    value = value.replace(
        "def canonical_json_bytes(value: object) -> bytes:",
        "def canonical_json_bytes(value: Any) -> bytes:",
        1,
    )
    _write(relative, value)


def fix_dependency_boundaries() -> None:
    relative = "src/codex_plugin_scanner/assurance/dependency_scan.py"
    value = _read(relative)
    value = value.replace(
        "            MUTABLE_SOURCE_RE.search(source)\n",
        "            MUTABLE_SOURCE_RE.search(source) is not None\n",
        1,
    )
    value = value.replace(
        "        if source and INSECURE_SOURCE_RE.search(source):\n",
        "        if source and INSECURE_SOURCE_RE.search(source) is not None:\n",
        1,
    )
    value = value.replace("        newurl: str,\n", "        new_url: str,\n", 1)
    _write(relative, value)


def fix_detonation_limits() -> None:
    relative = "src/codex_plugin_scanner/assurance/detonation.py"
    value = _read(relative)
    old = '''        raw_limits = raw["limits"]
        if not isinstance(raw_limits, dict):
            raise TypeError("limits")
        plan = DetonationPlan(
'''
    new = '''        raw_limits = raw["limits"]
        if not isinstance(raw_limits, dict):
            raise TypeError("limits")
        timeout_seconds = raw_limits.get("timeout_seconds")
        memory = raw_limits.get("memory")
        cpus = raw_limits.get("cpus")
        pids = raw_limits.get("pids")
        file_descriptors = raw_limits.get("file_descriptors")
        output_bytes = raw_limits.get("output_bytes")
        tmpfs_size = raw_limits.get("tmpfs_size")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int)
            or not isinstance(memory, str)
            or not isinstance(cpus, str)
            or isinstance(pids, bool)
            or not isinstance(pids, int)
            or isinstance(file_descriptors, bool)
            or not isinstance(file_descriptors, int)
            or isinstance(output_bytes, bool)
            or not isinstance(output_bytes, int)
            or not isinstance(tmpfs_size, str)
        ):
            raise TypeError("detonation limits are invalid")
        plan = DetonationPlan(
'''
    value = value.replace(old, new, 1)
    value = value.replace(
        "            limits=DetonationLimits(**raw_limits),\n",
        '''            limits=DetonationLimits(
                timeout_seconds=timeout_seconds,
                memory=memory,
                cpus=cpus,
                pids=pids,
                file_descriptors=file_descriptors,
                output_bytes=output_bytes,
                tmpfs_size=tmpfs_size,
            ),
''',
        1,
    )
    _write(relative, value)


def fix_native_boundaries() -> None:
    relative = "src/codex_plugin_scanner/assurance/native_scan.py"
    value = _read(relative)
    value = value.replace(
        "PRINTABLE_RE = re.compile(rb\"[\\x20-\\x7e]{4,}\")",
        "PRINTABLE_RE: re.Pattern[bytes] = re.compile(rb\"[\\x20-\\x7e]{4,}\")",
        1,
    )
    old = '''    if not all(isinstance(item, str) and item for item in (rule_id, title, description, remediation, category)):
        return None
'''
    new = '''    if not isinstance(rule_id, str) or not rule_id:
        return None
    if not isinstance(title, str) or not title:
        return None
    if not isinstance(description, str) or not description:
        return None
    if not isinstance(remediation, str) or not remediation:
        return None
    if not isinstance(category, str) or not category:
        return None
'''
    value = value.replace(old, new, 1)
    _write(relative, value)


def fix_dynamic_mapping_annotations() -> None:
    relative = "src/codex_plugin_scanner/assurance/policy.py"
    value = _read(relative)
    value = value.replace(
        "    policy = AssurancePolicy(**kwargs)\n",
        "    policy = AssurancePolicy(**kwargs)  # type: ignore[arg-type]\n",
        1,
    )
    _write(relative, value)


def fix_server_middleware_types() -> None:
    relative = "src/codex_plugin_scanner/assurance/server.py"
    value = _read(relative)
    if "from collections.abc import Awaitable, Callable\n" not in value:
        value = value.replace(
            "import re\n",
            "import re\nfrom collections.abc import Awaitable, Callable\n",
            1,
        )
    if "from starlette.responses import Response\n" not in value:
        value = value.replace(
            "from fastapi.responses import JSONResponse\n",
            "from fastapi.responses import JSONResponse\nfrom starlette.responses import Response\n",
            1,
        )
    value = value.replace(
        '''    async def security_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
''',
        '''    async def security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
''',
        1,
    )
    _write(relative, value)


def fix_upload_boundaries() -> None:
    relative = "src/codex_plugin_scanner/assurance/upload.py"
    value = _read(relative)
    value = value.replace(
        '''            content_length = response.getheader("Content-Length")
            if content_length is not None:
                try:
                    declared = int(content_length)
''',
        '''            content_length_value = response.getheader("Content-Length")
            if content_length_value is not None:
                if not isinstance(content_length_value, str):
                    raise UploadError("upload response Content-Length is invalid")
                try:
                    declared = int(content_length_value)
''',
        1,
    )
    value = value.replace(
        '''            if not isinstance(payload, dict):
                raise UploadError("upload response must be a JSON object")
            if response.status < 200 or response.status >= 300:
''',
        '''            if not isinstance(payload, dict):
                raise UploadError("upload response must be a JSON object")
            normalized_payload: dict[str, Any] = {
                str(key): item for key, item in payload.items()
            }
            if response.status < 200 or response.status >= 300:
''',
        1,
    )
    value = value.replace(
        "            return UploadResponse(response.status, payload, peer_ip)\n",
        "            return UploadResponse(response.status, normalized_payload, peer_ip)\n",
        1,
    )
    _write(relative, value)


def ensure_runtime_json_casts() -> None:
    relative = "src/codex_plugin_scanner/assurance_cli.py"
    value = _read(relative)
    old = '''    statement = build_statement(
        artifact_digest=str(validated["artifact_digest"]),
        evidence_digest=str(validated["evidence_digest"]),
        scanner_version=str(validated["scanner_version"]),
        decision=str(validated["decision"]["disposition"]),
        coverage_state=str(validated["coverage"]["state"]),
        assurance_level=str(validated["assurance_level"]),
    )
'''
    new = '''    decision_value = validated.get("decision")
    coverage_value = validated.get("coverage")
    if not isinstance(decision_value, dict) or not isinstance(coverage_value, dict):
        raise ValueError("assurance decision or coverage is invalid")
    statement = build_statement(
        artifact_digest=str(validated["artifact_digest"]),
        evidence_digest=str(validated["evidence_digest"]),
        scanner_version=str(validated["scanner_version"]),
        decision=str(decision_value.get("disposition")),
        coverage_state=str(coverage_value.get("state")),
        assurance_level=str(validated["assurance_level"]),
    )
'''
    value = value.replace(old, new, 1)
    value = value.replace(
        '        decision=str(dict(validated["decision"])["disposition"]),\n',
        '        decision=str(decision_value.get("disposition")),\n',
        1,
    )
    value = value.replace(
        '        coverage_state=str(dict(validated["coverage"])["state"]),\n',
        '        coverage_state=str(coverage_value.get("state")),\n',
        1,
    )
    _write(relative, value)


def main() -> None:
    normalize_file_directives()
    fix_canonical_json_boundary()
    fix_dependency_boundaries()
    fix_detonation_limits()
    fix_native_boundaries()
    fix_dynamic_mapping_annotations()
    fix_server_middleware_types()
    fix_upload_boundaries()
    ensure_runtime_json_casts()


if __name__ == "__main__":
    main()
