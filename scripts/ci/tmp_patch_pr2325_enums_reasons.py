from __future__ import annotations

from pathlib import Path


def replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one anchor, found {count}")
    return text.replace(old, new, 1)


def insert_after_post_init(source: str, class_name: str, statements: list[str]) -> str:
    lines = source.splitlines()
    class_index = lines.index(f"class {class_name}:")
    class_end = next(
        index
        for index in range(class_index + 1, len(lines))
        if lines[index].startswith("class ") or lines[index].startswith("@dataclass")
    )
    post_init = lines.index("    def __post_init__(self) -> None:", class_index, class_end)
    lines[post_init + 1:post_init + 1] = statements
    return "\n".join(lines) + "\n"


def patch_contracts() -> None:
    path = Path("src/codex_plugin_scanner/guard/secrets/contracts_v2.py")
    text = path.read_text(encoding="utf-8")

    schema_anchor = '_SCHEMA_SOURCE_CAPABILITIES: Final = "guard-secrets-source-capabilities.v2"\n'
    text = replace_once(
        text,
        schema_anchor,
        schema_anchor + '_SCHEMA_REASON_CODES: Final = "guard-secrets-reason-codes.v2"\n',
        label="reason schema",
    )

    reason_start = text.index("REASON_CODES_V2: Final[frozenset[str]] = frozenset(")
    reason_end = text.index("IGNORE_REASON_CODES_V2: Final[frozenset[str]]", reason_start)
    reason_authority = '''_REASON_CODE_CATEGORIES_MUTABLE: dict[str, tuple[str, ...]] = {
    "coverage": (
        "archive_budget_exceeded",
        "binary_skipped",
        "encoding_unsupported",
        "file_changed_during_scan",
        "git_object_missing",
        "history_shallow",
        "lfs_object_missing",
        "max_bytes",
        "max_commits",
        "max_files",
        "max_findings",
        "source_unreadable",
    ),
    "detector": (
        "detector_bundle_invalid",
        "detector_unavailable",
        "model_bundle_invalid",
        "model_degraded",
    ),
    "validation": (
        "validation_error",
        "validation_rate_limited",
        "validation_unknown",
        "validation_unsupported",
    ),
    "policy": ("policy_block", "policy_refresh_required"),
    "worker": ("cleanup_failed", "worker_cancelled", "worker_timeout"),
    "cache": ("cache_stale",),
}
REASON_CODE_CATEGORIES_V2: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    dict(_REASON_CODE_CATEGORIES_MUTABLE)
)
REASON_CODE_RULES_V2: Final[Mapping[str, bool]] = MappingProxyType(
    {
        "stable": True,
        "non_sensitive": True,
        "unknown_codes_fail_closed": True,
        "raw_exception_text_forbidden": True,
    }
)
REASON_CODES_V2: Final[frozenset[str]] = frozenset(
    code
    for codes in _REASON_CODE_CATEGORIES_MUTABLE.values()
    for code in codes
)
'''
    text = text[:reason_start] + reason_authority + text[reason_end:]

    text = replace_once(
        text,
        'r"(?:^|_)(?:raw(?:_value)?|raw_?secret|candidate(?:_value)?|credential(?:_value)?|"',
        'r"(?:^|_)(?:raw_value|raw_?secret|candidate(?:_value)?|credential(?:_value)?|"',
        label="prohibited raw-value key",
    )

    enum_anchor = '''def _enum_value(enum_type: type[Enum], value: object, *, field_name: str) -> Enum:
    text = _required_text(value, field_name=field_name)
    try:
        return enum_type(text)
    except ValueError as error:
        raise SecretContractError(f"{field_name}: invalid value") from error
'''
    text = replace_once(
        text,
        enum_anchor,
        enum_anchor
        + '''


def _require_enum_instance(value: object, enum_type: type[Enum], *, field_name: str) -> None:
    """Reject raw strings and unrelated enums on direct construction."""

    if not isinstance(value, enum_type):
        raise SecretContractError(f"{field_name}: expected {enum_type.__name__}")
''',
        label="enum helper",
    )

    text = insert_after_post_init(
        text,
        "SecretIgnoreDecisionV2",
        [
            '        _require_enum_instance(self.state, SecretIgnoreState, field_name="state")',
            "        _require_enum_instance(",
            "            self.requested_scope,",
            "            SecretIgnoreScope,",
            '            field_name="requested_scope",',
            "        )",
        ],
    )
    text = insert_after_post_init(
        text,
        "SecretCustomRuleV2",
        [
            "        _require_enum_instance(",
            "            self.matcher_kind,",
            "            SecretRuleMatcherKind,",
            '            field_name="matcher_kind",',
            "        )",
            "        _require_enum_instance(",
            "            self.compile_state,",
            "            SecretRuleCompileState,",
            '            field_name="compile_state",',
            "        )",
            "        _require_enum_instance(",
            "            self.rollout_state,",
            "            SecretRolloutState,",
            '            field_name="rollout_state",',
            "        )",
        ],
    )
    text = insert_after_post_init(
        text,
        "CapabilityEvidenceV2",
        ['        _require_enum_instance(self.state, ParityState, field_name="state")'],
    )

    metric_anchor = "@dataclass(frozen=True, slots=True)\nclass OrganizationMetricDefinitionV2:\n"
    text = replace_once(
        text,
        metric_anchor,
        '''@dataclass(frozen=True, slots=True)
class ReasonCodeManifestV2:
    """Runtime-validated reason-code categories and fail-closed rules."""

    category_ids: tuple[str, ...]
    codes: frozenset[str]
    rule_ids: tuple[str, ...]


'''
        + metric_anchor,
        label="reason manifest dataclass",
    )

    parser_anchor = "def parse_capability_evidence_manifest(payload: Mapping[str, object]) -> CapabilityManifestV2:\n"
    reason_parser = '''def parse_reason_codes_manifest(payload: Mapping[str, object]) -> ReasonCodeManifestV2:
    """Parse and compare the reason-code manifest to runtime authority."""

    allowed = {"schema", "categories", "rules"}
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise SecretContractError(
            f"{_SCHEMA_REASON_CODES}: unknown fields: {', '.join(unknown)}"
        )
    if payload.get("schema") != _SCHEMA_REASON_CODES:
        raise SecretContractError("unsupported reason-code manifest schema")

    categories = _mapping(payload.get("categories"), field_name="categories")
    expected_category_ids = tuple(REASON_CODE_CATEGORIES_V2)
    if tuple(categories) != expected_category_ids:
        raise SecretContractError(
            "reason-code category registry does not match the runtime contract"
        )

    seen: set[str] = set()
    for category_id, expected_codes in REASON_CODE_CATEGORIES_V2.items():
        declared_codes = _str_tuple(
            categories.get(category_id),
            field_name=f"categories.{category_id}",
            allow_empty=False,
        )
        if len(set(declared_codes)) != len(declared_codes):
            raise SecretContractError(
                f"categories.{category_id}: reason codes must be unique"
            )
        duplicates = sorted(seen.intersection(declared_codes))
        if duplicates:
            raise SecretContractError(
                "reason codes must belong to exactly one category: "
                + ", ".join(duplicates)
            )
        if declared_codes != expected_codes:
            raise SecretContractError(
                f"categories.{category_id}: codes do not match the runtime contract"
            )
        seen.update(declared_codes)
    if frozenset(seen) != REASON_CODES_V2:
        raise SecretContractError(
            "reason-code registry does not match the runtime contract"
        )

    rules = _mapping(payload.get("rules"), field_name="rules")
    if tuple(rules) != tuple(REASON_CODE_RULES_V2):
        raise SecretContractError(
            "reason-code rule registry does not match the runtime contract"
        )
    for rule_id, expected_value in REASON_CODE_RULES_V2.items():
        declared_value = _required_bool(
            rules.get(rule_id),
            field_name=f"rules.{rule_id}",
        )
        if declared_value is not expected_value:
            raise SecretContractError(
                f"rules.{rule_id}: policy does not match the runtime contract"
            )

    return ReasonCodeManifestV2(
        category_ids=expected_category_ids,
        codes=frozenset(seen),
        rule_ids=tuple(REASON_CODE_RULES_V2),
    )


'''
    text = replace_once(
        text,
        parser_anchor,
        reason_parser + parser_anchor,
        label="reason manifest parser",
    )

    for old, new, label in (
        (
            '    "REASON_CODES_V2",\n',
            '    "REASON_CODE_CATEGORIES_V2",\n    "REASON_CODE_RULES_V2",\n    "REASON_CODES_V2",\n',
            "reason exports",
        ),
        (
            '    "ProductBoundaryManifestV2",\n',
            '    "ProductBoundaryManifestV2",\n    "ReasonCodeManifestV2",\n',
            "reason dataclass export",
        ),
        (
            '    "parse_product_boundaries_manifest",\n',
            '    "parse_product_boundaries_manifest",\n    "parse_reason_codes_manifest",\n',
            "reason parser export",
        ),
    ):
        text = replace_once(text, old, new, label=label)

    path.write_text(text, encoding="utf-8")


def patch_gate() -> None:
    path = Path("scripts/ci/guard_secrets_release_claim_gate.py")
    lines = path.read_text(encoding="utf-8").splitlines()

    api_start = lines.index("def _contract_api() -> tuple[")
    api_end = lines.index("]:", api_start)
    validator_index = lines.index("    _CapabilityValidator,", api_start, api_end)
    lines.insert(validator_index, "    Callable[[Mapping[str, object]], object],")

    source_symbol = next(
        index
        for index in range(api_end, len(lines))
        if '_symbol(module, "parse_source_capabilities_manifest")' in lines[index]
    )
    source_cast_end = next(
        index for index in range(source_symbol, len(lines)) if lines[index] == "        ),"
    )
    lines[source_cast_end + 1:source_cast_end + 1] = [
        "        cast(",
        "            Callable[[Mapping[str, object]], object],",
        '            _symbol(module, "parse_reason_codes_manifest"),',
        "        ),",
    ]

    validate_start = lines.index("def validate_manifest(")
    signature_end = lines.index(") -> tuple[str, ...]:", validate_start)
    source_parameter = lines.index(
        "    source_capability_payload: Mapping[str, object],",
        validate_start,
        signature_end,
    )
    lines.insert(source_parameter + 1, "    reason_code_payload: Mapping[str, object],")

    unpack_source = lines.index(
        "        parse_source_capabilities_manifest,",
        signature_end,
    )
    lines.insert(unpack_source + 1, "        parse_reason_codes_manifest,")

    source_call = lines.index(
        "        _ = parse_source_capabilities_manifest(source_capability_payload)",
        unpack_source,
    )
    lines.insert(source_call + 1, "        _ = parse_reason_codes_manifest(reason_code_payload)")

    parser_start = lines.index("def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:")
    parser_source = lines.index(
        '    parser.add_argument("--source-capabilities", type=Path, required=True)',
        parser_start,
    )
    lines.insert(parser_source + 1, '    parser.add_argument("--reason-codes", type=Path, required=True)')

    main_start = lines.index("def main(argv: list[str] | None = None) -> int:")
    main_source = lines.index(
        "            source_capability_payload=load_manifest(args.source_capabilities),",
        main_start,
    )
    lines.insert(main_source + 1, "            reason_code_payload=load_manifest(args.reason_codes),")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def patch_toolchain() -> None:
    path = Path("scripts/write_release_toolchain_sbom.py")
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '_SOURCE_CAPABILITIES_MANIFEST = Path("docs/guard/contracts/guard-secrets-source-capabilities.v2.json")\n',
        '_SOURCE_CAPABILITIES_MANIFEST = Path("docs/guard/contracts/guard-secrets-source-capabilities.v2.json")\n_REASON_CODES_MANIFEST = Path("docs/guard/contracts/guard-secrets-reason-codes.v2.json")\n',
        label="reason manifest constant",
    )
    text = replace_once(
        text,
        '''        "--source-capabilities",
        str(repository_root / _SOURCE_CAPABILITIES_MANIFEST),
        "--release-commit",
''',
        '''        "--source-capabilities",
        str(repository_root / _SOURCE_CAPABILITIES_MANIFEST),
        "--reason-codes",
        str(repository_root / _REASON_CODES_MANIFEST),
        "--release-commit",
''',
        label="reason manifest command",
    )
    path.write_text(text, encoding="utf-8")


def patch_contract_tests() -> None:
    path = Path("tests/test_guard_secret_contracts_v2.py")
    text = path.read_text(encoding="utf-8")
    for old, new, label in (
        (
            '''    OUTCOME_SURFACE_MAPPING,
    REASON_CODES_V2,
''',
            '''    OUTCOME_SURFACE_MAPPING,
    REASON_CODE_CATEGORIES_V2,
    REASON_CODE_RULES_V2,
    REASON_CODES_V2,
''',
            "reason imports",
        ),
        (
            '''    parse_product_boundaries_manifest,
    parse_source_capabilities_manifest,
''',
            '''    parse_product_boundaries_manifest,
    parse_reason_codes_manifest,
    parse_source_capabilities_manifest,
''',
            "reason parser import",
        ),
        (
            '_SOURCE_CAPABILITY_PATH = _REPOSITORY_ROOT / "docs/guard/contracts/guard-secrets-source-capabilities.v2.json"\n',
            '_SOURCE_CAPABILITY_PATH = _REPOSITORY_ROOT / "docs/guard/contracts/guard-secrets-source-capabilities.v2.json"\n_REASON_CODE_PATH = _REPOSITORY_ROOT / "docs/guard/contracts/guard-secrets-reason-codes.v2.json"\n',
            "reason path",
        ),
    ):
        text = replace_once(text, old, new, label=label)

    helper_anchor = "def test_complete_coverage_is_clean_eligible() -> None:\n"
    helper_text = '''def _direct_ignore(**overrides: object) -> SecretIgnoreDecisionV2:
    values: dict[str, object] = {
        "decision_id": "ignore:direct",
        "state": SecretIgnoreState.REQUESTED,
        "requested_scope": SecretIgnoreScope.OCCURRENCE,
        "durable_match_key": "a" * 64,
        "reason": "pending_review",
        "expires_at": datetime.now(timezone.utc) + timedelta(days=7),
        "detector_version": "guard-secrets-v2",
        "model_version": None,
        "requester_id": "user:1",
        "approver_id": None,
        "policy_source": "personal",
        "propagation": ("cli",),
    }
    values.update(overrides)
    return SecretIgnoreDecisionV2(**values)  # type: ignore[arg-type]


def _direct_custom_rule(**overrides: object) -> SecretCustomRuleV2:
    values: dict[str, object] = {
        "rule_id": "rule:direct",
        "version": "1.0.0",
        "matcher_kind": SecretRuleMatcherKind.REGEX,
        "matcher_digest": "a" * 64,
        "safe_fixture_digest": "b" * 64,
        "provenance_digest": "c" * 64,
        "compile_state": SecretRuleCompileState.VALID,
        "complexity_budget": 100,
        "rollout_state": SecretRolloutState.DRAFT,
        "surfaces": ("cli",),
    }
    values.update(overrides)
    return SecretCustomRuleV2(**values)  # type: ignore[arg-type]


'''
    text = replace_once(text, helper_anchor, helper_text + helper_anchor, label="direct helpers")

    ignore_anchor = "def test_approved_ignore_requires_approver() -> None:\n"
    ignore_tests = '''@pytest.mark.parametrize(
    ("field_name", "value", "expected_type"),
    [
        ("state", "requested", "SecretIgnoreState"),
        ("requested_scope", "occurrence", "SecretIgnoreScope"),
    ],
)
def test_direct_ignore_rejects_raw_enum_values(
    field_name: str,
    value: str,
    expected_type: str,
) -> None:
    with pytest.raises(SecretContractError, match=f"expected {expected_type}"):
        _direct_ignore(**{field_name: value})


'''
    text = replace_once(text, ignore_anchor, ignore_tests + ignore_anchor, label="ignore enum tests")

    custom_anchor = "def test_active_custom_rule_must_compile_validly() -> None:\n"
    custom_tests = '''@pytest.mark.parametrize(
    ("field_name", "value", "expected_type"),
    [
        ("matcher_kind", "regex", "SecretRuleMatcherKind"),
        ("compile_state", "valid", "SecretRuleCompileState"),
        ("rollout_state", "active", "SecretRolloutState"),
    ],
)
def test_direct_custom_rule_rejects_raw_enum_values(
    field_name: str,
    value: str,
    expected_type: str,
) -> None:
    with pytest.raises(SecretContractError, match=f"expected {expected_type}"):
        _direct_custom_rule(**{field_name: value})


def test_raw_active_invalid_custom_rule_cannot_bypass_compile_check() -> None:
    with pytest.raises(SecretContractError, match="expected SecretRuleCompileState"):
        _direct_custom_rule(compile_state="invalid", rollout_state="active")


'''
    text = replace_once(text, custom_anchor, custom_tests + custom_anchor, label="custom enum tests")

    capability_anchor = "def test_release_claim_rejects_unverified_capability() -> None:\n"
    capability_test = '''def test_direct_capability_rejects_raw_parity_state() -> None:
    with pytest.raises(SecretContractError, match="expected ParityState"):
        _capability(
            state="verified_on_release_candidate",
            release_commit="d" * 40,
            evidence_artifacts=("sha256:evidence",),
            gap_label=None,
        )


'''
    text = replace_once(
        text,
        capability_anchor,
        capability_test + capability_anchor,
        label="capability enum test",
    )

    old_reason_test = '''def test_repository_reason_code_registry_matches_runtime() -> None:
    payload = _load(_REPOSITORY_ROOT / "docs/guard/contracts/guard-secrets-reason-codes.v2.json")
    categories = payload["categories"]
    assert isinstance(categories, dict)
    declared = {code for codes in categories.values() for code in codes}
    assert declared == REASON_CODES_V2
'''
    new_reason_tests = '''def test_repository_reason_code_manifest_matches_runtime() -> None:
    manifest = parse_reason_codes_manifest(_load(_REASON_CODE_PATH))
    assert manifest.category_ids == tuple(REASON_CODE_CATEGORIES_V2)
    assert manifest.codes == REASON_CODES_V2
    assert manifest.rule_ids == tuple(REASON_CODE_RULES_V2)


def test_reason_code_manifest_rejects_schema_drift() -> None:
    payload = _load(_REASON_CODE_PATH)
    payload["schema"] = "guard-secrets-reason-codes.v3"
    with pytest.raises(SecretContractError, match="unsupported reason-code"):
        parse_reason_codes_manifest(payload)


def test_reason_code_manifest_rejects_category_registry_drift() -> None:
    payload = _load(_REASON_CODE_PATH)
    categories = payload["categories"]
    assert isinstance(categories, dict)
    categories["unreviewed"] = ["unreviewed_reason"]
    with pytest.raises(SecretContractError, match="category registry"):
        parse_reason_codes_manifest(payload)


def test_reason_code_manifest_rejects_code_drift() -> None:
    payload = _load(_REASON_CODE_PATH)
    categories = payload["categories"]
    assert isinstance(categories, dict)
    coverage = categories["coverage"]
    assert isinstance(coverage, list)
    coverage[0] = "unreviewed_reason"
    with pytest.raises(SecretContractError, match="codes do not match"):
        parse_reason_codes_manifest(payload)


def test_reason_code_manifest_rejects_duplicate_code_in_category() -> None:
    payload = _load(_REASON_CODE_PATH)
    categories = payload["categories"]
    assert isinstance(categories, dict)
    coverage = categories["coverage"]
    assert isinstance(coverage, list)
    coverage.append(coverage[0])
    with pytest.raises(SecretContractError, match="must be unique"):
        parse_reason_codes_manifest(payload)


def test_reason_code_manifest_rejects_code_in_multiple_categories() -> None:
    payload = _load(_REASON_CODE_PATH)
    categories = payload["categories"]
    assert isinstance(categories, dict)
    coverage = categories["coverage"]
    detector = categories["detector"]
    assert isinstance(coverage, list)
    assert isinstance(detector, list)
    detector.insert(0, coverage[0])
    with pytest.raises(SecretContractError, match="exactly one category"):
        parse_reason_codes_manifest(payload)


@pytest.mark.parametrize("rule_id", tuple(REASON_CODE_RULES_V2))
def test_reason_code_manifest_rejects_rule_weakening(rule_id: str) -> None:
    payload = _load(_REASON_CODE_PATH)
    rules = payload["rules"]
    assert isinstance(rules, dict)
    rules[rule_id] = False
    with pytest.raises(SecretContractError, match="policy does not match"):
        parse_reason_codes_manifest(payload)


def test_reason_code_manifest_rejects_rule_registry_drift() -> None:
    payload = _load(_REASON_CODE_PATH)
    rules = payload["rules"]
    assert isinstance(rules, dict)
    rules["unreviewed"] = True
    with pytest.raises(SecretContractError, match="rule registry"):
        parse_reason_codes_manifest(payload)
'''
    text = replace_once(
        text,
        old_reason_test,
        new_reason_tests,
        label="reason registry tests",
    )
    path.write_text(text, encoding="utf-8")


def patch_gate_tests() -> None:
    path = Path("tests/test_guard_secret_release_claim_gate.py")
    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        '_SOURCE_CAPABILITY_PATH = _REPOSITORY_ROOT / "docs/guard/contracts/guard-secrets-source-capabilities.v2.json"\n',
        '_SOURCE_CAPABILITY_PATH = _REPOSITORY_ROOT / "docs/guard/contracts/guard-secrets-source-capabilities.v2.json"\n_REASON_CODE_PATH = _REPOSITORY_ROOT / "docs/guard/contracts/guard-secrets-reason-codes.v2.json"\n',
        label="gate reason path",
    )
    text = replace_once(
        text,
        '''    source_capability_payload: dict[str, object] | None = None,
) -> tuple[str, ...]:
''',
        '''    source_capability_payload: dict[str, object] | None = None,
    reason_code_payload: dict[str, object] | None = None,
) -> tuple[str, ...]:
''',
        label="gate validate helper signature",
    )
    text = replace_once(
        text,
        '''        source_capability_payload=(
            source_capability_payload if source_capability_payload is not None else _load(_SOURCE_CAPABILITY_PATH)
        ),
        exact_release_commit=release_commit,
''',
        '''        source_capability_payload=(
            source_capability_payload if source_capability_payload is not None else _load(_SOURCE_CAPABILITY_PATH)
        ),
        reason_code_payload=(
            reason_code_payload if reason_code_payload is not None else _load(_REASON_CODE_PATH)
        ),
        exact_release_commit=release_commit,
''',
        label="gate validate helper call",
    )
    text = replace_once(
        text,
        '''        source_capability_payload=load_manifest(_SOURCE_CAPABILITY_PATH),
        exact_release_commit="a" * 40,
''',
        '''        source_capability_payload=load_manifest(_SOURCE_CAPABILITY_PATH),
        reason_code_payload=load_manifest(_REASON_CODE_PATH),
        exact_release_commit="a" * 40,
''',
        label="repository gate validation",
    )
    text = replace_once(
        text,
        '''            source_capability_payload=_load(_SOURCE_CAPABILITY_PATH),
            exact_release_commit=None,
''',
        '''            source_capability_payload=_load(_SOURCE_CAPABILITY_PATH),
            reason_code_payload=_load(_REASON_CODE_PATH),
            exact_release_commit=None,
''',
        label="missing release commit validation",
    )

    lines = text.splitlines()
    index = 0
    inserted = 0
    while index < len(lines) - 1:
        if (
            lines[index].strip() == '"--source-capabilities",'
            and lines[index + 1].strip() == "str(_SOURCE_CAPABILITY_PATH),"
        ):
            lines[index + 2:index + 2] = [
                '        "--reason-codes",',
                "        str(_REASON_CODE_PATH),",
            ]
            inserted += 1
            index += 4
        else:
            index += 1
    if inserted != 3:
        raise SystemExit(f"gate argv: expected three insertions, found {inserted}")
    text = "\n".join(lines) + "\n"

    anchor = "def test_main_returns_zero_for_repository_policy(capsys: pytest.CaptureFixture[str]) -> None:\n"
    tests = '''def test_reason_code_schema_drift_is_rejected_by_gate() -> None:
    payload = _load(_REASON_CODE_PATH)
    payload["schema"] = "guard-secrets-reason-codes.v3"
    with pytest.raises(ClaimGateError, match="unsupported reason-code"):
        _validate(_manifest(), reason_code_payload=payload)


@pytest.mark.parametrize(
    "rule_id",
    (
        "stable",
        "non_sensitive",
        "unknown_codes_fail_closed",
        "raw_exception_text_forbidden",
    ),
)
def test_reason_code_policy_weakening_is_rejected_by_gate(rule_id: str) -> None:
    payload = _load(_REASON_CODE_PATH)
    rules = payload["rules"]
    assert isinstance(rules, dict)
    rules[rule_id] = False
    with pytest.raises(ClaimGateError, match="policy does not match"):
        _validate(_manifest(), reason_code_payload=payload)


'''
    text = replace_once(text, anchor, tests + anchor, label="gate reason tests")
    path.write_text(text, encoding="utf-8")


def patch_toolchain_tests() -> None:
    path = Path("tests/test_release_toolchain_sbom.py")
    text = path.read_text(encoding="utf-8")
    anchor = '    assert command[command.index("--source-capabilities") + 1].endswith("guard-secrets-source-capabilities.v2.json")\n'
    text = replace_once(
        text,
        anchor,
        anchor
        + '    assert command[command.index("--reason-codes") + 1].endswith("guard-secrets-reason-codes.v2.json")\n',
        label="toolchain reason argument assertion",
    )
    copy_anchor = '        "docs/guard/contracts/guard-secrets-source-capabilities.v2.json",\n'
    text = replace_once(
        text,
        copy_anchor,
        copy_anchor + '        "docs/guard/contracts/guard-secrets-reason-codes.v2.json",\n',
        label="toolchain reason fixture",
    )
    path.write_text(text, encoding="utf-8")


def main() -> None:
    patch_contracts()
    patch_gate()
    patch_toolchain()
    patch_contract_tests()
    patch_gate_tests()
    patch_toolchain_tests()


if __name__ == "__main__":
    main()
