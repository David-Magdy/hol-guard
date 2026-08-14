from __future__ import annotations

from pathlib import Path


def class_bounds(lines: list[str], class_name: str) -> tuple[int, int]:
    start = lines.index(f"class {class_name}:")
    end = next(
        index
        for index in range(start + 1, len(lines))
        if lines[index].startswith("@dataclass") or lines[index].startswith("class ")
    )
    return start, end


def patch_contracts() -> None:
    path = Path("src/codex_plugin_scanner/guard/secrets/contracts_v2.py")
    lines = path.read_text(encoding="utf-8").splitlines()

    helper_start = lines.index(
        "def _require_enum_instance(value: object, enum_type: type[Enum], *, field_name: str) -> None:"
    )
    helper_end = lines.index(
        "def _iso_datetime(value: object, *, field_name: str) -> datetime | None:"
    )
    if any(
        line.startswith("def _require_string_tuple(")
        for line in lines[helper_start:helper_end]
    ):
        raise SystemExit("immutable sequence helper already exists")
    lines[helper_end:helper_end] = [
        "def _require_string_tuple(",
        "    value: object,",
        "    *,",
        "    field_name: str,",
        "    allow_empty: bool = True,",
        ") -> None:",
        '    """Validate immutable, unique, non-blank privacy-safe direct sequences."""',
        "",
        "    if not isinstance(value, tuple) or any(",
        "        not isinstance(item, str) for item in value",
        "    ):",
        '        raise SecretContractError(f"{field_name}: expected a tuple of strings")',
        "    values = cast(tuple[str, ...], value)",
        "    if not allow_empty and not values:",
        '        raise SecretContractError(f"{field_name}: must not be empty")',
        "    if len(set(values)) != len(values):",
        '        raise SecretContractError(f"{field_name}: values must be unique")',
        "    for item in values:",
        "        if not item.strip():",
        '            raise SecretContractError(f"{field_name}: values must not be blank")',
        "        if item != item.strip():",
        '            raise SecretContractError(',
        '                f"{field_name}: surrounding whitespace is prohibited"',
        "            )",
        "        _assert_safe_public_text(item, field_name=field_name)",
        "",
        "",
    ]

    ignore_start, ignore_end = class_bounds(lines, "SecretIgnoreDecisionV2")
    ignore_insert = lines.index("        for field_name, value in {", ignore_start, ignore_end)
    lines[ignore_insert:ignore_insert] = [
        "        _require_string_tuple(",
        "            self.propagation,",
        '            field_name="propagation",',
        "            allow_empty=False,",
        "        )",
    ]

    custom_start, custom_end = class_bounds(lines, "SecretCustomRuleV2")
    custom_insert = lines.index(
        "        if not _IDENTIFIER.fullmatch(self.rule_id):",
        custom_start,
        custom_end,
    )
    lines[custom_insert:custom_insert] = [
        "        _require_string_tuple(",
        "            self.surfaces,",
        '            field_name="surfaces",',
        "            allow_empty=False,",
        "        )",
    ]

    capability_start, capability_end = class_bounds(lines, "CapabilityEvidenceV2")
    capability_state = lines.index(
        '        _require_enum_instance(self.state, ParityState, field_name="state")',
        capability_start,
        capability_end,
    )
    lines[capability_state + 1:capability_state + 1] = [
        "        for field_name, values, allow_empty in (",
        '            ("surfaces", self.surfaces, False),',
        '            ("plans", self.plans, False),',
        '            ("acceptance_tests", self.acceptance_tests, True),',
        '            ("evidence_artifacts", self.evidence_artifacts, True),',
        "        ):",
        "            _require_string_tuple(",
        "                values,",
        "                field_name=field_name,",
        "                allow_empty=allow_empty,",
        "            )",
    ]

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def patch_tests() -> None:
    path = Path("tests/test_guard_secret_contracts_v2.py")
    lines = path.read_text(encoding="utf-8").splitlines()
    insertion = lines.index("def test_complete_coverage_is_clean_eligible() -> None:")
    additions = '''def test_direct_ignore_rejects_mutable_propagation() -> None:
    mutable = ["cli"]
    with pytest.raises(SecretContractError, match="tuple of strings"):
        _direct_ignore(propagation=mutable)
    mutable.append("github")
    assert mutable == ["cli", "github"]


def test_direct_ignore_rejects_string_propagation() -> None:
    with pytest.raises(SecretContractError, match="tuple of strings"):
        _direct_ignore(propagation="cli")


def test_direct_ignore_rejects_duplicate_propagation() -> None:
    with pytest.raises(SecretContractError, match="values must be unique"):
        _direct_ignore(propagation=("cli", "cli"))


def test_direct_ignore_rejects_blank_propagation() -> None:
    with pytest.raises(SecretContractError, match="must not be blank"):
        _direct_ignore(propagation=(" ",))


def test_direct_ignore_rejects_empty_propagation() -> None:
    with pytest.raises(SecretContractError, match="must not be empty"):
        _direct_ignore(propagation=())


def test_direct_custom_rule_rejects_mutable_surfaces() -> None:
    mutable = ["cli"]
    with pytest.raises(SecretContractError, match="tuple of strings"):
        _direct_custom_rule(surfaces=mutable)
    mutable.append("pre_commit")
    assert mutable == ["cli", "pre_commit"]


def test_direct_custom_rule_rejects_string_surfaces() -> None:
    with pytest.raises(SecretContractError, match="tuple of strings"):
        _direct_custom_rule(surfaces="cli")


def test_direct_custom_rule_rejects_duplicate_surfaces() -> None:
    with pytest.raises(SecretContractError, match="values must be unique"):
        _direct_custom_rule(surfaces=("cli", "cli"))


def test_direct_custom_rule_rejects_blank_surfaces() -> None:
    with pytest.raises(SecretContractError, match="must not be blank"):
        _direct_custom_rule(surfaces=(" ",))


def test_direct_custom_rule_rejects_empty_surfaces() -> None:
    with pytest.raises(SecretContractError, match="must not be empty"):
        _direct_custom_rule(surfaces=())


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("surfaces", ["cli"]),
        ("plans", ["free"]),
        ("acceptance_tests", ["test_cli"]),
        ("evidence_artifacts", ["sha256:evidence"]),
    ],
)
def test_direct_capability_rejects_mutable_sequence_fields(
    field_name: str,
    value: list[str],
) -> None:
    with pytest.raises(SecretContractError, match="tuple of strings"):
        _capability(**{field_name: value})
    value.append("mutated")
    assert value[-1] == "mutated"


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("surfaces", "cli"),
        ("plans", "free"),
        ("acceptance_tests", "test_cli"),
        ("evidence_artifacts", "sha256:evidence"),
    ],
)
def test_direct_capability_rejects_string_sequence_fields(
    field_name: str,
    value: str,
) -> None:
    with pytest.raises(SecretContractError, match="tuple of strings"):
        _capability(**{field_name: value})


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("surfaces", ("cli", "cli")),
        ("plans", ("free", "free")),
        ("acceptance_tests", ("test_cli", "test_cli")),
        ("evidence_artifacts", ("sha256:evidence", "sha256:evidence")),
    ],
)
def test_direct_capability_rejects_duplicate_sequence_fields(
    field_name: str,
    value: tuple[str, ...],
) -> None:
    with pytest.raises(SecretContractError, match="values must be unique"):
        _capability(**{field_name: value})


@pytest.mark.parametrize(
    "field_name",
    ["surfaces", "plans", "acceptance_tests", "evidence_artifacts"],
)
def test_direct_capability_rejects_blank_sequence_fields(field_name: str) -> None:
    with pytest.raises(SecretContractError, match="must not be blank"):
        _capability(**{field_name: (" ",)})


@pytest.mark.parametrize("field_name", ["surfaces", "plans"])
def test_direct_capability_rejects_empty_required_sequence_fields(field_name: str) -> None:
    with pytest.raises(SecretContractError, match="must not be empty"):
        _capability(**{field_name: ()})


'''.splitlines()
    lines[insertion:insertion] = additions
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    patch_contracts()
    patch_tests()


if __name__ == "__main__":
    main()
