from __future__ import annotations

from pathlib import Path

WORKFLOW = Path('.github/workflows/publish.yml')
TESTS = Path('tests/test_release_train_workflow.py')

text = WORKFLOW.read_text(encoding='utf-8')

push_rerun_gate = "      (github.event_name != 'push' || github.run_attempt == 1) &&\n"
if push_rerun_gate not in text:
    raise SystemExit('push rerun build gate not found')
text = text.replace(push_rerun_gate, '', 1)

alpha_testpypi_anchor = (
    "  publish-alpha-testpypi:\n"
    "    name: Verify alpha artifact on TestPyPI\n"
    "    if: >-\n"
    "      always() &&\n"
    "      vars.RELEASE_PUBLISHING_ENABLED == 'true' &&\n"
)
if alpha_testpypi_anchor not in text:
    raise SystemExit('alpha TestPyPI job anchor not found')
text = text.replace(
    alpha_testpypi_anchor,
    alpha_testpypi_anchor + "      vars.ALPHA_TESTPYPI_ENABLED == 'true' &&\n",
    1,
)

testpypi_dependency = "      needs.publish-alpha-testpypi.result == 'success' &&\n"
if text.count(testpypi_dependency) != 1:
    raise SystemExit('expected exactly one production TestPyPI dependency')
text = text.replace(testpypi_dependency, '', 1)

alpha_needs = "    needs: [build, reserve-alpha-tag, publish-alpha-testpypi]\n"
if text.count(alpha_needs) != 1:
    raise SystemExit('expected exactly one alpha publish needs list')
text = text.replace(alpha_needs, "    needs: [build, reserve-alpha-tag]\n", 1)

head_check = '''          train_ref="refs/heads/release/${TRAIN}"
          remote_train_sha=$(git ls-remote --exit-code origin "$train_ref" | awk '{print $1}')
          if [[ "$remote_train_sha" != "$SOURCE_SHA" ]]; then
            echo "Alpha publication source is no longer the release train head" >&2
            exit 1
          fi
'''
ancestor_check = '''          train_ref="refs/heads/release/${TRAIN}"
          git fetch --no-tags origin "+${train_ref}:refs/remotes/origin/release/${TRAIN}"
          if ! git merge-base --is-ancestor "$SOURCE_SHA" "refs/remotes/origin/release/${TRAIN}"; then
            echo "Alpha publication source is no longer part of the release train" >&2
            exit 1
          fi
'''
if text.count(head_check) != 2:
    raise SystemExit(f'expected two alpha head checks, found {text.count(head_check)}')
text = text.replace(head_check, ancestor_check)

text = text.replace(
    "      - name: Verify the TestPyPI-proven artifact\n",
    "      - name: Verify immutable build artifact\n",
    1,
)
WORKFLOW.write_text(text, encoding='utf-8')

tests = TESTS.read_text(encoding='utf-8')
old_assert = '    assert "github.event_name != \'push\' || github.run_attempt == 1" in build_condition\n'
if old_assert not in tests:
    raise SystemExit('build rerun assertion not found')
tests = tests.replace(
    old_assert,
    '    assert "github.event_name != \'push\' || github.run_attempt == 1" not in build_condition\n',
    1,
)

old_dependency_contract = '''    assert jobs["publish-alpha-pypi"]["needs"] == [
        "build",
        "reserve-alpha-tag",
        "publish-alpha-testpypi",
    ]
    assert "needs.publish-alpha-testpypi.result == 'success'" in jobs["publish-alpha-pypi"]["if"]
'''
new_dependency_contract = '''    assert jobs["publish-alpha-pypi"]["needs"] == ["build", "reserve-alpha-tag"]
    assert "needs.publish-alpha-testpypi.result == 'success'" not in jobs["publish-alpha-pypi"]["if"]
    assert "vars.ALPHA_TESTPYPI_ENABLED == 'true'" in jobs["publish-alpha-testpypi"]["if"]
'''
if old_dependency_contract not in tests:
    raise SystemExit('alpha dependency contract not found')
tests = tests.replace(old_dependency_contract, new_dependency_contract, 1)

old_registry_assert = '    assert "git ls-remote --exit-code origin" in alpha_run\n'
new_registry_assert = '''    assert "git fetch --no-tags origin" in alpha_run
    assert "git merge-base --is-ancestor" in alpha_run
'''
if old_registry_assert not in tests:
    raise SystemExit('alpha registry revalidation assertion not found')
tests = tests.replace(old_registry_assert, new_registry_assert, 1)

old_source_assert = '    assert \'git ls-remote --exit-code origin "$train_ref"\' in alpha_test_run\n'
new_source_assert = '''    assert "git fetch --no-tags origin" in alpha_test_run
    assert "git merge-base --is-ancestor" in alpha_test_run
'''
if old_source_assert not in tests:
    raise SystemExit('alpha source branch assertion not found')
tests = tests.replace(old_source_assert, new_source_assert, 1)

TESTS.write_text(tests, encoding='utf-8')
