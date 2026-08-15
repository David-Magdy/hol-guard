# Secrets hardening bootstrap failure

```text
From https://github.com/hashgraph-online/hol-guard
 * branch              fix/secrets-complete-hardening-final-v1 -> FETCH_HEAD
 * branch              fix/secrets-e2e-platform-hardening-v2 -> FETCH_HEAD
 * branch              fix/secrets-git-process-hardening-v2 -> FETCH_HEAD
 * branch              fix/secrets-git-object-edge-hardening -> FETCH_HEAD
 * branch              fix/secrets-hook-identity-final-v2 -> FETCH_HEAD
 * branch              fix/secrets-coverage-edge-cases-v2 -> FETCH_HEAD
 * branch              fix/secrets-coverage-evidence-v2 -> FETCH_HEAD
Performing three-way merge...
Applied patch to 'docs/guard/contracts/guard-secrets-capability-evidence.v2.json' cleanly.
Performing three-way merge...
Applied patch to 'docs/guard/contracts/guard-secrets-product-boundaries.v2.json' cleanly.
Performing three-way merge...
Applied patch to 'docs/guard/contracts/guard-secrets-reason-codes.v2.json' cleanly.
Performing three-way merge...
Applied patch to 'docs/guard/contracts/guard-secrets-source-capabilities.v2.json' cleanly.
Performing three-way merge...
Applied patch to 'scripts/ci/guard_secrets_release_claim_gate.py' cleanly.
Applied patch to 'scripts/write_release_toolchain_sbom.py' cleanly.
Performing three-way merge...
Applied patch to 'src/codex_plugin_scanner/guard/secrets/contracts_v2.py' cleanly.
Performing three-way merge...
Applied patch to 'tests/test_guard_secret_contracts_v2.py' cleanly.
Performing three-way merge...
Applied patch to 'tests/test_guard_secret_release_claim_gate.py' cleanly.
Applied patch to 'tests/test_release_toolchain_sbom.py' cleanly.
Performing three-way merge...
Applied patch to '.github/workflows/secrets-platform-e2e.yml' cleanly.
Performing three-way merge...
Applied patch to 'docs/guard/secrets-platform-hardening.md' cleanly.
Performing three-way merge...
Applied patch to 'scripts/ci/run_guard_secrets_platform_smoke_v2.py' cleanly.
Applied patch to 'src/codex_plugin_scanner/guard/secrets/cli.py' cleanly.
Performing three-way merge...
Applied patch to 'src/codex_plugin_scanner/guard/secrets/git_subprocess.py' cleanly.
Applied patch to 'src/codex_plugin_scanner/guard/secrets/precommit.py' cleanly.
Applied patch to 'src/codex_plugin_scanner/guard/secrets/secret_staged_scanner.py' cleanly.
Performing three-way merge...
Applied patch to 'src/codex_plugin_scanner/guard/secrets/setup_diagnostics.py' cleanly.
Performing three-way merge...
Applied patch to 'tests/test_guard_secret_doctor.py' cleanly.
Performing three-way merge...
Applied patch to 'tests/test_guard_secret_git_subprocess_hardening.py' cleanly.
Performing three-way merge...
Applied patch to 'tests/test_guard_secret_hook_configuration_hardening.py' cleanly.
Performing three-way merge...
Applied patch to 'tests/test_guard_secret_input_coverage_hardening.py' cleanly.
Performing three-way merge...
Applied patch to 'tests/test_guard_secret_platform_hardening.py' cleanly.
Traceback (most recent call last):
  File "/home/runner/work/hol-guard/hol-guard/scripts/ci/integrate_guard_secrets_final_v2.py", line 520, in <module>
    main()
  File "/home/runner/work/hol-guard/hol-guard/scripts/ci/integrate_guard_secrets_final_v2.py", line 474, in main
    (ROOT / destination).write_text(show(revision, source), encoding="utf-8")
                                    ^^^^^^^^^^^^^^^^^^^^^^
  File "/home/runner/work/hol-guard/hol-guard/scripts/ci/integrate_guard_secrets_final_v2.py", line 25, in show
    return run("git", "show", f"{revision}:{path}", capture=True)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/runner/work/hol-guard/hol-guard/scripts/ci/integrate_guard_secrets_final_v2.py", line 14, in run
    completed = subprocess.run(
                ^^^^^^^^^^^^^^^
  File "/opt/hostedtoolcache/Python/3.12.13/x64/lib/python3.12/subprocess.py", line 571, in run
    raise CalledProcessError(retcode, process.args,
subprocess.CalledProcessError: Command '('git', 'show', '3e2328a76c506c78df2f571af15d248aa3589ea0:src/codex_plugin_scanner/guard/secrets/coverage.py')' returned non-zero exit status 128.
```
