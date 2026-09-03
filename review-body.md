All previously flagged probes now reach review with attribution to `command.repo2nb.reverse-force` / `command.repo2nb.sync`:

- Indirect launchers: `python`/`python3`/`py -m repo2nb`, `exec`, `xargs` including `-n 1` forms.
- Abbreviated force flags: every unambiguous argparse prefix of `--force` (`--f` through `--force`).
- Unresolved shell expansions: `$VAR`, `${VAR}`, `$(...)`, and backtick tokens in a `reverse` invocation cannot prove `--force` absent, so a conservative matcher overlay routes them to review; safe variants still clone pure literal-flag matchers.
- `sync --dry-run` remains a safe variant while unknown options fail secure.

Regression cases cover direct and wrapper forms; plain `repo2nb reverse` and dry-run sync stay unreviewed. The extension-control catalog baseline, policy-bundle projection vector, permission-catalog digest, and decision-diff report are regenerated to match the updated catalog. CI and Desktop contract CI pass on the final head (plus Security Gates, CodeQL, Fuzzing, Semgrep, Gitleaks); the Native wheel soak failure reproduces on `main` and unrelated PRs and is unrelated to this diff.
