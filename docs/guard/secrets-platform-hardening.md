# HOL Guard Secrets: setup and platform compatibility

HOL Guard Secrets runs locally and does not require a Guard Cloud account. Raw secret values are never included in the public scan result.

## Supported baseline

- Python 3.10 or newer
- Git 2.30 or newer for staged, history, and pre-commit protection
- macOS, Linux, WSL, Windows with Git for Windows, and development containers

Check the current machine without changing files:

```bash
hol-guard secrets doctor
hol-guard secrets doctor --json
```

## Install

Use an isolated `pipx` installation so Guard does not modify a project virtual environment.

### macOS

```bash
brew install python git pipx
pipx ensurepath
pipx install hol-guard
hol-guard secrets doctor
```

### Linux or WSL

```bash
python3 -m pip install --user pipx
python3 -m pipx ensurepath
pipx install hol-guard
hol-guard secrets doctor
```

Reopen the shell after `ensurepath`. Install Git with the distribution package manager when `doctor` reports `git_missing`.

### Windows PowerShell

Install Python 3.10 or newer and Git for Windows, then reopen PowerShell:

```powershell
py -m pip install --user pipx
py -m pipx ensurepath
pipx install hol-guard
hol-guard secrets doctor
```

The managed pre-commit hook uses the shell distributed with Git for Windows. Keep Windows and WSL installations separate because they have different executables, home directories, Git metadata, and credential stores.

## Verify detection and coverage

```bash
hol-guard secrets rules
hol-guard secrets scan .
hol-guard secrets scan . --history
hol-guard secrets scan --staged --fail-on-findings
```

A history scan is bounded. A partial scan, unavailable Git object, unsupported encoding, oversized file, or exceeded bound returns a nonzero exit code and must not be treated as clean evidence.

## Pre-commit protection

```bash
hol-guard secrets install-hook
hol-guard secrets scan --staged --fail-on-findings
```

Guard preserves an existing executable `pre-commit` hook and runs it first. Remove Guard and restore the original hook byte-for-byte with:

```bash
hol-guard secrets uninstall-hook
```

Guard refuses to modify a custom or shared `core.hooksPath`. Keep the existing hook manager authoritative and invoke this command from it:

```bash
hol-guard secrets scan --staged --fail-on-findings
```

## Containers and read-only checkouts

Working-tree and history scans are read-only. Hook installation requires writable Git metadata. In a read-only container, run scans directly or mount the repository Git metadata read-write. Do not copy host credentials or secret files into the image merely to test detection.

For a development container, install Guard inside the container. A host installation does not prove that the container shell, Python interpreter, or Git hook can invoke Guard.

## Git edge cases

- Shallow and partial clones can only prove coverage for locally available objects.
- Git LFS pointer files are scanned as pointers; fetch the corresponding objects before claiming their contents were scanned.
- Submodules are separate repositories and must be scanned independently.
- Symlinks and special files are not followed.
- Unsupported encodings and oversized files make coverage partial rather than silently clean.
- Paths containing spaces and Unicode are supported.
- Staged scans inspect the Git index, not unstaged working-tree content.

## Incident response

When a credential is found:

1. Rotate or revoke it at the issuing provider.
2. Replace every legitimate consumer.
3. Run a complete current-tree and bounded-history scan.
4. Remove the old value from reachable Git history where appropriate.
5. Treat prior clones, forks, caches, build logs, and artifacts as potentially exposed.

Deleting a value from the current branch is not containment. Rotation is the required first action.
