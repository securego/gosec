---
name: Update Supported Go Versions
description: Update gosec to the latest patch versions of the two latest supported Go major versions using go.dev release data.
---

# Update supported Go versions across the repository

Use this skill when you want to bump repository Go versions to the newest patch releases of the latest two supported Go major versions.

Reference source for versions:
- https://go.dev/doc/devel/release

## Required behavior

1. Fetch and parse the release page.
2. Detect the latest two Go major.minor series and their latest patch versions.
   - Example shape: latest series `1.26.x` and previous series `1.25.x`.
3. Derive:
   - `latest_patch` (for newest series, full patch string, e.g. `1.26.3`)
   - `previous_patch` (for second newest series, full patch string, e.g. `1.25.9`)
   - `latest_minor` (e.g. `1.26`)
   - `previous_minor` (e.g. `1.25`)
4. Apply updates carefully across all relevant files.

## Version update rules

Use repository-wide search and update all applicable occurrences, including but not limited to:

- GitHub Actions workflow `go-version` values:
  - Matrix entries for supported versions must include exactly the two patch versions:
    - `previous_patch`
    - `latest_patch`
  - Single-version setup-go steps should use `latest_patch`.
- Build argument and build tool defaults:
  - `GO_VERSION=<major.minor>` style values should use `latest_minor`.
- Module/toolchain minimum version markers:
  - `go.mod` `go` directive should be set to `previous_minor.0`.
  - Embedded temporary `go.mod` contents in tests/benchmarks should use `previous_minor` (without patch) unless file style requires otherwise.
- Documentation and skill/prompt metadata that state supported versions:
  - Update text to match the new supported pair (`previous_minor` and `latest_minor`).
  - Update "requires Go X or newer" style statements to `previous_minor`.

## Discovery checklist (must run)

Search the full repository for version markers and review each hit:

- `go-version:`
- `setup-go`
- `GO_VERSION`
- `golang:`
- `^go [0-9]+\.[0-9]+(\.[0-9]+)?$`
- `Go 1.`
- `1\.[0-9]+\.[0-9]+`

Do not change unrelated historical references unless they represent active supported-version policy.

## Validation

1. Confirm all intended files were updated and no obvious supported-version location was missed.
2. Run targeted checks:
   - `go test ./...`
3. Re-run search to ensure old supported pair is removed from active config/docs.

## Git and PR workflow

1. Create branch: `chore/update-go-versions-<latest_minor>`
2. Commit message: `chore(go): update supported Go versions to <previous_patch> and <latest_patch>`
3. Push branch.
4. Open PR to `master` with:
   - Title: `chore(go): update supported Go versions to <previous_patch> and <latest_patch>`
   - Body summary listing key files changed and source link to go.dev release page.

## Output requirements

- Report detected versions (`previous_patch`, `latest_patch`, `previous_minor`, `latest_minor`).
- List all updated files grouped by category (workflows, build config, module/tests, docs/metadata).
- Report test command result.
- Report branch name, commit SHA, PR title, and PR URL.
