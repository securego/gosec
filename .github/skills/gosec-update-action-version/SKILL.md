---
name: Update Gosec Action Version
description: Update the gosec Docker image version in action.yml using a provided gosec version.
---

# Update gosec version in GitHub Action metadata

Use this skill when you want to update the gosec version used by this repository's GitHub Action.

## Required input

### gosec version
<gosec version, for example 2.24.1>

## Execution workflow

1. Read `action.yml`.
2. Locate `runs.image` with format `docker://securego/gosec:<version>`.
3. Replace only the version segment after the colon with the provided gosec version.
4. Do not change unrelated fields or formatting in `action.yml`.
5. Validate that the resulting image value is exactly `docker://securego/gosec:<provided_version>`.
6. Create a branch named `chore/update-action-gosec-<provided_version>`.
7. Commit the change with message `chore(action): bump gosec to <provided_version>`.
8. Push the branch to origin.
9. Open a pull request to `master` with:
	- Title: `chore(action): bump gosec to <provided_version>`
	- Body: concise summary that this updates `action.yml` Docker image version.

## Output requirements

- Report old version and new version.
- Confirm that only `action.yml` was modified for the version bump.
- Report the created branch name, commit SHA, pull request title, and pull request URL.
