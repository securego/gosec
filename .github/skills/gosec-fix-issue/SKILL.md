---
name: Fix Gosec Bug From Issue
description: Analyze, reproduce, and fix a gosec bug reported in a GitHub issue with a confirmation-gated workflow.
---

# Fix a gosec bug from a GitHub issue

Use this skill when you want to fix a bug described in a GitHub issue.

## Required input

Provide at least:

- GitHub issue URL

Optional but useful:

- gosec version
- Go version (`go version` output)
- OS and environment details
- extra reproduction notes

## Execution workflow

1. Review the GitHub issue thoroughly and extract the problem statement, reproduction hints, expected behavior, and actual behavior.
2. Try to reproduce the issue against the current `master` version of gosec.
3. Analyze the codebase and isolate the root cause.
4. Produce a detailed, minimal fix plan and stop. Ask for confirmation before changing code.

After confirmation, implement end-to-end:

1. Keep the fix small and isolated to the issue scope.
2. Follow good design principles and idiomatic Go.
3. Add tests for both positive and negative cases.
4. When a code sample is appropriate, add or update a sample in `testutils/` in the relevant rule sample file.
5. Validate the result:
   - Build succeeds
   - Relevant tests pass
   - `golangci-lint` has no warnings in changed code
   - `gosec` CLI run on a sample confirms the issue is fixed

## Output requirements

- First response must only contain:
  - Reproduction status on `master` (or clear blocker)
  - Root cause analysis
  - Detailed fix plan
  - Confirmation request
- Do not implement any code changes until confirmation is provided.
