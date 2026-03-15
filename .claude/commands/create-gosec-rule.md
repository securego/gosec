# Create a new gosec rule from issue description

Use this command to design and implement a new gosec rule based on a Go security issue report.

## Required input

Provide the issue description using this structure:

$ARGUMENTS

## Execution workflow

1. Analyze the current source code of gosec, with emphasis on existing analyzers (SSA and taint) and current rules.
2. Think deeply and propose the best implementation approach for this issue.
3. Prefer an SSA-based analyzer over an AST-based rule when feasible.
4. Assess whether this issue is still relevant for supported Go versions (Go 1.25 and Go 1.26).
5. Propose a candidate rule ID and stop. Ask for confirmation before implementation.

After confirmation, implement end-to-end:

1. Implement the analyzer or rule with idiomatic Go and maintainable structure.
2. Optimize for performance (avoid unnecessary repeated AST or SSA traversals).
3. Select an appropriate CWE aligned with current repository mappings.
4. Integrate the rule in all required registration points.
5. Add sample file(s) in testutils following existing conventions:
   - At least 2 positive samples (issue must trigger)
   - At least 2 negative samples (issue must not trigger)
6. Update rule documentation in README.md in the same style as other rules.
7. Validate the change:
   - Build succeeds
   - Relevant tests pass
   - golangci-lint is clean for new code
   - Rule works against a sample file with the gosec CLI

## Output requirements

- First response must only contain:
  - Proposed rule ID
  - Approach recommendation (SSA / taint / AST with rationale)
  - Relevance assessment for Go 1.25 and 1.26
  - A request for user confirmation
- Do not start implementation until confirmation is provided.
