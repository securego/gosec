---
name: Create Gosec Rule
mode: agent
description: Create a new gosec rule from a Go issue description using the reusable gosec skill.
---

Use the skill Create New Gosec Rule from .github/skills/gosec-new-rule/SKILL.md.

Follow the skill contract exactly:
- First response must propose a rule ID, implementation approach, relevance for Go 1.25 and Go 1.26, and ask for confirmation.
- Do not start implementation until confirmation is explicitly provided.

Issue description:

### Summary
{{summary}}

### Steps to reproduce the behavior
{{steps_to_reproduce}}

### gosec version
{{gosec_version}}

### Go version (output of 'go version')
{{go_version}}

### Operating system / Environment
{{environment}}

### Expected behavior
{{expected_behavior}}

### Actual behavior
{{actual_behavior}}
