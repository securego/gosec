---
name: Fix Gosec Bug From Issue
mode: agent
description: Investigate and fix a gosec bug from a GitHub issue URL using the reusable bug-fix skill.
---

Use the skill Fix Gosec Bug From Issue from .github/skills/gosec-fix-issue/SKILL.md.

Follow the skill contract exactly:
- First response must include only reproduction status on master (or blocker), root cause, detailed fix plan, and a confirmation request.
- Do not start implementation until confirmation is explicitly provided.

Issue input:

### GitHub issue URL
{{github_issue_url}}

### gosec version (optional)
{{gosec_version}}

### Go version (optional)
{{go_version}}

### Operating system / Environment (optional)
{{environment}}

### Additional notes (optional)
{{additional_notes}}
