---
name: Update Gosec Action Version
mode: agent
description: Update action.yml to use a provided gosec GHCR image version and open a pull request using the reusable gosec skill.
---

Use the skill Update Gosec Action Version from .github/skills/gosec-update-action-version/SKILL.md.

The skill updates `action.yml`, creates a branch and commit, and opens a pull request.

Use this input:

### gosec version
{{gosec_version}}
