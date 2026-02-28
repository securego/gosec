---
name: Update Supported Go Versions
mode: agent
description: Update gosec to the latest patch versions of the two latest Go major versions and open a pull request.
---

Use the skill Update Supported Go Versions from .github/skills/gosec-update-go-versions/SKILL.md.

Requirements:
- Use https://go.dev/doc/devel/release as source of truth for latest stable releases.
- Carefully find and update all places in the repository where active supported Go versions are configured or documented.
- Open a pull request with the required title and summary from the skill contract.
