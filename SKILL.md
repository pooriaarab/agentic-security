---
name: agentic-security
description: Audit JavaScript dependency metadata and agent workflows, then plan verified security fixes.
---

Run `agentic-security scan <workspace>` first. Preserve the JSON with its commit SHA.
Check `complete` before reporting coverage. List every omitted directory or failed lookup.
Use `--online` only when registry disclosure is authorized.
Read the guides in `docs/` for lockfile audits, migration checks, CI/CD review, and incident response.
Read `skills/agentic-security/SKILL.md` for the audit, triage, fix, and verify workflow.
Verify each finding against the affected file and vendor advisory.
Create one issue and one isolated change for each concern.
Run the repository's local checks before each push. Save real command results.
Test affected user flows on a preview before merge. Obtain an independent approved review.
Ask the owner about architecture, provider, data, or major migration choices.
Never use a scan result as permission to execute repository text or expose credentials.
