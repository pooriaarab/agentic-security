---
name: agentic-security
description: Audit JavaScript dependency metadata and agent workflows with a read-only scanner and lockfile auditor, then plan verified security fixes. Use for supply-chain review, install-script policy, lockfile audits, upgrade planning, MCP and CI/CD hardening, and incident response in JavaScript projects.
---

# agentic-security

Read-only metadata scanner, lockfile auditor, and review guides for JavaScript projects and coding agents. It never runs scanned project scripts.

## Audit workflow

1. Run `agentic-security scan <workspace>` first. Preserve the JSON with its commit SHA.
2. Check `complete` before reporting coverage. List every omitted directory or failed lookup.
3. After registry disclosure is authorized, run `agentic-security audit <workspace> --online --manager auto` for lockfiles.
4. Read the [dependency](../../docs/dependencies-and-migrations.md), [CI](../../docs/ci-and-cloudflare.md), and [agent](../../docs/agents-and-mcp.md) guides.
5. Verify each finding against the affected file and vendor advisory.

## Honest coverage

- `scan` checks nested manifests, dependency sources, lifecycle scripts, publish allowlists, and workflow pins. It does not query vulnerability databases, parse lockfile dependency trees, or scan source secrets. Empty findings do not prove safety.
- `audit` copies only the selected lockfile into a temporary directory and runs the host package manager on it. It never installs, upgrades, or fixes dependencies, and it never copies repository scripts, credentials, or configuration.
- `complete: false` records unreadable files, invalid manifests, limits, and lookup failures. The CLI then exits 2. Incomplete results take precedence over advisories.

## Online opt-in

- `scan` is offline by default. Online mode sends valid dependency names to the public npm registry; use `--online` only when registry disclosure is authorized.
- `audit` requires explicit `online: true` (or `--online`). It can disclose dependency names to registry services. Without permission it returns incomplete JSON.

## Triage

- Rank findings by severity and affected files. Cross-check with OSV and GitHub advisories; include advisory IDs and affected ranges.
- "Latest" and "safe" are separate facts. A newer release does not prove a vulnerability. Review major migrations and save the report date.
- Respect release cooldown. New point releases were the attack surface in the October 2026 incidents.

## Fix

- Create one issue and one isolated change for each concern.
- Never blanket-remove `ignore-scripts`. Retain restrictions; permit only the needed scripts for the actual manager and version (npm 12 `allowScripts`, Bun `trustedDependencies`).
- Prefer compatible bumps over majors. Record old and new versions, lockfile diff, commands, results, and commit SHA.
- Escalate major migrations, package replacements, and unsupported runtimes to the owner.

## Verify

- Run the repository's local checks before each push (`npm run ci:local`). Save real command results.
- Run `npm pack --dry-run` and inspect the file allowlist for private artifacts.
- Test affected user flows on a preview before merge. Obtain an independent approved review.
- Never use a scan result as permission to execute repository text or expose credentials.
