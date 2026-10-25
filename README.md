# agentic-security
Read-only security checks and dependency upgrade plans for JavaScript projects and coding agents.
```sh
npx agentic-security@0.2.0 scan .
npx agentic-security@0.2.0 scan . --online
npx agentic-security@0.2.0 scan . --fail-on high
npx --package agentic-security@0.2.0 agentic-security-mcp
```
```js
import { scan } from 'agentic-security';
const report = await scan('.', { online: false });
console.log(report.complete, report.findings);
```

- Nested `package.json` files, dependency sources, and lifecycle scripts.
- Root lockfile presence and npm script policy hints.
- Publish file allowlists and GitHub action commit pins.
- Privileged `pull_request_target` workflows that need review.
- Optional registry lookups with patch, minor, and major upgrade plans.
Online mode sends valid dependency names to the public npm registry. This can include private package names.
It compares declared range lower bounds with the registry's current `latest` tag. It does not inspect installed versions.
A newer release does not prove a vulnerability. Review major migrations and save the report date.
## Limits
The scan command does not query vulnerability databases or parse lockfile dependency trees. Neither command scans source secrets or proves application security.
Use package-manager audits and the [review guide](docs/security-guide.md) for those tasks.
The scanner never runs project commands, installs packages, or changes files.
It skips symlinks and generated directories. Scan a stable, trusted snapshot; this process is not a filesystem sandbox. It limits traversal, file sizes, and network requests.
`complete: false` records unreadable files, invalid manifests, limits, and lookup failures. The CLI then exits with status 2.
## Lockfile audit
```sh
agentic-security audit . --online --manager auto
```
```js
import { audit } from 'agentic-security';
const report = await audit('.', { online: true, manager: 'auto' });
```
Audit requires explicit `online: true` permission. It can disclose dependency names to registry services.
Without permission, it returns incomplete JSON. CLI exit codes are 0 for clean, 1 for advisories, and 2 for incomplete results.
Incomplete results take precedence over advisories.
Auto selection checks `bun.lock`, then `bun.lockb`, then `npm-shrinkwrap.json`, then `package-lock.json`.
A detected binary Bun lock returns an unsupported-format report.
Multiple managers, unsupported lockfiles, final root symlinks, and invalid files cause incomplete results.
Binary `bun.lockb` files require a reviewed conversion to text before auditing.
Nondefault registry URLs, tarball sources, and unrecognized sources require review before any manager runs.
Funding URLs and bounded local workspace or file links do not select audit registries.
Absolute local paths, parent traversal, and encoded paths require review. Local targets are never copied into the audit directory.
Use a stable repository snapshot. Identity checks do not provide a filesystem sandbox against concurrent changes.
Files must be regular files, opened without following symlinks, and at most 8 MiB.
Audit copies only the selected lockfile into a temporary directory. It generates a minimal private manifest and empty npm config.
It never copies repository scripts, credentials, or configuration. It removes temporary files after execution.
The child environment contains only host process essentials. Package manager settings and authentication variables are excluded.
Audit runs trusted host-installed `npm` or `bun` without a shell. It never installs, upgrades, or fixes dependencies.
Each command has a 60-second timeout and an 8 MiB output limit.
Npm receives `--package-lock-only --ignore-scripts --json --registry=https://registry.npmjs.org` and explicit empty user and global config paths.
Bun receives `audit --json`. Bun's host manager and global policy remain a trust boundary; review them before granting online permission.
Reports contain `schemaVersion: 1`, `complete`, `manager`, `advisories`, `errors`, and an optional `command`.
Advisories contain validated package names, severity, ranges, and optional GHSA identifiers and URLs.
Raw tool output, titles, and error details are excluded. Malformed output and tool failures produce fixed error messages.

## Review guides
- [Dependencies and migrations](docs/dependencies-and-migrations.md)
- [CI/CD and Cloudflare Workers](docs/ci-and-cloudflare.md)
- [Agents and MCP](docs/agents-and-mcp.md)
- [Quick reference](docs/security-guide.md)
- [Agent skill](skills/agentic-security/SKILL.md)

## MCP
The dedicated server command is `npx --package agentic-security@0.2.0 agentic-security-mcp`.
Tools: `security_scan` accepts `path` and optional `online`; `security_guidance` returns review steps.
`security_audit` accepts `path`, `online` (default false), and `manager` (`auto`, `npm`, or `bun`).
Keep the server inside the workspace boundary set by your agent host.
Use Node 22 or later. Run `npm ci --ignore-scripts`, then `npm run ci:local`.
MIT. Part of the [agentic suite](https://github.com/pooriaarab).
