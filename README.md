# agentic-security

[![npm version](https://img.shields.io/npm/v/agentic-security)](https://www.npmjs.com/package/agentic-security)
[![Downloads per month](https://img.shields.io/npm/dm/agentic-security)](https://www.npmjs.com/package/agentic-security)
[![MIT license](https://img.shields.io/npm/l/agentic-security)](LICENSE)
[![TypeScript types](https://img.shields.io/badge/TypeScript-types%20included-3178c6)](https://www.npmjs.com/package/agentic-security)

[Guides](https://github.com/pooriaarab/agentic-security/tree/main/docs) · [API](https://github.com/pooriaarab/agentic-security/blob/main/src/index.ts) · [Comparison](#compare-security-tools) · [Agent skill](https://github.com/pooriaarab/agentic-security/blob/main/skills/agentic-security/SKILL.md) · [MCP setup](https://github.com/pooriaarab/agentic-security/blob/main/.mcp.json) · [llms.txt](https://github.com/pooriaarab/agentic-security/blob/main/llms.txt)

agentic-security is an open-source Node.js security review toolkit for JavaScript projects and coding agents. It checks dependency metadata, agent workflows, and lockfile advisories. It provides a library, command-line interface (CLI), and Model Context Protocol (MCP) server.

## Install

```sh
npm install agentic-security
```

Requires Node.js 22 or later. The package includes TypeScript declarations. It has four runtime dependencies.

## Run your first scan

Run this command from a JavaScript project:

```sh
npx agentic-security@0.2.2 scan .
```

The command prints a JSON report. Check `complete: true` before using its findings. Offline scanning needs no credentials and sends no network requests.

To check current registry versions, add `--online`. This sends valid dependency names to the public npm registry. Names can reveal private packages.

```sh
npx agentic-security@0.2.2 scan . --online --fail-on high
```

## How it works

```text
Project files ──read-only scan──▶ Metadata findings
Lockfile ──explicit online audit──▶ Host npm or Bun ──▶ Advisory report
                                  ▲
                         Temporary lockfile copy
```

## Why agentic-security exists

`npm audit`, Bun audit, and OSV-Scanner focus on known dependency vulnerabilities. Agentic-security adds project metadata and workflow checks. Its audit command uses a trusted host-installed npm or Bun process on a reviewed lockfile copy.

The package reports checks and upgrade plans. It does not apply fixes or claim that a project is secure.

## Compare security tools

Checked on 2026-10-25 against each project's primary documentation.

| | agentic-security | npm audit | Bun audit | OSV-Scanner |
|---|---|---|---|---|
| Main scope | JavaScript metadata, workflows, and lockfile advisories | Known advisories for the project dependency tree | Known advisories from `bun.lock` | Known vulnerabilities across supported artifacts and manifests |
| Advisory source | Host npm or Bun audit command | Configured npm registry | npm advisory endpoint or scoped registry | OSV database |
| Change behavior | Read-only; plans version updates | `audit` reports; `audit fix` can change packages | `audit` reports; `audit fix` changes the lockfile and install | Scanner reports; remediation depends on workflow |
| Runtime | Node.js package; npm or Bun manager for lockfile audit | npm CLI | Bun CLI | Standalone CLI or Go library |
| Project checks beyond advisories | Manifests, lifecycle scripts, publish allowlists, and GitHub Actions | No agent workflow checks | No agent workflow checks | Vulnerability scanning focus |

See the [npm audit docs](https://docs.npmjs.com/cli/v12/commands/npm-audit/), [Bun audit docs](https://bun.com/docs/pm/cli/audit), and [OSV-Scanner docs](https://google.github.io/osv-scanner/).

## Checks and coverage

| Check | Source | Verification |
|---|---|---|
| Dependency names, ranges, and lifecycle scripts | Root and nested `package.json` files | Parsed locally; no scripts run |
| Lockfile and npm script policy hints | Root lockfile and `.npmrc` | Presence and policy text checked |
| Publish file list and GitHub Actions pins | `package.json` and workflow YAML | File-list presence and full commit SHA pattern checked |
| Known dependency advisories | Selected npm or text Bun lockfile | Host npm or Bun runs on a temporary copy when online permission is explicit |
| Current package releases | Public npm registry `latest` tags | Optional online lookup; compares declared range lower bounds |

These are source-level checks. The package has no vendor credential verification. Registry and manager responses are checked for valid report fields. `complete: false` means the result is incomplete and needs review.

## Common use cases

1. **Node.js maintainers.** Check workspace manifests and release allowlists before a package release.
2. **Coding-agent teams.** Scan workflow text for `pull_request_target` and actions without full commit SHA pins before an agent edits CI files.
3. **CI maintainers.** Produce JSON findings and set `--fail-on` to stop a scan on selected severities.
4. **Bun projects.** Audit a supported text `bun.lock` through the installed Bun CLI after explicit online permission.

## Features

- Scan package manifests and selected workflow risks. See the [security quick reference](https://github.com/pooriaarab/agentic-security/blob/main/docs/security-guide.md).
- Report missing lockfiles, npm script-policy hints, and missing publish file lists.
- Compare range lower bounds with npm `latest` tags. See [dependency and migration reviews](https://github.com/pooriaarab/agentic-security/blob/main/docs/dependencies-and-migrations.md).
- Audit npm and supported text Bun lockfiles. See the [audit contract](https://github.com/pooriaarab/agentic-security/blob/main/docs/auditing.md).
- Bound reads, traversal, network lookups, temporary files, and manager output.
- Return JSON reports with completion status and fixed error messages.
- Provide static dependency, runtime, and workflow guidance.

## Runtime surfaces

### CLI

```text
agentic-security --help
agentic-security scan [root] [--online] [--fail-on high|critical|any]
agentic-security audit [root] [--online] [--manager auto|npm|bun]
```

Both commands default to `.`. Scan is offline by default. Audit requires `--online` to invoke a package manager. `--fail-on` affects scan exit status; it does not filter findings. Scan exits with code 2 for incomplete results and code 1 for the selected severity threshold. Audit exits 2 for incomplete results and 1 when advisories exist.

### Library

```js
import { scan, audit, guidance } from 'agentic-security';

const report = await scan('.', { online: false });
console.log(report.complete, report.findings);
console.log(guidance);
```

`scan(root, { online?, registry? })` returns `schemaVersion`, `generatedAt`, `complete`, `manifests`, `findings`, `updates`, and `errors`. `audit(root, { online?, manager? })` returns `schemaVersion`, `complete`, `manager`, `advisories`, `errors`, and an optional `command`. `manager` accepts `auto`, `npm`, or `bun`.

### MCP server

Start the stdio server with:

```sh
npx --package agentic-security@0.2.2 agentic-security-mcp
```

It provides three tools: `security_scan` accepts `path` and `online`; `security_audit` accepts `path`, `online`, and `manager`; `security_guidance` returns static review guidance. Online audit defaults to false. Keep the server inside the workspace boundary set by your agent host.

### Configuration

The package does not load `.env` files or read configuration variables. Pass the root path and options to the library, CLI, or MCP tool. Online mode is an explicit request for registry access.

## Behavior limits

- Scan checks metadata and selected workflow text. It does not query vulnerability databases or inspect full lockfile dependency trees.
- Online scan compares declared range lower bounds with public npm `latest` tags. A newer version does not prove a vulnerability or a safe upgrade.
- Audit requires explicit online permission because dependency names may be disclosed to a registry.
- Audit supports npm lockfiles and text Bun lockfiles. Binary `bun.lockb`, Yarn, pnpm, ambiguous managers, and unrecognized sources return incomplete reports.
- Audit runs the host-installed npm or Bun command. Review the installed tool before granting permission.
- The package never runs project scripts, installs dependencies, changes project files, or applies fixes.
- Scan skips symlinks and `.git`, `node_modules`, `dist`, `build`, `.next`, `.secrets`, `coverage`, and `vendor`.
- Scan limits traversal to depth 32 and 10,000 entries. It limits dependencies to 5,000 and recorded errors to 100.
- Scan reads files up to 256 KiB each, with an 8 MiB total. Online lookup allows six requests at once.
- Each online lookup times out after five seconds. Responses stop at 256 KiB, and redirects fail.
- Audit rejects symlinks and changed roots. It limits lockfiles and each output stream to 8 MiB.
- Audit limits each manager run to 60 seconds. It removes the temporary audit directory after execution.
- Scanning a changing workspace is not a filesystem sandbox. Use a stable, trusted snapshot.
- Reports do not prove application security. Review findings against source files and primary advisories.

## Review guides

- [Dependency and migration reviews](https://github.com/pooriaarab/agentic-security/blob/main/docs/dependencies-and-migrations.md)
- [CI and Cloudflare Worker reviews](https://github.com/pooriaarab/agentic-security/blob/main/docs/ci-and-cloudflare.md)
- [Agent and MCP reviews](https://github.com/pooriaarab/agentic-security/blob/main/docs/agents-and-mcp.md)
- [Security quick reference](https://github.com/pooriaarab/agentic-security/blob/main/docs/security-guide.md)
- [Audit contract and limits](https://github.com/pooriaarab/agentic-security/blob/main/docs/auditing.md)
- [Agent skill](https://github.com/pooriaarab/agentic-security/blob/main/skills/agentic-security/SKILL.md)

## Status

Version 0.2.2 is a pre-1.0 release. Interfaces can change. Support and bug reports use the [GitHub issue tracker](https://github.com/pooriaarab/agentic-security/issues). Public case studies are not published.

## FAQ

**What does agentic-security check?**

agentic-security checks JavaScript package metadata, selected GitHub workflow risks, and supported lockfile advisories. It also offers optional version lookup against the npm registry.

**Which integrations are verified?**

agentic-security runs local parsing checks and validates npm or Bun audit output. It does not use vendor credentials or claim live service verification.

**Does agentic-security fix vulnerabilities?**

agentic-security reports findings and version plans. It does not change files, install packages, or apply upgrades.

**Does agentic-security provide managed security monitoring?**

agentic-security is a package you run in your environment. It has no managed service or hosted dashboard.

**How is agentic-security different from npm audit?**

agentic-security adds metadata and selected workflow checks around lockfile auditing. npm audit focuses on known vulnerabilities in the dependency tree and can apply changes with `npm audit fix`.

**How is agentic-security different from Bun audit?**

agentic-security checks additional package and workflow metadata. Its lockfile audit delegates to a host-installed Bun process when it selects a supported Bun lockfile.

**How is agentic-security different from OSV-Scanner?**

agentic-security focuses on JavaScript project metadata and npm or Bun lockfiles. OSV-Scanner connects supported project artifacts with vulnerabilities in the OSV database.

**Does online scanning upload source files?**

agentic-security does not upload source files. Online lookups send valid dependency names to a registry and can disclose private package names.

**What does an incomplete report mean?**

agentic-security sets `complete: false` when checks fail or reach a limit. Review the errors and do not treat an incomplete report as a clean result.

## License

MIT. See [LICENSE](https://github.com/pooriaarab/agentic-security/blob/main/LICENSE).
