# agentic-security
Read-only security checks and dependency upgrade plans for JavaScript projects and coding agents.
```sh
npx agentic-security@0.1.0 scan .
npx agentic-security@0.1.0 scan . --online
npx agentic-security@0.1.0 scan . --fail-on high
npx --package agentic-security@0.1.0 agentic-security-mcp
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
This version does not query vulnerability databases, parse lockfile dependency trees, scan source secrets, or prove application security.
Use package-manager audits and the [review guide](docs/security-guide.md) for those tasks.
The scanner never runs project commands, installs packages, or changes files.
It skips symlinks and generated directories. Scan a stable, trusted snapshot; this process is not a filesystem sandbox. It limits traversal, file sizes, and network requests.
`complete: false` records unreadable files, invalid manifests, limits, and lookup failures. The CLI then exits with status 2.
## MCP
The dedicated server command is `npx --package agentic-security@0.1.0 agentic-security-mcp`.
Tools: `security_scan` accepts `path` and optional `online`; `security_guidance` returns review steps.
Keep the server inside the workspace boundary set by your agent host.
Use Node 22 or later. Run `npm ci --ignore-scripts`, then `npm run ci:local`.
MIT. Part of the [agentic suite](https://github.com/pooriaarab).
