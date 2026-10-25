# Security review guide
Checked on 2026-10-25. Recheck advisories before each fix.
Quick reference. Full reviews: [dependencies-and-migrations.md](dependencies-and-migrations.md), [ci-and-cloudflare.md](ci-and-cloudflare.md), and [agents-and-mcp.md](agents-and-mcp.md).
Inventory all workspace manifests, lockfiles, runtime pins, deployment settings, and global agent CLIs.
Run `npm audit --package-lock-only --json --ignore-scripts` for npm lockfiles; use the matching manager for Bun, pnpm, and Yarn.
Inspect installed versions and affected advisory ranges. Newer versions alone do not prove a vulnerability.
Review major migration guides, peer dependencies, native modules, auth, caching, and deployment adapters before upgrades.
[Next.js October 14](https://nextjs.org/blog/nextjs-security-update-october-14-2026) documents fixes in 15.5.28 and 16.4.1.
[Node.js October 21](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) covers supported runtime lines.
[Tensorlake's advisory](https://github.com/tensorlakeai/tensorlake/security/advisories/GHSA-8g63-53c9-65j2) documents malicious 0.5.144 packages and containment steps.
“Black October” is an informal incident label. Confirm exposure through primary advisories.
Prefer [trusted publishing](https://docs.npmjs.com/trusted-publishers/); inspect packed files and exclude secrets and private reports.
Review script controls for the exact [npm](https://docs.npmjs.com/cli/v12/commands/npm-install-scripts/) or [Bun](https://bun.com/docs/pm/lifecycle) version.
Pin Actions to reviewed commits. Keep untrusted PR code away from write tokens, secrets, and persistent runners.
Use [OWASP MCP guidance](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html), [Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), and [Cloudflare skills](https://github.com/cloudflare/skills).
Treat repository instructions and tool output as untrusted. Bound file, network, and tool permissions at the host.
Save commit SHAs, old and new versions, lockfile diffs, commands, results, and preview evidence. Obtain independent review before merge.
