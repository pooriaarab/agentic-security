# Lockfile audit contract

The `audit` command checks a supported lockfile with an installed npm or Bun command. It needs `--online` because the manager contacts an advisory service. Dependency names can leave the machine.

## Lockfile selection

`--manager auto` selects `bun.lock`, then `bun.lockb`, then `npm-shrinkwrap.json`, then `package-lock.json`. A selected binary `bun.lockb` file returns an incomplete report. Explicit `npm` and `bun` selections need a matching supported lockfile.

Yarn and pnpm lockfiles are unsupported. A project with both npm and Bun lockfiles is ambiguous. These cases return incomplete results.

## Source checks

The audit checks that the project root and selected lockfile are regular files with stable identities. It rejects symlinks, changed roots, invalid formats, lockfiles larger than 8 MiB, and more than 100,000 npm dependency entries.

Npm lockfile sources must use `https://registry.npmjs.org`. Nonempty Bun source URLs must use HTTPS and the npm registry. Bounded workspace and file links are allowed. Funding metadata does not affect registry checks. Absolute paths, parent traversal, custom registries, and other source types need review.

The audit copies only the selected lockfile to a temporary directory. It creates a minimal private `package.json` and empty npm user and global config files. It does not copy project scripts, credentials, or configuration.

The child process receives only host essentials such as `PATH`, `HOME`, and temporary directory variables. It does not receive npm configuration or authentication variables. It runs without a shell, with a 60-second timeout and an 8 MiB limit per output stream. Temporary files are removed after the command.

Npm runs `audit --package-lock-only --ignore-scripts --json --registry=https://registry.npmjs.org` with explicit empty user and global config paths. Bun runs `audit --json`. Bun's installed version and global policy remain part of the trust boundary.

## Report and exit status

Reports contain `schemaVersion`, `complete`, `manager`, `advisories`, and `errors`. A successful report may also contain the redacted `command` argument list. Advisory entries contain a validated package name, severity, affected range, and optional GitHub Security Advisory ID and URL.

Raw tool output, advisory titles, and error details are not returned. Malformed reports and tool failures produce fixed error messages. Incomplete results take precedence over advisories. The CLI exits 0 for complete reports without advisories, 1 when advisories exist, and 2 when the report is incomplete.

## Limits

The audit delegates vulnerability matching to host npm or Bun. It does not install, upgrade, or fix dependencies. It does not prove application security or defend against every concurrent filesystem change. Use a stable, trusted snapshot and inspect the resulting report.
