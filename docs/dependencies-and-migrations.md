# Dependencies and migrations: security review guide

Checked: 2026-10-25. Recheck vendor advisories before every change.
This guide is generic. It is not exhaustive.

Use `agentic-security scan` and `agentic-security audit` for the metadata pass.
See [README.md](../README.md) for their coverage and limits. Audit requires explicit `--online` permission.

## Scope

1. Inventory every version pin in the project. Include manifests, lockfiles, runtime engines, version files, CI images, containers, and local CLI toolchains.
2. Treat "latest" and "safe" as separate facts. Query the registry. Then check advisories. One does not imply the other.

## Inspection commands

3. Use inspection commands only. Do not pipe a script into a shell. Do not force an upgrade.
4. Run audits without dependency scripts:

```bash
npm audit --package-lock-only --json --ignore-scripts
bun audit --json                  # when the installed Bun supports it
npm ls --depth=0                  # direct dependencies
npm outdated --json               # available updates
bun outdated                      # Bun lockfiles
npm view <package> version        # current registry version
node --version && npm --version   # runtime and CLI in use
```

5. Use the package manager that owns the lockfile. npm, Bun, pnpm, and Yarn each record different metadata.
6. Record the default branch commit before you scan. Scan a clean snapshot, not a working tree with local edits.

## Pins and lockfiles

7. Commit lockfiles. They fix the installed tree. See https://docs.npmjs.com/cli/v12/configuring-npm/package-lock-json
8. Set exact versions for direct dependencies in manifests.
9. Document runtime pins: engines, version files, CI images.
10. Review every lockfile diff. A renamed dependency can hide a swap.

## Vulnerability status

11. Cross-check audit output with OSV and GitHub advisories.
12. Include advisory IDs and affected ranges in reports.
13. Audit tools can miss new malware. Advisories lag behind releases.
14. Provenance does not prove safety. A compromised workflow can publish malware through trusted publishing. See the October 2026 incidents: https://osv.dev/vulnerability/MAL-2026-17571 and https://github.com/tensorlakeai/tensorlake/security/advisories/GHSA-8g63-53c9-65j2

## Runtime and CLI updates

15. Patch the production runtime first. The Node.js project released security updates for the 22.x, 24.x, and 26.x lines on 2026-10-21. Patch versions: v22.23.4, v24.22.1, v26.12.1. One fix is a Brotli decoder out-of-bounds write that permits remote code execution (CVE-2026-111497). Source: https://nodejs.org/en/blog/vulnerability/october-2026-security-releases
16. Update local CLIs after the runtime. Inventory Node, Bun, npm, and any agent CLIs you run.
17. Verify binary paths and versions after every update.
18. Restart running agents in a separate maintenance step.

## Install-script policy

19. npm 12 blocks dependency install scripts by default. The `allowScripts` field in package.json records approved packages. Source: https://docs.npmjs.com/cli/v12/commands/npm-install-scripts/
20. Approve scripts deliberately, pinned to the reviewed version:

```bash
npm install-scripts ls
npm install-scripts approve <pkg>
```

21. Retain script restrictions where possible.
    Keep `ignore-scripts=true` when no dependency needs a lifecycle script.
    When scripts are necessary, permit only reviewed packages.
    On npm 12, `approve` writes a pinned `allowScripts` entry.
    Older npm lacks this allowlist.
    Keep install scripts disabled.
    Review and run necessary rebuilds for named packages in isolation.
    A blanket setting hides the skipped-scripts review list on npm 12.
22. Consider `strict-allow-scripts=true` to fail on unapproved scripts. Apply the project's reviewed policy in CI and developer environments.
23. Bun runs lifecycle scripts only for trusted packages. Use the `trustedDependencies` allowlist; setting the field replaces the default list. Source: https://bun.com/docs/pm/lifecycle
24. Approve file:, link:, and git: packages only when their reviewed lifecycle scripts must run. Name matches alone do not grant trust.

## Framework and peer dependencies

25. Check peer dependency ranges before major upgrades. Next.js and React ship advisories together.
26. Next.js released an out-of-band security update on 2026-10-14: v16.4.1 and v15.5.28. Fixes: RCE in `use cache` (GHSA-673q-mjm6-r5xr), SVG image RCE (CVE-2026-96889), Server Actions DoS (GHSA-p3m5-59mp-jv5r). Source: https://nextjs.org/blog/nextjs-security-update-october-14-2026
27. For the SVG image issue, keep the bundled sharp at 0.35.5 or later. That is the advisory workaround, not a recommendation.
28. Do not rely on middleware alone for authorization. Enforce auth in route handlers. The Next.js advisories state the same.
29. Review deprecated packages. Deprecation is registry metadata; it does not remove the package. Replace deprecated direct dependencies on a schedule.

## Release cooldown

30. Wait before adopting a fresh release. New point releases were the attack surface in the October 2026 incidents.
31. The malicious `tensorlake@0.5.144` and `@subql/common@5.8.3` versions shipped as ordinary updates. Both ran install or import-time code. Sources: https://github.com/tensorlakeai/tensorlake/security/advisories/GHSA-8g63-53c9-65j2 and https://osv.dev/vulnerability/MAL-2026-17571
32. Define a review window for new releases. A few days of ecosystem exposure surfaces reports before you adopt.
33. Keep the known-good version pinned during the window.

## Major upgrades: decision record

34. Record major upgrade decisions. One issue, one PR, one reason.
35. Write down: old and new versions, lockfile diff, commands, results, and commit SHA.
36. Escalate major migrations. Package replacements and unsupported runtimes need a human decision.

## Scanner coverage vs manual review

37. Advisory audits report known vulnerabilities. Other scanners can flag suspicious behavior through static analysis or heuristics.
38. Separate scanner output from manual review in the report.
39. List each tool's actual coverage. This package separates static metadata checks from package-manager advisory reports.
40. List what a human must review: new lifecycle scripts, renamed dependencies, fresh point releases, and peer conflicts.
41. Check the license of any third-party scanner before use. The agentic-security-scanner package uses the PolyForm Internal Use 1.0.0 license, not MIT. Source: https://www.npmjs.com/package/@clear-capabilities/agentic-security-scanner
42. Do not copy third-party checklists or code into this guide. Write original content.

## Source gaps

43. CircleCI npm OIDC support timeline: not verified here. Check the vendor docs before migrating.
44. GhostAction victim counts differ between trackers. Triage from primary advisories.
