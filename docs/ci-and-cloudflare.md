# CI/CD and Cloudflare Workers: security review guide

Checked: 2026-10-25. Recheck vendor advisories before every change.
This guide is generic. It is not exhaustive.

Use `agentic-security scan` and `agentic-security audit` for the metadata pass.
See [README.md](../README.md) for their coverage and limits. Audit requires explicit `--online` permission.

## npm publish path

1. Use trusted publishing with OIDC. It removes long-lived npm tokens. It needs npm CLI 11.5.1 or later and Node 22.14.0 or higher. Source: https://docs.npmjs.com/trusted-publishers/
2. Unvalidated trusted publisher configs expire after 48 hours. Complete a first publish to validate. Source: https://github.blog/changelog/2026-10-02-unvalidated-npm-trusted-publishing-configurations-now-expire/
3. npm rejects OIDC tokens from `issue_comment` and `pull_request_target` events. Publish from `push`, `release`, or `workflow_dispatch` instead.
4. If a token is necessary, use a granular write token. New write tokens cap at 90 days. Source: https://github.blog/changelog/2025-11-05-npm-security-update-classic-token-creation-disabled-and-granular-token-changes/

## Install-script policy

5. Check the npm version in CI. npm 12 blocks dependency install scripts by default. Source: https://docs.npmjs.com/cli/v12/commands/npm-install-scripts/
6. On npm 12, record approvals in the `allowScripts` field with `npm install-scripts approve <pkg>`. Set `strict-allow-scripts=true` in the CI .npmrc so unapproved scripts fail the build instead of warn.
7. Retain script restrictions. Never blanket-remove `ignore-scripts=true`. Keep it when no dependency needs a lifecycle script.
8. When a dependency needs a script, permit only that package for the manager and version in use. On npm 12, `approve` writes a pinned entry for the reviewed version. Older npm lacks this allowlist. Keep install scripts disabled; review and run necessary rebuilds for named packages in isolation.
9. Bun blocks lifecycle scripts by default. Use `trustedDependencies`; setting the field replaces the built-in list. Source: https://bun.com/docs/pm/lifecycle

## Workflow injection

10. Treat issue text, PR titles, and branch names as untrusted.
11. Never interpolate context values into shell commands. Pass them as environment variables. Source: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
12. Review workflow files for unexpected steps. The GhostAction campaign added fake security-audit workflows that stole secrets and mined git history (October 8, 2026): https://www.stepsecurity.io/blog/ghostaction-returns
13. Search for known bad filenames:

```bash
rg --files --hidden .github/workflows | rg '(^|/)(security-audit|github_actions_security)\.ya?ml$'
```

14. Treat filenames as indicators, not proof. Inspect workflow contents and runs for credential theft during the suspected compromise window.

## Action pins and forks

15. Pin actions to a full commit SHA. Verify the SHA is from the action repository, not a fork.
16. Consider workflow dependency lockfiles. They record exact commits for transitive actions.
17. Keep untrusted PR code away from privileged workflows. `pull_request_target` and `workflow_run` run with access to secrets and may have repository write access; they share the main-branch cache. GitHub treats both as privileged triggers.
18. For `workflow_run`, treat the triggering run's payload and downloaded artifacts as untrusted. Fork PRs can trigger it with attacker-controlled content. Never execute artifact contents or interpolate them into shell commands.
19. Give the GITHUB_TOKEN read-only by default. Raise permissions per job.
20. Do not run self-hosted runners on public repositories. Any user can open a PR and run code on the runner. Treat private pull requests as untrusted unless contributor permissions and approvals establish trust. Restrict secret exposure and isolate each job. Ephemeral teardown is not a guarantee; jobs can share a runner, and command-line secrets are visible to other processes.

## Worker bindings and secrets

21. Store secrets as secrets, not as vars. Source: https://developers.cloudflare.com/workers/configuration/secrets/
22. Set secrets with `wrangler secret put`. Use `wrangler versions secret put` for gradual deployments.
23. Keep `.dev.vars` out of git. Add it to .gitignore.
24. Never commit a secrets file. `--secrets-file` uploads at deploy time only.
25. Declare required secrets in the wrangler config. Deploy fails when a required secret is missing.
26. Consider Secrets Store for account-level secrets. It is in beta.

## Tenant authorization

27. Enforce authorization per tenant in route handlers. Do not rely on middleware alone. Next.js advisories warn about middleware auth bypasses: https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw
28. Do not trust a tenant id from the client. Derive it from the verified session.
29. Scope queries by tenant. A shared database needs a tenant key on every row.
30. See the OWASP multi-tenant security cheat sheet: https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html

## D1 and R2 access

31. D1 databases: use Time Travel for recovery. It is always on and restores to any minute within the retention window. Retention is plan-dependent: up to 30 days on the Workers Paid plan, 7 days on the Workers Free plan. Bookmarks older than the window are invalid. Source: https://developers.cloudflare.com/d1/reference/time-travel/
32. Check the storage subsystem with `wrangler d1 info <db>`. Databases with `version: production` support Time Travel; legacy alpha databases use snapshot backups only.
33. R2 buckets are private by default. Public access needs explicit permission. Source: https://developers.cloudflare.com/r2/buckets/public-buckets/
34. Use the r2.dev subdomain for development only. It is rate-limited.
35. Review every bucket access path before adding domain authentication. Protecting one hostname does not protect other public routes or S3 credentials.
36. Disable the r2.dev URL before production.

## SSRF

37. Prevent server-side request forgery. Do not fetch user-supplied URLs against internal services. Source: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
38. Validate and allowlist outbound URLs.
39. Keep internal endpoints off the public path. Use bindings, not HTTP.

## Redaction

40. Mask sensitive values in CI logs with `::add-mask::`.
41. Do not store structured data as a secret. It breaks redaction.
42. Revoke or rotate exposed credentials promptly. Preserve restricted, redacted evidence, then remove leaked public logs.

## Backups and preview cleanup

43. Test a database restore before you rely on it.
44. Preview environments must be ephemeral. Create per PR, delete after merge.
45. Give previews no write secrets.
46. Disable public r2.dev access on previews.
47. Clean up after merge: remove preview workers, buckets, and DNS.

## Scanner coverage vs manual review

48. Dependabot alerts cover registry advisories. They now support npm 12, pnpm 11 and 12, and Bun 1.4. Source: https://github.blog/changelog/2026-10-20-dependabot-now-supports-npm-12-pnpm-11-and-12-and-bun-1-4
49. This package checks selected workflow metadata. Other tools can analyze workflow logic; review privileged execution paths separately.
50. Separate automatic coverage from manual review in the report.
51. Check the license of third-party actions and scanners before use.

## Source gaps

52. CircleCI npm OIDC support: not verified here.
53. GhostAction victim counts vary by tracker. Use primary advisories.
