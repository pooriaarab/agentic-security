# npm publishing

The `publish.yml` workflow publishes from the `release` branch with npm trusted publishing.
It uses a GitHub-hosted runner, Node 24, and npm 11.5.1 or later.
Only the publish job receives `id-token: write`. The workflow passes no npm token.

Before enabling this workflow, configure the package's trusted publisher on npm:

- Provider: GitHub Actions
- Organization or user: `pooriaarab`
- Repository: `agentic-security`
- Workflow filename: `publish.yml`
- Environment name: `npm-release`
- Allowed actions: direct publication with `npm publish`

The workflow filename is case-sensitive. Enter the filename without its directory.
The environment must match the job's `environment` exactly.
The package's `repository.url` must match this GitHub repository.
A maintainer configures publisher settings and reviews the first real publication separately.

Publication jobs share the fixed `npm-agentic-security-publish` concurrency group.
A new run cannot cancel an active publication. GitHub keeps only one pending run by default.
The version guard runs inside this group and skips versions that npm already lists.
Registry failures, including 404, stop the job. Invalid version metadata also stops the job.
Only a valid, nonempty version list that omits the local version permits publication.
A failed publication fails the job. A rerun checks the registry again before publication.

Sources: [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/),
[GitHub concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency),
and [GitHub OIDC](https://docs.github.com/en/actions/concepts/security/openid-connect).
