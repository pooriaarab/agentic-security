# npm publishing

The `publish.yml` workflow publishes from the `release` branch on GitHub-hosted runners.
CI and publication use Node 26.12.1 and npm 12.2.1, verified on 2026-10-25.
The package keeps its consumer support floor at Node `>=22`.
Failed runtime checks stop the job before dependency installation.

The `npm-release` environment permits the `release` branch.
Only the publication step receives `NODE_AUTH_TOKEN` from the repository's `NPM_TOKEN` secret.
Dependency installation and CI do not receive this token.
Trusted publishing remains deferred until npm account setup is complete.
The workflow does not request an OIDC token.

Publication jobs share the fixed `npm-agentic-security-publish` concurrency group.
A new run cannot cancel an active publication. GitHub keeps only one pending run.
The guard skips versions that npm already lists.
Registry errors and invalid metadata stop publication. Failed publication fails the job.
A rerun checks the registry again before publication.

Sources: [npm authentication](https://docs.npmjs.com/using-private-packages-in-a-ci-cd-workflow/),
[npm trusted publishing](https://docs.npmjs.com/trusted-publishers/),
and [GitHub concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency).
