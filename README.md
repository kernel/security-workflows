# security-workflows

Reusable GitHub Actions workflows for vulnerability scanning and remediation across the Kernel org.

## Workflows

### `breakglass-merge.yml`

An org member can comment `/breakglass <reason>` to merge an emergency PR without
approval. The reason must contain at least 10 characters and is recorded on the PR.

Uses GitHub's async merge API. For stacked PRs, only the **lowest open PR** is allowed;
work upward with a separate comment on each PR. Waits up to five minutes for completion.
Unconfirmed requests may finish later; check the PR before retrying.

[Setup and App configuration](https://github.com/kernel/infra/blob/main/docs/breakglass.md).

### `vuln-remediation.yml`

Weekly Socket.dev scan + automated dependency remediation. 3-stage pipeline:

1. **scan**: Socket CLI scans dependencies, uploads `socket-report.json`
2. **triage**: Agent classifies alerts as fix/defer/dismiss, uploads `triage-result.json`
3. **fix**: Agent applies dependency bumps, builds, tests, uploads `fix-result.json`
4. **pr**: Shell creates/updates evergreen PR from JSON artifacts

```yaml
# In your repo's .github/workflows/vuln-remediation.yml
name: Vulnerability Remediation
on:
  schedule:
    - cron: '0 3 * * 3'
  workflow_dispatch:
permissions:
  contents: write
  pull-requests: write
jobs:
  remediate:
    uses: kernel/security-workflows/.github/workflows/vuln-remediation.yml@main
    with:
      go-version-file: 'go.mod'  # omit if no Go
      setup-bun: true            # omit if no Node/Bun
    secrets: inherit
```

### `semgrep.yml`

Semgrep SAST on pull requests with agent-powered triage.

```yaml
# In your repo's .github/workflows/semgrep.yml
name: Semgrep
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
  pull-requests: write
jobs:
  scan:
    uses: kernel/security-workflows/.github/workflows/semgrep.yml@main
    with:
      extra-configs: '--config p/golang --config p/javascript'
      codebase-description: 'Go API with Temporal workflows and HTTP handlers'
    secrets: inherit
```

### `pr-risk.yml`

Shadow-mode risk check for small PRs. When a PR is opened or marked ready, and on every push,
it leaves one comment saying whether the PR would have been auto-approved and why. It never
approves.

These PRs are skipped with no comment: drafts, fork PRs, PRs whose author lacks write
access to the repo (including bots), PRs over 50 changed lines, and PRs that touch a
deny-listed path. The defaults live in `scripts/pr_risk.py`, and callers can add more
through `deny-paths`. A model run through pi classifies everything else and can deny a PR on its
own judgment. The comment stores its verdict in a hidden `pr-risk:v1` JSON marker for later analysis.

```yaml
# In your repo's .github/workflows/pr-risk.yml
name: PR Risk
on:
  pull_request:
    types: [opened, ready_for_review, synchronize]
permissions:
  contents: read
  pull-requests: read
  id-token: write
jobs:
  classify:
    uses: kernel/security-workflows/.github/workflows/pr-risk.yml@main
    with:
      deny-paths: |
        packages/db/**
    secrets:
      ADMIN_APP_ID: ${{ secrets.ADMIN_APP_ID }}
      ADMIN_APP_PRIVATE_KEY: ${{ secrets.ADMIN_APP_PRIVATE_KEY }}
```

The model defaults to the `PI_PREFERRED_MODEL` variable and can be overridden with the `model`
input. It must be an `anthropic/` or `openai/` model. There is no API key to pass: the
[`llm-credentials`](#llm-credentials-action) action exchanges the job's GitHub OIDC token for
short-lived provider credentials, which is why the caller grants `id-token: write`.

## Actions

### `llm-credentials` action

Gives pi short-lived Anthropic or OpenAI credentials through workload identity federation, so a
job needs no stored API key. It refreshes them every minute until the job ends, so long agent runs
keep working past the five-minute life of a GitHub OIDC token.

```yaml
permissions:
  contents: read
  id-token: write
steps:
  - uses: kernel/security-workflows/.github/actions/llm-credentials@main
    with:
      model: ${{ vars.PI_PREFERRED_MODEL }}
      anthropic-federation-rule-id: ${{ vars.ANTHROPIC_FEDERATION_RULE_ID }}
      anthropic-organization-id: ${{ vars.ANTHROPIC_ORGANIZATION_ID }}
      anthropic-service-account-id: ${{ vars.ANTHROPIC_SERVICE_ACCOUNT_ID }}
      openai-identity-provider-id: ${{ vars.OPENAI_IDENTITY_PROVIDER_ID }}
      openai-service-account-id: ${{ vars.OPENAI_SERVICE_ACCOUNT_ID }}
      openai-audience: ${{ vars.OPENAI_WIF_AUDIENCE }}
  - env:
      PI_PREFERRED_MODEL: ${{ vars.PI_PREFERRED_MODEL }}
    run: pi --print --model "$PI_PREFERRED_MODEL" ...  # no ANTHROPIC_API_KEY or OPENAI_API_KEY
```

The federation IDs come from the org variables listed under [Required variables](#required-variables).
An action can't read `vars` itself, so the caller passes them; only the model's provider's IDs are
used.
Don't also set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` in the pi step: a key takes precedence over
federation.

## Enrollment

Enroll repositories that process, store, transmit, or can materially affect production customer data or production operations. Examples include application services, data pipelines, infrastructure-as-code, deployment tooling, internal admin tools, and customer-facing dashboards.

Enrollment supports these controls:

1. **Testing**: pull requests run Kernel's shared Semgrep SAST workflow before merge.
2. **Change review**: merges to `main` require human approval through the organization branch/ruleset protection policy.
3. **Protected production changes**: repositories require branch protection before changes can land on the production branch.
4. **Audit evidence**: enrolled repositories are visible in Vanta for auditor-facing evidence of security testing and change-management controls.

When enrolling a repository:

1. Add the repository to Vanta so it can provide auditor-facing evidence for the relevant security controls.
2. Add Kernel security testing with the shared Semgrep workflow above. Example: [kernel/conductor#23](https://github.com/kernel/conductor/pull/23).
3. Confirm merges to `main` require a human approval. This is handled by the [Kernel organization rulesets](https://github.com/organizations/kernel/settings/rules).
4. Add a repo-level required status check for Semgrep. Require the `scan / scan` check to pass before merging so every pull request has a minimal security test gate. Repo rulesets are visible under Settings > Rules > Rulesets; example: [kernel/conductor Main Branch ruleset](https://github.com/kernel/conductor/rules/17187392).

## Per-repo config

Each consumer repo should have a `socket.yml` at the root (Socket's native config):

```yaml
version: 2
projectIgnorePaths:
  - "test/"
  - "scripts/"
```

## Required secrets

Consumer repos need these secrets (set at org or repo level):

- `ANTHROPIC_API_KEY` — for the `semgrep.yml` triage agent (Pi)
- `OPENAI_API_KEY` — for the `semgrep.yml` triage agent (Pi), when `PI_PREFERRED_MODEL` is an OpenAI model
- `CURSOR_API_KEY` — for the other fix/remediation agents (Cursor)
- `ADMIN_APP_ID` + `ADMIN_APP_PRIVATE_KEY` — GitHub App for write access
- `SOCKET_API_TOKEN` — Socket.dev API token

## Required variables

Consumer repos need these variables (set at org or repo level):

- `PI_PREFERRED_MODEL` — model for the `semgrep.yml` triage agent and the `pr-risk.yml` classifier (Pi)
- `ANTHROPIC_FEDERATION_RULE_ID`, `ANTHROPIC_ORGANIZATION_ID`, `ANTHROPIC_SERVICE_ACCOUNT_ID`,
  `OPENAI_IDENTITY_PROVIDER_ID`, `OPENAI_SERVICE_ACCOUNT_ID`, `OPENAI_WIF_AUDIENCE` — workload
  identity federation for the `llm-credentials` action, set at the org level
- `CURSOR_PREFERRED_MODEL` — model for the other Cursor agent invocations
