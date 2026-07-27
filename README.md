# security-workflows

Reusable GitHub Actions workflows for vulnerability scanning and remediation across the Kernel org.

## Workflows

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

- `OPENAI_API_KEY` — for GPT-5.5 triage and remediation agents (Codex)
- `ADMIN_APP_ID` + `ADMIN_APP_PRIVATE_KEY` — GitHub App for write access
- `SOCKET_API_TOKEN` — Socket.dev API token
