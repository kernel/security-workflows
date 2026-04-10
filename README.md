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

- `CURSOR_API_KEY` — for the triage/fix agents
- `CURSOR_PREFERRED_MODEL` — model for agent invocations
- `ADMIN_APP_ID` + `ADMIN_APP_PRIVATE_KEY` — GitHub App for write access
- `SOCKET_API_TOKEN` — Socket.dev API token
