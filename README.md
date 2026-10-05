# security-workflows

Reusable GitHub Actions workflows for vulnerability scanning and remediation across the Kernel org.

## Workflows

### `breakglass-merge.yml`

Merges an emergency PR without its required approval when an org member comments
`/breakglass <reason>`. The reason must contain at least 10 characters and is recorded
on the PR before merging. The GitHub App token is scoped to the calling repository;
the workflow never checks out PR code.

To merge a linear PR stack, comment on its **bottom PR**, targeting the repository's
default branch:

```
/breakglass --stack emergency fix spans these dependent PRs
```

Stack mode follows open PRs whose base branch is the preceding PR's head branch. It
validates the entire discovered stack before starting, then merges from bottom to
top into the default branch, retargeting each dependent PR after its parent merges.
Every PR gets the requester, reason, and stack order recorded before its merge.

Merge commits must be enabled: stack mode uses them to preserve the commits shared
with dependent branches. The ordinary single-PR command still prefers squash merging.
Stacks containing forks, non-member authors, drafts, cycles, or multiple dependents
on one branch are refused. A changed head or base, a merge conflict, or an API error
stops the operation and reports which PRs already merged. Merges are not rolled back;
a retargeted PR can remain pointed at the default branch. Resume from the first
remaining PR targeting the default branch after resolving the failure.

Existing callers matching the `/breakglass` prefix support both commands without
changes. Installation and App configuration are documented in
[kernel/infra](https://github.com/kernel/infra/blob/main/docs/breakglass.md).

Run the workflow boundary tests with `python3 -m unittest discover -s scripts`
(Python 3 and PyYAML required).

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

- `ANTHROPIC_API_KEY` — for the `semgrep.yml` triage agent (Claude Code)
- `CURSOR_API_KEY` — for the other fix/remediation agents (Cursor)
- `ADMIN_APP_ID` + `ADMIN_APP_PRIVATE_KEY` — GitHub App for write access
- `SOCKET_API_TOKEN` — Socket.dev API token

## Required variables

Consumer repos need these variables (set at org or repo level):

- `CLAUDE_CODE_PREFERRED_MODEL` — model for the `semgrep.yml` triage agent (Claude Code)
- `CURSOR_PREFERRED_MODEL` — model for the other Cursor agent invocations
