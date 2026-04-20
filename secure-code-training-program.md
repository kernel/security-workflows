# Kernel Secure Code Training Program

**Program Type:** Continuous, automated, integrated into the software development lifecycle
**Delivery Method:** Automated tooling on every pull request + automated vulnerability remediation
**Coverage:** All engineering personnel (anyone contributing code)
**Effective Date:** 2025 (ongoing)

---

## Program Description

Kernel delivers secure code training continuously through automated security tooling integrated into every stage of the software development lifecycle. Rather than periodic classroom-style training that is quickly forgotten, Kernel engineers receive contextual security guidance at the exact moment they write code — when it is most actionable and educational.

Every pull request to Kernel's codebase is automatically analyzed by multiple security tools that identify vulnerabilities, explain why they are dangerous, and show the developer how to fix them. This creates a continuous feedback loop where developers learn secure coding practices through real examples in their own code, not abstract scenarios.

## Training Components

### 1. Static Analysis Security Testing (Semgrep)

Every pull request is scanned by Semgrep against industry-standard security rulesets:

- **OWASP Top Ten** (`p/owasp-top-ten`) — injection flaws, broken authentication, XSS, insecure deserialization, and other critical web application risks
- **Security Audit** (`p/security-audit`) — broad security anti-pattern detection
- **Secrets Detection** (`p/secrets`) — hardcoded credentials, API keys, tokens
- **Trail of Bits** (`p/trailofbits`) — advanced vulnerability patterns from security research
- **Language-specific rules** — Go, JavaScript, React, Python, and GitHub Actions rulesets

When a finding is detected, an AI-powered triage agent reads the affected source code, evaluates whether the finding is a true positive with real security impact, and posts an inline review comment directly on the pull request. Each comment includes:

- What the vulnerability is and why it is a true positive
- The relevant CWE or vulnerability class
- A recommended fix with a code snippet
- How to suppress the finding if it is an accepted risk

This teaches developers to recognize vulnerability patterns in context and understand remediation strategies specific to their codebase.

### 2. Supply Chain Security Analysis (Socket.dev)

Socket.dev analyzes every dependency change in every pull request for:

- Known vulnerabilities (CVEs) in direct and transitive dependencies
- Malicious packages and typosquatting attempts
- Risky package behaviors (install scripts, network access, filesystem access, obfuscated code)
- License compliance issues

Developers receive real-time feedback on the security posture of their dependency choices, teaching them to evaluate third-party code critically.

### 3. Automated Vulnerability Remediation

Kernel operates an automated vulnerability remediation pipeline that runs on a regular cadence:

1. **Scan** — Socket CLI scans all dependencies across Go and JavaScript ecosystems
2. **Triage** — An AI agent categorizes each alert as fixable, deferrable, or dismissible with documented reasoning
3. **Fix** — Fixable vulnerabilities are automatically patched, tests are run, and a pull request is opened
4. **Review** — The remediation PR includes a structured report showing what was fixed, what was deferred (with justification), and what was dismissed

This pipeline ensures vulnerabilities are addressed proactively and provides transparency into the decision-making process for every alert.

### 4. Architecture Security Review

Pull requests modifying backend services (Go API and metro-api packages) trigger an automated architecture review that evaluates:

- Adherence to established architectural patterns and security boundaries
- Proper use of authentication and authorization patterns
- Data flow security and input validation
- Concurrency safety and resource management

### 5. Weekly Dependency Upgrades

A weekly automated workflow upgrades all dependencies across the monorepo, ensuring the codebase stays current with security patches. This reduces the window of exposure to known vulnerabilities and teaches developers about the importance of dependency hygiene through the upgrade PRs they review.

## Evidence and Measurement

### Quantitative Evidence

- Number of Semgrep findings detected and remediated per quarter
- Number of Socket.dev alerts triaged and resolved per quarter
- Number of automated vulnerability remediation PRs merged
- Percentage of PRs that receive security review comments

### Qualitative Evidence

All training interactions are permanently recorded in GitHub pull request history:

- Inline security review comments with vulnerability explanations
- Socket.dev alerts with risk assessments
- Vulnerability remediation PRs with structured triage reports
- Architecture review feedback on security-relevant changes

### Repositories Covered

This program applies to all repositories in the Kernel GitHub organization, including:

- `kernel/kernel` — Core monorepo (API, metro-api, dashboard, database schema)
- `kernel/infra` — Infrastructure-as-code (Pulumi, Ansible)
- `kernel/security-workflows` — Shared security CI/CD workflows

## Comparison to Traditional Training

| Dimension | Traditional Training | Kernel's Program |
|---|---|---|
| Frequency | Annual or quarterly | Every pull request (daily) |
| Context | Generic examples | Developer's own code |
| Timeliness | After vulnerabilities ship | Before code merges |
| Retention | Low (forgotten within weeks) | High (learning at point of action) |
| Measurability | Completion certificates | PR history, finding counts, remediation rates |
| Coverage | Whoever attends | Every engineer who opens a PR |
| Adaptability | Static curriculum | Rules updated continuously by security community |

## Applicable Frameworks

This program satisfies secure code training requirements across:

- **SOC 2** — CC1.4 (Security Awareness), CC2.2 (Internal Communication)
- **ISO 27001** — A.7.2.2 (Information Security Awareness, Education and Training)
- **HIPAA** — §164.308(a)(5) (Security Awareness and Training)
- **NIST CSF** — PR.AT-1 (Awareness and Training)
- **PCI DSS** — Requirement 6.5 (Secure Coding Training)

## Scope and Exemptions

This program applies to all personnel who write, review, deploy, or maintain application source code or infrastructure-as-code in Kernel's production environment. Because training is delivered through automated tooling on pull requests, participation is inherent to the development workflow — anyone who opens a PR receives training.

Personnel whose roles do not involve software development or code access are exempt from this program:

| Role | Exemption Reason | Alternative Training |
|------|-----------------|---------------------|
| CEO | Non-engineering role; no code access | General security awareness training |
| COO / Product Operations | Non-engineering role; no code access | General security awareness training |
| Customer-facing roles (non-coding) | No access to source code repositories | General security awareness training |
| Contractors (non-engineering) | No access to source code repositories | General security awareness training |

Exempted personnel are still required to complete **general security awareness training** covering phishing, password hygiene, data handling, and incident reporting.

This exemption list is reviewed whenever personnel roles change or at the annual policy review cycle.

## Program Ownership

- **Program Owner:** Engineering Leadership
- **Tooling Maintained By:** Security Engineering
- **Contact:** security@kernel.sh
