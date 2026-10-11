---
name: ci-assessment
description: READ-ONLY CI/CD pipeline security assessment for GitHub Actions, dependency security, and software supply chain
category: security-assessment
tags: [cicd, github-actions, supply-chain, dependency-security, branch-protection, secrets, pipeline-security]
tech_stack: [github, gh-cli]
cwe_ids: [CWE-94, CWE-78, CWE-269, CWE-311, CWE-502, CWE-829]
chains_with: [cicd-attacks, T1059.004, T1552.001]
prerequisites: []
version: "1.1.0"
---

# CI/CD Pipeline Security Assessment

READ-ONLY CI/CD security assessment using gh CLI and local filesystem inspection. No repositories, workflows, or configurations are modified. Focused on GitHub Actions but includes dependency and supply chain checks applicable to any CI platform.

## Prerequisites

1. **gh CLI installed and authenticated** — `gh auth status`
2. **Repository access** — read access to target repository
3. **For dependency_audit** — local checkout of the repository

```bash
# Quick prerequisite check
gh auth status          # verify GitHub auth
gh repo view OWNER/REPO # verify repo access
```

## Assessment Phases

### Phase 1 — GitHub Actions Workflow Security

| Check | Command | Risk |
|-------|---------|------|
| Dangerous triggers | `ci_audit github_actions_audit --repo OWNER/REPO` | pull_request_target, workflow_dispatch injection |
| Script injection | `ci_audit github_actions_audit --repo OWNER/REPO` | ${{ github.event.* }} in run blocks |
| Token permissions | `ci_audit github_permissions_audit --repo OWNER/REPO` | Missing or overly broad GITHUB_TOKEN scope |
| Action pinning | `ci_audit github_actions_pinning_audit --repo OWNER/REPO` | Unpinned third-party actions (tag poisoning) |

### Phase 2 — Secrets & Runner Security

| Check | Command | Risk |
|-------|---------|------|
| Secret leakage | `ci_audit github_secrets_exposure_audit --repo OWNER/REPO` | Secrets in logs, env dumps, artifacts |
| Self-hosted runners | `ci_audit github_runner_audit --repo OWNER/REPO` | Runner persistence, PR-triggered execution |

### Phase 3 — Repository Security

| Check | Command | Risk |
|-------|---------|------|
| Branch protection | `ci_audit github_branch_protection_audit --repo OWNER/REPO` | Missing reviews, force push, no status checks |

### Phase 4 — Dependency & Supply Chain

| Check | Command | Risk |
|-------|---------|------|
| Dependency security | `ci_audit dependency_audit --path /path/to/repo` | Unpinned deps, no lockfile, known vulns |
| Supply chain | `ci_audit supply_chain_audit --repo OWNER/REPO --path /path` | No Dependabot, missing CODEOWNERS, hardcoded tokens |

## Detection Scope

| Category | What We Check | What We Don't |
|----------|---------------|---------------|
| **Workflows** | Triggers, injection, permissions, pinning | Runtime behavior, actual secret values |
| **Secrets** | Exposure patterns in YAML | Actual secret content or rotation status |
| **Runners** | Self-hosted presence, risky triggers | Runner OS hardening, network isolation |
| **Branch Protection** | Rule configuration | Bypass via admin override audit trail |
| **Dependencies** | Versions, lockfiles, known CVEs | Transitive dependency behavior |
| **Supply Chain** | Automation config, CODEOWNERS | SBOM completeness, SLSA compliance level |

## Verification and False Positives

- This skill is read-only: do not edit workflows, open pull requests, publish artifacts, run pipeline jobs, or change repository settings during assessment.
- A dangerous workflow trigger or writable permission is a lead. Confirm the trigger source, token permissions, branch protection, runner trust, and whether an untrusted contributor can reach the risky step.
- Treat secret-name matches as leads, not proof of secret exposure. Do not print or upload real secrets; verify with metadata or an approved synthetic canary.
- Confirm dependency findings against the resolved package/version and lockfile. A package name in source without a reachable dependency is not sufficient evidence.
- Record repository, workflow path, event context, effective permissions, timestamps, and sanitized evidence. Do not copy private workflow logs or repository data into public files.

## Scope and Validation Notes

- Confirm repository, organization, workflow, runner, package registry, and cloud integration scope before reviewing settings. A linked repository or deployment target is not automatically authorized.
- Prefer read-only inspection of workflow permissions, branch protections, secrets configuration, dependency pinning, artifact provenance, and deployment gates.
- Distinguish a risky configuration from demonstrated impact. For example, an untrusted expression is a lead until the execution context and reachable privilege boundary are shown.
- Validate suspected workflow injection only in a designated test branch or fork with a harmless marker. Do not print real secrets, publish packages, deploy artifacts, or modify production workflows without explicit written permission.
- Save the minimal sanitized evidence needed: workflow path and line, triggering event, effective permissions, expected versus observed behavior, and timestamps. Redact tokens and private repository data.

## Program Reference

| Program | Focus | Tool |
|---------|-------|------|
| github_actions_audit | Trigger analysis, script injection | gh API |
| github_permissions_audit | GITHUB_TOKEN scope | gh API |
| github_actions_pinning_audit | SHA pinning vs tag references | gh API |
| github_secrets_exposure_audit | Secret leakage patterns | gh API |
| github_runner_audit | Self-hosted runner risks | gh API |
| github_branch_protection_audit | Protection rule analysis | gh API |
| dependency_audit | Lockfile, versions, npm audit | local + npm |
| supply_chain_audit | Dependabot, CODEOWNERS, .npmrc | gh API + local |

## Pipeline Trust-Boundary and Evidence Matrix

Map untrusted input to the exact workflow execution context before testing. Review event type, actor permissions, branch protections, runner trust, token scopes, artifact flow, and deployment environment.

| Boundary | Review | Proof standard |
|---|---|---|
| Pull request to workflow | event type and whether secrets are available | workflow/configuration evidence plus safe test branch |
| Expression to shell | untrusted values interpolated into commands | harmless marker in a disposable branch |
| Workflow token | default and job-level permissions | minimum permission that enables the demonstrated action |
| Artifact/cache | producer, consumer, trust and key scope | synthetic artifact marker crosses an unintended boundary |
| Runner to cloud | identity federation and audience/subject conditions | read-only trust-policy evidence or test identity |
| Build to deployment | approvals, environments, signing and provenance | test artifact path; no production deploy without approval |

Do not print real secrets, alter production workflows, publish packages, or deploy artifacts to validate a theoretical issue. A risky YAML pattern is a lead; establish the trigger, attacker-controlled input, execution identity, and reachable impact. Keep workflow logs sanitized and include commit/event context so the finding is reproducible.
