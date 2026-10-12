---
name: recon-gitlab-public-recon
description: "Inventory public GitLab projects, groups, package artifacts, CI configuration, and exposed metadata with ownership verification."
category: "recon"
version: "1.0.0"
author: "cyberstrike-official"
tags: [recon, GitLab, source-code, CI/CD, information-disclosure]
tech_stack: [GitLab, Git, HTTP, CI/CD]
chains_with: [attack-source-leak, attack-cicd, recon-methodology]
prerequisites:
  - "A confirmed organization namespace or public GitLab instance"
severity_boost:
  high: "A public artifact exposes a sensitive private asset or a verified active secret, confirmed without using the secret."
---

# GitLab Public Project Reconnaissance

## Objective

Discover public GitLab projects and artifacts associated with an organization, then identify source/configuration exposure that materially affects security. Public project visibility is not inherently a vulnerability; attribution and data sensitivity determine relevance.

## Methodology

### 1. Establish the namespace

Start with the organization's official GitLab group, known project links, developer documentation, and confirmed domains. Search public namespaces using domain and organization identifiers, but treat name matches as candidates until ownership is corroborated.

### 2. Inventory public projects and artifacts

Review project descriptions, default branches, tags/releases, package registries, container image metadata, wiki pages, issue attachments, snippets, and CI configuration. Record project URL, visibility, last activity, owner/group, and relevance. Use unauthenticated public interfaces or approved API access only.

### 3. Inspect high-value files and history

Prioritize deployment manifests, CI variables references, Dockerfiles, infrastructure-as-code, environment templates, configuration files, backup artifacts, and scripts that reveal trust boundaries. Review commit history where public and relevant; avoid cloning huge unrelated repositories or collecting private user data.

### 4. Analyze CI/CD trust boundaries

Look for untrusted merge-request code running with privileged runners, unsafe artifact exposure, overly broad token permissions, insecure deployment rules, and secrets printed in job logs. Configuration patterns are leads: establish whether the affected workflow is reachable and whether a real permission boundary is crossed.

### 5. Classify secret-like strings safely

Use local secret-scanning tools on the minimum relevant repository content. Treat matches as unverified candidates; redact immediately and do not authenticate to third-party services with discovered material. Determine likely type and location from context, and ask the owner to verify/revoke through their normal process.

### 6. Confirm impact and report

A report should identify the public asset, why it belongs to the organization, what non-public information or control gap is exposed, and the smallest sanitized proof. For a CI/CD issue, describe the trust relationship and permission consequence without triggering a deployment or modifying pipelines.

## What Constitutes a Finding

- A public repository or artifact unintentionally exposes non-public source, internal configuration, personal data, or secret material.
- A CI/CD configuration defect allows untrusted contributors or jobs to cross a meaningful deployment or privilege boundary.
- A repository name, public README, intentionally published SDK, public client identifier, or stale placeholder secret alone is not a vulnerability.

## Evidence Requirements

- Canonical project/group URL, public visibility evidence, and ownership rationale.
- Exact file path/commit or artifact location and a minimal redacted excerpt.
- For CI/CD, the relevant trust rule and resulting permission boundary.
- Secret values and private personal data must not be copied into the report; do not test a candidate secret.

## Tools

- GitLab public web UI and documented public API.
- Git for bounded repository/history inspection.
- Gitleaks or TruffleHog in local mode on authorized public content.
- YAML/CI linting and static review tools for pipeline configuration.
- jq/Python for metadata normalization and inventory export.

## Public GitLab Review Matrix

| Surface | Review question | Strong evidence | False positive |
|---|---|---|---|
| Group/project | Is the project actually attributable to the target? | Official links, group ownership, matching first-party references | Same-name user or organization |
| Repository files | Is non-public configuration exposed? | Sensitive internal details or secret material in context | Example/template with placeholders |
| Commit history | Was sensitive material committed publicly? | Specific commit and affected artifact with redacted proof | Revoked sample/test string |
| CI pipeline | Can untrusted code access privileged runner/secrets? | Concrete rule path and permission consequence | Runner exists but is isolated |
| Job logs | Are secrets or private data printed? | Redacted log line with clear sensitive context | Masked placeholder or benign build output |
| Packages/artifacts | Is a private build unintentionally public? | Identifiable internal artifact and sensitive contents | Intended public release |
| Container registry | Are images/config layers exposing private assets? | Minimal image metadata/layer proof | Public base image or normal package |
| Snippets/wiki/issues | Is sensitive content accidentally public? | Specific non-public data with provenance | Public documentation by design |

## Verification and False Positives

- Confirm ownership independently of project naming.
- Separate public source from private configuration and deploy-time secrets.
- Secret scanners produce false positives; do not validate by logging in or making privileged API calls.
- Public client-side configuration can be intended; assess what authority the value actually grants.
- Do not trigger CI pipelines, change settings, or attempt deployment as proof.

## References

- Source merged: [uphiago/recon-skills — recon/gitlab-public-recon/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/gitlab-public-recon/SKILL.md)
- [GitLab CI/CD Security](https://docs.gitlab.com/ci/security/)
- [GitLab REST API](https://docs.gitlab.com/api/)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
