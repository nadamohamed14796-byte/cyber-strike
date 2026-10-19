---
name: recon-gitlab-public-recon
description: "Inventory public GitLab projects, groups, package artifacts, CI configuration, and exposed metadata with ownership verification."
category: "recon"
version: "1.0.0"
author: "cyberstrike-official"
tags: [recon, GitLab, source-code, CI/CD, information-disclosure]
tech_stack: [GitLab, Git, HTTP, CI/CD]
chains_with: [attack-source-leak, cicd-attacks, recon-methodology]
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

- GitLab documented public API and `glab` CLI where appropriate; do not depend on the web UI.
- `git`: bounded repository/history inspection for public repositories within the task's permitted scope.
- `gitleaks` or `trufflehog` in local mode on authorized public content.
- YAML/CI linters and static review tools for pipeline configuration.
- `jq` / Python: normalize metadata and export inventory.

Verify `git --version`, `jq --version`, and `glab --version` if installed. Official docs: https://docs.gitlab.com/ee/api/, https://docs.gitlab.com/editor_extensions/gitlab_cli/, https://github.com/gitleaks/gitleaks/.

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


## Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. there is no fixed hypothesis-count ceiling; continue distinct, decision-relevant hypotheses while authorized, and stop when evidence or a real safety/policy boundary resolves the branch. Prefer passive sources first, deduplicate candidates, and use active checks only when the asset and activity are explicitly in scope.

### Evidence record and confidence

For each candidate, preserve normalized asset, source/provenance, observation time, scope proof, resolver/HTTP/tool and relevant version, raw-evidence location, corroborating source, negative control, attribution confidence, next action, and related-skill trigger. Separate **asset confidence** (is it related to the organization?) from **security confidence** (is a vulnerability demonstrated?).

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. C1/C2 are not confirmed vulnerabilities.

### Skill-specific next steps

1. Confirm the GitLab host and organization/group attribution through first-party domains, verified group ownership, or repository metadata; a matching brand string alone is insufficient.
2. Use read-only public metadata and bounded pagination to inventory public projects, snippets, package/container registries, CI configuration, and release artifacts that are explicitly in scope.
3. Distinguish public-by-design content from accidental exposure; inspect a minimal file/commit context and avoid cloning unrelated projects or collecting private contributor data.
4. If a secret-shaped value appears, record detector type, project, path, and commit without copying it. Only verify validity through a single read-only identity call if explicit authorization allows it.
5. Return provenance, deduplication key, last-seen commit/time, ownership confidence, and safe next-step trigger. Do not treat a public project, open signup, or a code fingerprint as a vulnerability by itself.


### Deduplication and stop rules

Normalize case, trailing dots, scheme/port, redirects, canonical names and resolved addresses before deduplication. Detect wildcard DNS, shared hosting, CDN/edge responses, soft-404s and stale records before ranking counts. Stop on exclusions, ownership ambiguity, unexpected sensitive data, throttling, instability or boundaries requiring further permission. Never claim ownership or register dangling resources.

### Handoff format

Return candidates with scope/provenance, confidence level, evidence path, deduplication key, negative control, priority rationale, safe next step and trigger for any linked attack skill. Promote a candidate to active testing only after scope and attribution are confirmed; promote it to a finding only after the relevant attack skill verifies the security boundary.

## References

- Source merged: [uphiago/recon-skills — recon/gitlab-public-recon/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/gitlab-public-recon/SKILL.md)
- [GitLab CI/CD Security](https://docs.gitlab.com/ci/security/)
- [GitLab REST API](https://docs.gitlab.com/api/)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)


## Targeted quality-loop enrichment (2026-10-19)

### Repository attribution and secret-safe handling
Confirm namespace/organization attribution and public visibility before pivoting through group projects, forks, issue attachments, packages, snippets, build artifacts, and commit history. Preserve repository URL, commit hash, path/line, observed time, and whether the content is current, deleted, forked, or generated. Secret-like matches must be recorded as type plus redacted fingerprint; do not test or reuse credentials or access projects beyond what is public and authorized. Distinguish public code disclosure from an exploitable credential or CI trust boundary. Route workflow/runner problems to CI/CD review, first-party JavaScript to JS analysis, and secret candidates to evidence-safe triage without invoking them.


## Agent-executable CLI tooling, resources, and helper scripts

Use agent-executable CLI tools and local scripts; browser interfaces, extensions, and interactive intercepting proxies are not dependencies. Check tool presence/version and official documentation before running it; only process data the operator is authorized to inspect.

### Recommended tools
- gitleaks — scan local checked-out repositories
- GitHub/GitLab native CLI or API client for public metadata where authorized
- git — inspect history and repository metadata
- jq/rg — normalize matches and redact sensitive values

### Resources
- https://github.com/gitleaks/gitleaks
- https://docs.gitlab.com/cli/
- https://git-scm.com/docs
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids; verify project maintenance, license, and supported behavior from official sources.

### Helper-script contract
Collect repository URL, commit/hash, path, detector, and redacted fingerprint. Do not test leaked credentials or access private repositories without explicit permission.

Keep raw artifacts separate from normalized output. Preserve provenance, timestamp, tool/version, detector/rule, error state, confidence, redaction, and evidence path. Use JSON/JSONL when useful and test redaction on local fixtures.

### Handoff
Return actual commands and versions, inputs/outputs, records processed, redaction status, errors, confidence, limitations, and next skill. Never include live secrets in notes or reports.
