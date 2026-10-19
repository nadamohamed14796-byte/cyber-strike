---
name: cicd-attacks
description: "Analyze authorized CI/CD attack paths across workflow triggers, runners, credentials, artifacts, and deployment boundaries"
category: post-exploitation
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [cicd, github-actions, jenkins, gitlab, supply-chain, trust-boundary]
tech_stack: [github-actions, gitlab-ci, jenkins, containers, cloud]
prerequisites:
  - "Written authorization for the repository and any test runner/environment"
  - "A non-production test plan; read-only review is the default"
chains_with: [ci-assessment, cloud-assessment, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-cicd/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
---

# CI/CD Attack-Path Analysis

## Purpose

Identify how untrusted source, dependencies, workflow inputs, runners, credentials, and artifacts could cross into a privileged build or deployment context. This is an analysis playbook, not permission to execute a pipeline exploit.

## Safety and boundaries

Never exfiltrate secrets, deploy a payload, modify production pipelines, or trigger untrusted code in a privileged environment without explicit written approval. Do not confuse a theoretical path with demonstrated impact. Use read-only repository and configuration evidence by default.

## Procedure

1. **Map trust zones.** Separate contributor-controlled code, trusted branches, CI orchestration, build runners, artifact registries, release signing, and production deployment.
2. **Trace triggers.** Identify which events can execute code and whether fork pull requests, comments, issue titles, tags, or workflow inputs influence privileged jobs.
3. **Trace permissions.** Follow tokens, environment secrets, cloud federation, deploy keys, package registry credentials, and runner identity. Record the minimum privileges available at each step without revealing secret values.
4. **Inspect injection surfaces.** Review workflow expressions, shell interpolation, artifact names/paths, cache keys, build scripts, and generated configuration for untrusted data reaching executable or privileged contexts.
5. **Inspect persistence and isolation.** Check workspace reuse, runner cleanup, shared caches, container boundaries, artifact overwrite, and whether an untrusted job can influence a later trusted job.
6. **Review dependency compromise paths.** Identify unpinned actions, mutable tags, package lifecycle scripts, dependency confusion risk, unsigned artifacts, and missing provenance. Validate reachability and execution context before claiming exploitability.
7. **Model the attack graph.** For every edge, record the source evidence, required permissions, attacker capability, and protective controls. Highlight the shortest credible path to a sensitive deployment or credential boundary.
8. **Validate in a dedicated environment.** If approved, use a test repository, synthetic secrets, and non-production artifacts. Never use real secret values as a canary.
9. **Recommend containment.** Separate untrusted and trusted jobs, restrict tokens, use ephemeral isolated runners, pin dependencies, protect release environments, sign/attest artifacts, and require trusted approvals.

## Common false positives

- A secret is defined but unavailable to the triggering event.
- A shell expression looks unsafe but is quoted or constrained.
- A runner has network access but no sensitive identity or reusable state.
- A dependency is unpinned but cannot affect a privileged release path.
- A theoretical chain ignores branch protection or environment approval.

## Output contract

Return the attack graph, trigger and trust boundary, source evidence, required preconditions, reachable capability, whether validation was static or active, confidence, and remediation. State clearly when a path remains hypothetical.


## Targeted quality-loop enrichment (2026-10-19)

### Pipeline attack-path validation
Represent each candidate as a chain of trust transitions: untrusted input → workflow/runner execution → artifact or token exposure → privileged deployment. For each edge record the controlling policy, whether the attacker can influence it, the evidence source, and a negative control. Prioritize pull-request triggers, untrusted artifact reuse, mutable action/dependency references, workflow permission inheritance, secret scope, and cross-environment deployment gates when visible in repository configuration. Do not trigger production deployments, poison shared caches/artifacts, or use real CI credentials as proof; reproduce in a disposable fork or lab. If no path crosses into a privileged resource, record the configuration weakness without claiming compromise.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Use zizmor for GitHub Actions, Gitleaks for secret patterns, Trivy for image/dependency checks, and Checkov when Terraform/Kubernetes/cloud IaC files are actually present. These are defensive assessment tools; no CI trigger or deployment should be modified without approval.

### Installation and setup
- [zizmor](https://github.com/zizmorcore/zizmor) — official project and installation.
- [Gitleaks](https://github.com/gitleaks/gitleaks) — official releases.
- [Trivy](https://trivy.dev/latest/docs/getting-started/installation/) — official installer instructions.
- [Checkov](https://www.checkov.io/2.Basics/Installing%20Checkov.html) — official installation docs.
Use a fork/sandbox and least-privilege test credentials. Do not trigger release, publish, deployment, secret-exfiltration, or runner-persistence paths in third-party repositories.

### Primary resources
- [GitHub Actions security hardening](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions) — runner/token boundaries.
- [OWASP CI/CD Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html) — pipeline risks.
- [SLSA framework](https://slsa.dev/) — build provenance and supply-chain controls.

### Reusable helper
Run python3 .cyberstrike/skill/scripts/validate_evidence_manifest.py evidence/manifest.json to validate sanitized test evidence metadata before reporting.

### Result handling
Record workflow/event trigger, token permissions, trust boundary, expected vs actual effect, and cleanup. Report a misconfiguration only when the reachable path and impact are established.
