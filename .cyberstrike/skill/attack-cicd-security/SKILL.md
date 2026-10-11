---
name: attack-cicd-security
description: "Review authorized CI/CD pipelines for exposed secrets, unsafe trust, and build-to-deploy privilege paths"
category: "supply-chain-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [cicd, supply-chain, github-actions, pipelines, secrets]
tech_stack: [github-actions, gitlab-ci, jenkins, containers, cloud]
prerequisites:
  - "Authorization for the repositories, runners, and deployment environment"
  - "Read-only repository/configuration access where possible"
chains_with: [attack-cloud-iam, attack-api-misconfig, attack-evidence-hygiene, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-cicd/SKILL.md"
---

# CI/CD Pipeline Security Review

## When to use

Use when reviewing source repositories, workflow files, build runners, artifact registries, deployment credentials, or trust between pull requests and release workflows.

## Safety gate

Stay within authorized repositories and environments. Prefer read-only configuration review. Do not trigger untrusted workflows, alter branch protections, exfiltrate secrets, deploy code, or modify production artifacts as a test unless specifically approved.

## Procedure

1. **Map the delivery path.** Document source repository, trigger events, runner type, build artifacts, registry, deployment identity, and production destination.
2. **Review workflow triggers.** Check pull-request, fork, tag, release, schedule, and manual triggers. Identify workflows that execute untrusted code with privileged tokens or secrets.
3. **Review permissions.** Inspect job-level token permissions, cloud role assumption, deploy keys, environment protections, and secret exposure. Prefer least privilege and short-lived credentials.
4. **Check dependency and action pinning.** Record whether third-party actions and build dependencies are pinned to immutable revisions and whether updates are reviewed.
5. **Review artifact integrity.** Check whether build outputs are trusted, signed where required, and promoted between environments without untrusted overwrite paths.
6. **Inspect runner isolation.** Determine whether self-hosted runners persist across jobs, process untrusted pull requests, or share credentials and workspaces.
7. **Trace privilege paths.** Explain how a contributor, compromised dependency, or untrusted workflow could reach a sensitive token or deployment boundary. Treat each step as a hypothesis until the configuration proves it.
8. **Validate safely.** Use policy review, static checks, or a dedicated test branch with no production secrets. Do not attempt secret extraction.
9. **Recommend controls.** Limit token permissions, isolate untrusted jobs, pin dependencies, protect environments, separate build and deploy identities, and audit artifacts.

## Pitfalls

- A secret name in YAML does not prove the secret is exposed.
- A public workflow file is not a vulnerability by itself.
- Self-hosted runners are not inherently unsafe; isolation and trust boundaries matter.
- Do not trigger real deployments to demonstrate a workflow weakness.

## Verification

Provide workflow path and line references, trigger conditions, permissions, trust boundary, reachable impact, and a safe validation result. Redact secret values and private infrastructure details.
