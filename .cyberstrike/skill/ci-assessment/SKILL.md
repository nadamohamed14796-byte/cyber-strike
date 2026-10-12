---
name: ci-assessment
description: "Read-only assessment of CI/CD configuration, dependency integrity, runner isolation, and software supply-chain trust"
category: security-assessment
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [cicd, github-actions, supply-chain, dependencies, runners, secrets]
tech_stack: [github-actions, gitlab-ci, jenkins, containers, package-registries]
prerequisites:
  - "Authorization for the repositories, workflow files, runners, and deployment environments"
  - "Read-only source/configuration access where possible"
chains_with: [cicd-attacks, cloud-assessment, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-cicd/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
---

# CI/CD Security Assessment

## Objective

Review the path from source commit to build artifact and deployment for excessive trust, secret exposure, dependency tampering, and unsafe automation. This skill is read-only by default; active pipeline tests require explicit approval.

## Safety gates

Do not trigger untrusted workflows, alter branch protections, access secret values, deploy code, or modify production artifacts. Use configuration review and static analysis first. A public workflow file or secret reference is not itself a vulnerability.

## Procedure

### 1. Map the delivery chain

Record repository, workflow triggers, runner type, dependency sources, build outputs, artifact registry, deployment identity, environment gates, and production destination.

### 2. Review trigger trust

Inspect pull-request, fork, tag, release, schedule, manual, and issue/comment triggers. Identify workflows that execute untrusted contributions with write-capable tokens, secrets, or persistent self-hosted runners.

### 3. Review permissions and credentials

Check job-level token permissions, deploy keys, cloud role assumption, environment protection, secret scoping, credential lifetime, and whether untrusted jobs can reach privileged jobs. Do not print or extract secret values.

### 4. Check action and dependency integrity

Record whether third-party actions and dependencies are pinned to immutable revisions, whether package versions are locked, whether provenance/signatures are verified, and whether dependency updates are reviewed. Distinguish an outdated dependency from a reachable exploitable path.

### 5. Review runner and artifact isolation

Check whether self-hosted runners persist state across jobs, process untrusted code, share credentials/workspaces, or allow artifact overwrite. Verify that release artifacts are built from trusted commits and promoted through controlled environments.

### 6. Trace privilege paths

Model contributor or dependency → workflow trigger → token/runner permissions → artifact/deploy step → protected resource. Each edge needs configuration evidence. Do not attempt secret exfiltration to prove the chain.

### 7. Validate safely

Use static workflow analysis, policy checks, repository settings, and approved test branches without production secrets. Any active test should use a dedicated test repository/environment and be approved in advance.

### 8. Recommend remediation

Use least-privilege tokens, immutable action pins, isolated ephemeral runners, protected environments, separate build/deploy identities, artifact attestations, dependency review, and explicit trust boundaries between forked code and privileged workflows.

## Common false positives

- A workflow references a secret but the job cannot access it.
- A broad permission is constrained by a separate environment or organization policy.
- A self-hosted runner is isolated and ephemeral.
- An unpinned dependency exists but is not executed in a privileged path.
- A theoretical workflow injection has no attacker-controlled input reaching an executable context.

## Output contract

Return repository/workflow path, trigger, permissions, runner type, trust boundary, evidence lines, reachable impact, confidence, and remediation. Redact all secret values and private infrastructure details.
