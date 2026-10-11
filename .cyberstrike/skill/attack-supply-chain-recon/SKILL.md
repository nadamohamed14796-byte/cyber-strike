---
name: attack-supply-chain-recon
description: "Map authorized software supply-chain trust boundaries and exposed build/dependency risks"
category: "supply-chain-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [supply-chain, dependencies, packages, ci-cd, provenance]
tech_stack: [git, package-managers, ci-cd, containers]
prerequisites:
  - "Authorization for repositories, packages, and build infrastructure in scope"
  - "Read-only source access and an agreed boundary for third-party services"
chains_with: [attack-cicd-security, attack-cloud-iam, attack-source-leak, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/supply-chain-attack-recon/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/redteam/supply-chain-attack-recon/SKILL.md"
---

# Software Supply-Chain Reconnaissance

## When to use

Use when reviewing package dependencies, source-control permissions, build workflows, release artifacts, registries, update channels, or third-party integrations in an authorized engagement.

## Safety gate

Use read-only review by default. Do not publish packages, alter releases, poison dependencies, access private registries outside scope, or trigger deployments without explicit authorization.

## Procedure

1. Map source repositories, maintainers, dependency manifests, lockfiles, CI/CD workflows, registries, signing/provenance, and deployment consumers.
2. Identify dependency sources and version constraints; note mutable tags, unpinned actions, untrusted registries, and direct Git dependencies.
3. Review repository permissions, branch protections, release approval, artifact signing, and secret exposure in build logs/configuration.
4. Trace how untrusted contributions or compromised dependencies could influence build artifacts or deployment credentials.
5. Review dependency advisories against exact installed versions and reachable code paths; do not report a package name or CVE match alone.
6. Check artifact provenance and promotion boundaries using existing metadata or approved attestations.
7. Validate suspected weaknesses through static configuration review or a test repository, not by poisoning a production pipeline.
8. Recommend immutable pinning, lockfile enforcement, least-privilege build tokens, isolated runners, signed artifacts, and controlled release approvals.

## Pitfalls

- An outdated dependency is not automatically exploitable.
- A public repository is not proof of weak release controls.
- A theoretical maintainer compromise should be described as a threat path, not a confirmed finding.
- Never publish a proof-of-concept package to a public registry.

## Verification

Document the affected repository/package/workflow, exact trust boundary, evidence source, reachable consequence, and confidence. Separate observed configuration from hypothetical attack steps.
