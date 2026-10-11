---
name: cloud-assessment
description: "Read-only, evidence-led AWS, Azure, and GCP security assessment aligned with least privilege and benchmark controls"
category: assessment
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [cloud, aws, azure, gcp, iam, cis, storage, logging]
tech_stack: [aws, azure, gcp, iam, cloud]
prerequisites:
  - "Written authorization for the exact account, subscription, project, and assessment mode"
  - "Read-only credentials or exported configuration whenever possible"
chains_with: [ad-security, k8s-assessment, ci-assessment, cicd-attacks]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/cloud-iam-deep/SKILL.md"
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-cloud-misconfig/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/redteam/cloud-iam-deep/SKILL.md"
---

# Multi-Cloud Security Assessment

## Objective

Review cloud configuration, identity, storage, network exposure, logging, and workload trust boundaries using read-only evidence wherever possible. The assessment is not permission to assume roles, retrieve secrets, change policies, or access customer data.

## Scope and safety

- Confirm provider, account/tenant/subscription/project identifiers, region boundaries, and excluded resources.
- Prefer read-only roles, exported policies, provider policy simulators, and configuration snapshots.
- Never create access keys, alter trust policies, disable logging, expose storage, or retrieve secrets unless that exact action is explicitly approved.
- Redact account identifiers, resource names, secrets, and customer data according to the engagement rules.

## Assessment workflow

### 1. Establish inventory and context

Record cloud provider, organization structure, accounts/projects/subscriptions, regions, workloads, identity sources, public endpoints, storage, logging, and deployment paths. Separate observed facts from inferred relationships.

### 2. Identity and effective permissions

Review users, groups, service principals, workload identities, roles, attached/inline policies, resource policies, permission boundaries, organization-level controls, and explicit denies. Evaluate effective permissions rather than judging a single policy statement in isolation. Flag broad wildcards, privilege-management operations, long-lived credentials, and overly broad cross-account trust.

### 3. Trust and federation

Inspect role-assumption conditions, external account/tenant constraints, audience/subject restrictions, MFA conditions, workload identity bindings, and federation issuer validation. Model a privilege path as principal → allowed action → resource → resulting capability. Treat the path as a hypothesis until a simulator or approved test identity confirms it.

### 4. Storage and data exposure

Review bucket/container ACLs, public access settings, object policies, signed URL lifetime, encryption settings, retention, and cross-account access. Use metadata or synthetic objects to validate controls; do not download sensitive customer objects to prove exposure.

### 5. Network and workload exposure

Review security groups/firewall rules, public IPs, load balancers, management ports, private endpoints, container/cluster exposure, and egress. Validate reachability only within approved scope and rate limits. Do not pivot into internal workloads or metadata endpoints without explicit authorization.

### 6. Logging, monitoring, and recovery

Check audit logging coverage, retention, alerting, immutable storage, key management, backup posture, and recovery configuration. Distinguish missing configuration from a demonstrated security incident.

### 7. Benchmark alignment

Use the applicable CIS/provider baseline as a reference, recording benchmark version and control ID. A failed benchmark check is a configuration finding candidate; prioritize by exposure, privilege, data sensitivity, compensating controls, and demonstrated impact.

### 8. Safe validation and remediation

Use provider-native policy simulation, read-only APIs, and approved test identities. Avoid changing production settings. Recommend least privilege, narrowed trust policies, short-lived credentials, private storage defaults, egress restrictions, and complete audit coverage.

## Common false positives

- A wildcard permission constrained by an explicit deny or resource policy.
- A public endpoint that exposes no sensitive action or data.
- A missing control that is covered by an organization-level policy.
- A theoretical privilege-escalation path without effective permission evaluation.
- A benchmark deviation incorrectly labeled as confirmed compromise.

## Output contract

Return provider and scope, resource identifier (redacted as required), control/baseline reference, evidence source, effective permission or exposure, preconditions, impact, confidence, and least-privilege remediation. Default to read-only evidence.
