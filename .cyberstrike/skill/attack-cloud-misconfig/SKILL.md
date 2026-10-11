---
name: attack-cloud-misconfig
description: "Review authorized cloud configuration for exposed resources and ineffective security boundaries"
category: "cloud-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [cloud, misconfiguration, storage, network, identity]
tech_stack: [aws, azure, gcp, cloud]
prerequisites:
  - "Written authorization for the exact account, tenant, or resources"
  - "Read-only access or exported configuration where practical"
chains_with: [attack-cloud-iam, attack-api-noauth, attack-triage-validation, attack-evidence-hygiene]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-cloud-misconfig/SKILL.md"
  - "https://github.com/uphiago/recon-skills/tree/main/infra"
---

# Cloud Misconfiguration Assessment

## When to use

Use when reviewing public cloud storage, network exposure, service configuration, metadata access boundaries, logging, encryption, or identity-linked configuration.

## Safety gate

Confirm resource ownership and scope before making requests. Prefer configuration inspection and policy simulation. Do not retrieve secrets, enumerate customer data, modify access policies, or access cloud metadata from an unapproved environment.

## Procedure

1. Define account/tenant, resource identifiers, exclusions, and permitted validation.
2. Collect configuration evidence: access policies, public-access flags, network rules, encryption settings, logging, and resource ownership.
3. Determine intended exposure from service purpose and documented policy; public assets may be intentional.
4. Review effective permissions, including explicit denies, organization policies, identity policies, and resource policies.
5. Validate reachability with a harmless metadata or synthetic object check when allowed; avoid bulk listing or downloading data.
6. Check whether the exposed resource contains meaningful sensitive information using the minimum necessary proof and stop immediately if real user data appears.
7. Separate configuration weakness from demonstrated impact. State what an unauthenticated or lower-privileged actor can actually do.
8. Recommend least privilege, private-by-default access, scoped network rules, logging, and safe secret rotation where relevant.

## Pitfalls

- A public endpoint does not prove that private data is exposed.
- A scanner flag must be confirmed against effective configuration.
- Encryption at rest does not correct an authorization failure.
- Do not change live policies as a test.

## Verification

Include resource, effective policy, caller identity, access result, minimal sanitized evidence, intended exposure, and impact. Mark unverified configuration concerns separately from confirmed exposure.
