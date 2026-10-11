---
name: attack-cloud-iam
description: "Review authorized cloud identity and access controls for excessive permissions and trust-boundary failures"
category: "cloud-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [cloud, iam, least-privilege, roles, trust-policy]
tech_stack: [aws, azure, gcp, iam, cloud]
prerequisites:
  - "Written authorization for the cloud account, tenant, or configuration under review"
  - "Read-only role or exported policy documents whenever possible"
chains_with: [attack-api-misconfig, attack-triage-validation, attack-evidence-hygiene, attack-report-writing]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/cloud-iam-deep/SKILL.md"
---

# Cloud IAM Assessment

## When to use

Use when reviewing cloud IAM users, roles, service principals, workload identities, trust policies, permission boundaries, federation, or cross-account access.

## Preconditions and safety

- Verify the exact account/tenant/subscription and written authorization.
- Prefer read-only policy inspection and exported configuration.
- Do not create access keys, assume privileged roles, alter trust policies, or access secrets unless the rules of engagement explicitly authorize that exact action.
- Never copy credentials or customer data into the repository or reports.

## Procedure

1. **Map identity types.** Inventory human users, service accounts, workload identities, federated principals, roles, and cross-account trust relationships.
2. **Collect effective permissions.** Review attached and inline policies, group inheritance, resource policies, permission boundaries, organization policies, and explicit denies where applicable.
3. **Identify high-impact permissions.** Flag broad administrative actions, wildcard resources, privilege-management operations, credential creation, policy modification, role assumption, and access to sensitive data stores.
4. **Review trust relationships.** Check who can assume a role, external tenant/account identifiers, audience/subject constraints, MFA conditions, and whether trust is broader than intended.
5. **Trace privilege-escalation paths.** Build a graph of principal → allowed action → resource → resulting privilege. Treat each edge as a hypothesis until policy evaluation or authorized simulation confirms it.
6. **Check least privilege.** Compare permissions with the workload's documented need. Distinguish unused permissions from permissions that are actually exploitable.
7. **Validate safely.** Use cloud policy simulators, read-only APIs, or approved test identities. Avoid making live policy changes or retrieving secrets as proof.
8. **Assess impact and remediation.** Explain the reachable privilege boundary, preconditions, affected resources, and minimum policy change that would close the path.
9. **Preserve evidence.** Capture policy identifiers, version/timestamp, sanitized snippets, and evaluation output. Redact account IDs if required by policy.

## Pitfalls

- A wildcard permission may be constrained by resource policy, organization policy, or explicit deny.
- A policy statement alone may not represent effective permissions.
- Unused permissions are a hardening issue, not automatically a demonstrated compromise.
- Never claim privilege escalation based only on a role name or a theoretical path.

## Verification

Confirm effective permission through policy evaluation or a controlled identity in the authorized account. A finding must identify the principal, permission, resource boundary, required conditions, demonstrated or simulated result, and confidence level.
