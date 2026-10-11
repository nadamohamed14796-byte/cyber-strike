---
name: attack-vcenter
description: "Assess authorized VMware vCenter exposure, authentication boundaries, and configuration risks"
category: "infrastructure-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [vmware, vcenter, virtualization, infrastructure]
tech_stack: [vmware, vcenter, vsphere, http]
prerequisites:
  - "Written authorization for the vCenter instance and associated infrastructure"
  - "Low-impact checks and a read-only account where available"
chains_with: [attack-cloud-misconfig, attack-cloud-iam, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/vmware-vcenter-attack/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/redteam/vmware-vcenter-attack/SKILL.md"
---

# VMware vCenter Assessment

## When to use

Use when an in-scope environment exposes VMware vCenter/vSphere management interfaces, APIs, authentication, or configuration endpoints.

## Safety gate

Management planes are high impact. Confirm exact instance and permitted checks. Use read-only inspection; do not create snapshots, power-cycle VMs, modify networks, deploy appliances, or attempt exploitation without explicit approval.

## Procedure

1. Confirm host identity, TLS certificate, version evidence, and scope.
2. Identify publicly reachable management surfaces and API endpoints using low-rate requests.
3. Review authentication configuration and whether sensitive management APIs disclose meaningful data before authentication.
4. With an approved read-only account, inspect role assignments and whether permissions exceed the account's stated purpose.
5. Review federation/SSO, session expiry, MFA enforcement, and privileged account separation where configuration evidence is available.
6. Compare version evidence with vendor advisories and verify affected configuration/preconditions; do not claim a CVE from a banner alone.
7. Check exposed backup/configuration endpoints only within scope and capture minimal sanitized evidence.
8. Assess management-plane network segmentation and audit logging from configuration or approved read-only views.
9. Stop if real VM inventory, credentials, or sensitive tenant data is exposed; do not enumerate or download it.

## Pitfalls

- A login page or version banner is not a vulnerability.
- Management access may be intentionally restricted to VPN/internal networks.
- Do not alter virtual infrastructure as a proof of impact.

## Verification

Provide the exact instance, version/configuration evidence, expected control, observed behavior, impact, and confidence. Separate confirmed exposure from hardening recommendations.
