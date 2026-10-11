---
name: attack-enterprise-vpn
description: "Assess authorized enterprise VPN exposure, authentication, and configuration boundaries"
category: "infrastructure-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [vpn, enterprise, authentication, remote-access]
tech_stack: [vpn, tls, sso, mfa, network]
prerequisites:
  - "Written authorization for the VPN gateway and permitted checks"
  - "Defined source IPs, test identities, and scanning limits"
chains_with: [attack-m365-entra, attack-okta, attack-mfa-bypass, attack-cloud-misconfig]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/enterprise-vpn-attack/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/redteam/enterprise-vpn-attack/SKILL.md"
---

# Enterprise VPN Assessment

## When to use

Use when reviewing authorized remote-access gateways, SSO/MFA enforcement, client configuration, exposed management interfaces, or vendor advisory applicability.

## Safety gate

Do not brute-force logins, exploit a live gateway, alter VPN policies, or attempt lateral movement without explicit written authorization. Begin with low-rate metadata and configuration review.

## Procedure

1. Confirm gateway hostname/IP, vendor evidence, source allowlist, and permitted test window.
2. Record TLS certificate, supported protocol metadata, and externally reachable management surfaces.
3. Review authentication flow, MFA/step-up requirements, SSO integration, and session lifetime using test identities.
4. Compare clientless portal and VPN-client access only where both are in scope.
5. Match version/configuration evidence to vendor advisories; verify preconditions rather than relying on a banner.
6. Review split tunneling, route assignment, device posture, and privilege separation through configuration evidence.
7. Validate only with read-only access or a test environment; do not access internal hosts outside scope.
8. Capture minimal evidence and recommend patching, MFA enforcement, exposure reduction, and monitoring.

## Pitfalls

- A VPN login portal is expected to be internet-reachable for many deployments.
- Vendor/version fingerprints may be inaccurate.
- A theoretical path from VPN access to internal systems is not proof of lateral movement.

## Verification

Document gateway, version evidence, authentication policy, test identity, expected control, observed behavior, and impact. Separate hardening recommendations from confirmed vulnerabilities.
