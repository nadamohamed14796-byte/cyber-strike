---
name: attack-ntlm
description: "Review authorized NTLM exposure, relay prerequisites, and legacy authentication boundaries"
category: "identity-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [ntlm, windows, active-directory, authentication]
tech_stack: [windows, ntlm, smb, ldap, http]
prerequisites:
  - "Written authorization for the domain and relevant services"
  - "Read-only configuration or passive evidence preferred"
chains_with: [attack-ldap, attack-m365-entra, attack-cloud-iam, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-ntlm-info/SKILL.md"
---

# NTLM Exposure Assessment

## When to use

Use when reviewing legacy NTLM authentication, service exposure, signing/channel-binding requirements, or relay-risk configuration in an authorized Windows environment.

## Safety gate

Do not capture credentials, coerce authentication, relay live sessions, or perform lateral movement unless those exact actions are explicitly authorized. Prefer configuration review and protocol metadata. Avoid scanning internal networks beyond the defined scope.

## Procedure

1. Confirm in-scope hosts, services, domain boundary, and permitted test techniques.
2. Identify NTLM use from approved configuration, logs, or low-impact service metadata.
3. Review whether NTLM is required, whether SMB signing and LDAP signing/channel binding are enforced, and whether extended protection is configured where applicable.
4. Trace the prerequisites for relay risk: attacker network position, reachable service, signing/channel-binding behavior, and credential flow.
5. Check whether services unnecessarily expose NTLM to untrusted networks or use weakly scoped service identities.
6. Validate with configuration evidence or a lab simulation; do not relay production authentication or collect hashes as a first test.
7. Recommend reducing NTLM use, enforcing signing/channel binding, segmenting services, and monitoring suspicious authentication.

## Pitfalls

- NTLM presence alone is not proof of relayability.
- Signing settings may differ by service and protocol.
- A hostname or banner is not enough to establish domain membership.
- Do not store password hashes or authentication captures in the repository.

## Verification

Document service, configuration evidence, relay prerequisites, reachable boundary, and confidence. Keep protocol exposure separate from a demonstrated exploit chain.
