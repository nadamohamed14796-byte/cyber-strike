---
name: attack-ldap
description: "Assess authorized LDAP directory exposure, authentication boundaries, and access controls"
category: "identity-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [ldap, active-directory, identity, directory-services]
tech_stack: [ldap, ldaps, active-directory]
prerequisites:
  - "Written authorization for the directory and its network endpoints"
  - "Read-only test identity and documented query limits"
chains_with: [attack-cloud-iam, attack-ntlm, attack-m365-entra, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-ldap/SKILL.md"
---

# LDAP Directory Assessment

## When to use

Use when an in-scope application or directory service exposes LDAP/LDAPS, directory queries, identity federation, or Active Directory-backed authorization.

## Safety gate

Use a read-only identity and authorized endpoints. Do not perform password spraying, modify directory objects, dump all users/groups, or test against unrelated internal hosts. Keep queries narrow and avoid collecting personal data.

## Procedure

1. Confirm host, port, directory boundary, allowed authentication methods, and permitted query scope.
2. Identify anonymous bind behavior and supported protocol capabilities with low-impact requests.
3. Using a controlled identity, query only a small set of expected attributes and record access policy.
4. Review whether sensitive attributes (password-related fields, tokens, personal records, privileged group membership) are accessible beyond the intended role; do not bulk-export them.
5. Check group and role resolution only for controlled test principals. Verify whether application authorization depends on client-side group claims or server-side directory checks.
6. Review TLS configuration and whether simple binds are permitted over an unencrypted channel, without sending real credentials in cleartext.
7. Validate suspected over-permission with one synthetic/test object or policy simulation when available.
8. Record the exact query, principal, returned attributes, expected policy, and minimal redacted evidence.

## Pitfalls

- A successful bind does not prove excessive access.
- Public directory attributes may be intentional.
- Directory names and group names alone do not prove privilege escalation.
- Do not test guessed credentials or enumerate all accounts.

## Verification

Confirm an access-control violation or credential transport weakness using a controlled identity and minimal evidence. State whether the issue is configuration exposure, excessive read access, or an application authorization defect.
