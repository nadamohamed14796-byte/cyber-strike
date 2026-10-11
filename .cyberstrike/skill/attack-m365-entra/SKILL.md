---
name: attack-m365-entra
description: "Review authorized Microsoft 365 and Entra ID identity, consent, and tenant security boundaries"
category: "identity-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [m365, entra, azure-ad, identity, oauth, conditional-access]
tech_stack: [microsoft-365, entra-id, oauth, saml, graph-api]
prerequisites:
  - "Written authorization for the exact tenant and permitted identity tests"
  - "Test accounts and read-only admin/configuration access where possible"
chains_with: [attack-oauth, attack-saml, attack-mfa-bypass, attack-cloud-iam, attack-ato]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/m365-entra-attack/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/redteam/m365-entra-attack/SKILL.md"
---

# Microsoft 365 and Entra ID Assessment

## When to use

Use when assessing authorized Microsoft 365 tenant configuration, Entra ID identities, application registrations, OAuth consent, conditional access, federation, or guest access.

## Safety gate

Use only the named tenant and test accounts. Do not consent to unknown applications, access mailboxes or files belonging to real users, create persistence, change tenant-wide policies, or test password spraying. Prefer read-only review and test-tenant simulation.

## Procedure

1. Confirm tenant ID/domain, test identities, scope exclusions, and allowed API permissions.
2. Inventory application registrations, service principals, delegated/application permissions, redirect URIs, credential expiry, and publisher verification.
3. Review consent policies and whether users can grant high-impact permissions without administrator review.
4. Review Conditional Access, MFA requirements, legacy authentication, guest access, and privileged role assignments.
5. Check federation and token claims for intended issuer/audience and correct tenant binding; use the dedicated OAuth/SAML skills for protocol-level hypotheses.
6. Review workload identity and service-principal permissions for unnecessary tenant-wide access.
7. Validate only with approved read-only Graph queries, exported policies, or test users. Never retrieve real mailbox contents as proof.
8. Explain the specific trust boundary and minimum permission/configuration change that would address it.

## Pitfalls

- A public tenant identifier is not a secret.
- An application permission listed in configuration may be constrained or unconsented.
- A missing policy in one portal view may be inherited or enforced elsewhere.
- Do not claim account takeover from a theoretical consent path.

## Verification

Record tenant boundary, principal/app, effective permission, policy evidence, test identity, observed result, and sanitized proof. Clearly distinguish configuration review from an executed exploit path.
