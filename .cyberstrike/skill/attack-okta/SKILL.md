---
name: attack-okta
description: "Assess authorized Okta tenant configuration, federation, session controls, and application assignments"
category: "identity-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [okta, sso, identity, saml, oauth, mfa]
tech_stack: [okta, saml, oauth, oidc, web]
prerequisites:
  - "Written authorization for the Okta org and its connected applications"
  - "Test users and read-only configuration access where possible"
chains_with: [attack-saml, attack-oauth, attack-mfa-bypass, attack-ato, attack-cloud-iam]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/okta-attack/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/redteam/okta-attack/SKILL.md"
---

# Okta Identity Assessment

## When to use

Use when reviewing an authorized Okta organization, SSO integration, application assignment, factor enrollment, session policy, or identity lifecycle workflow.

## Safety gate

Do not test real users, reset real factors, alter production policies, create persistence, or access mail/files. Use test accounts and a staging app wherever possible.

## Procedure

1. Confirm organization domain, test accounts, app scope, and permitted admin visibility.
2. Review application assignments, group rules, administrator roles, and least-privilege access.
3. Inspect SAML/OIDC configuration, issuer/audience/redirect validation, signing certificate lifecycle, and account-linking assumptions.
4. Review MFA enrollment, recovery, factor reset, step-up requirements, and session lifetime using controlled identities.
5. Check deprovisioning and group membership changes against app access using a test user.
6. Review API tokens/service accounts and app integrations for scope, rotation, and ownership without retrieving secret values.
7. Validate behavior through configuration review and controlled test-user flows; avoid policy changes in production.
8. Record the expected identity boundary, observed control, and minimum remediation.

## Pitfalls

- An application visible in the catalog is not necessarily assigned to a user.
- SSO configuration is not proof of a bypass.
- MFA recovery differences can be policy-driven.
- Do not infer impact from an admin role name alone.

## Verification

Include organization/app, test principal, policy configuration, expected access, observed access, and sanitized evidence. State clearly whether the result is configuration risk or a confirmed access-control failure.
