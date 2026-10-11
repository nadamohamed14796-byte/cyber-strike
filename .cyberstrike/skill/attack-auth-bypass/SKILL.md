---
name: attack-auth-bypass
description: "Assess authentication boundary inconsistencies across routes, protocols, and session states"
category: "authentication"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [authentication, sso, access-control, session]
tech_stack: [http, web, api, identity]
prerequisites:
  - "Explicit authorization for authentication-flow testing"
  - "Controlled test accounts with documented roles"
chains_with: [attack-oauth, attack-saml, attack-mfa-bypass, attack-password-reset, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-auth-bypass/SKILL.md"
---

# Authentication Bypass Assessment

## When to use

Use when login, SSO, legacy routes, API endpoints, or session transitions appear to enforce different authentication requirements. Focus on inconsistent enforcement rather than guessing credentials.

## Preconditions and safety

Use only controlled accounts and approved test identities. Do not attempt credential stuffing, password spraying, token theft, or access to real user accounts. Follow lockout, rate-limit, and identity-provider rules.

## Procedure

1. **Map the intended flow.** Document login, MFA, SSO callback, session issuance, logout, and sensitive post-login actions.
2. **Inventory alternate routes.** Compare browser and API routes, legacy endpoints, versioned APIs, mobile endpoints, and direct navigation to protected pages.
3. **Record the baseline.** Use a controlled account to capture a successful login and a logged-out request to the same protected resource.
4. **Check consistent enforcement.** Test whether every protected route validates the expected session, role, issuer, audience, and authentication state.
5. **Inspect state transitions.** Determine whether pre-authentication, post-password, post-MFA, and logged-out sessions are distinguishable and enforced server-side.
6. **Review token trust.** Check issuer, audience, signature validation, expiry, nonce/state, and key-selection behavior through safe test fixtures or provider-supported test modes.
7. **Compare roles and routes.** Use controlled users with different roles to check whether a lower-privilege account can reach a protected action. Avoid any action that changes real accounts or data.
8. **Validate minimally.** Demonstrate access to a harmless protected resource or a denied action that should be authorized. Do not chain to account takeover unless separately authorized and safely reproducible.
9. **Capture evidence.** Record the expected auth state, session context, request, response, and exact boundary failure.

## Verification

A finding requires a repeatable request accepted without the authentication state or identity proof the application requires. A visible page, decoded token, or HTTP 200 alone is not proof.

## Pitfalls

- Confusing missing authorization with missing authentication.
- Testing a legacy route that is intentionally public.
- Ignoring identity-provider configuration or audience boundaries.
- Treating a JWT decode as server-side acceptance.
- Triggering lockouts or account changes during testing.

## Remediation guidance

Centralize authentication middleware, validate token signature/issuer/audience/expiry, enforce step-up requirements consistently, and test legacy and alternate routes against the same policy.

## CyberStrike integration contract

Verify the actual auth-context model, request runner, scope gate, and finding schema before runtime integration. This skill must not perform credential attacks.

## Attribution

Adapted from Claude-BugHunter hunt-auth-bypass: https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-auth-bypass/SKILL.md
