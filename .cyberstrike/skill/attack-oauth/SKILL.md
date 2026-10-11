---
name: attack-oauth
description: "Assess OAuth and OIDC redirect, state, token, and client-binding controls"
category: "authentication"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [oauth, oidc, sso, redirect, tokens]
tech_stack: [http, browser, oauth2, oidc]
prerequisites:
  - "Authorized application and a controlled OAuth client/account"
  - "Provider and program rules for authentication-flow testing"
chains_with: [attack-auth-bypass, attack-saml, attack-mfa-bypass, attack-triage-validation, attack-evidence-hygiene]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-oauth/SKILL.md"
---

# OAuth and OpenID Connect Assessment

## When to use

Use when a web or mobile application relies on OAuth 2.0 or OpenID Connect for login, account linking, API authorization, or delegated access.

## Preconditions and safety

Use a test client and test accounts. Do not capture or reuse other users' authorization codes or tokens. Avoid consent changes, account linking, or token grants that affect real accounts. Confirm the exact callback URLs and provider testing policy.

## Procedure

1. **Map the flow.** Record authorization endpoint, client ID, redirect URI, response type, scopes, state, nonce, PKCE use, and token endpoint.
2. **Capture a valid baseline.** Complete a normal test login and note how the application validates state, nonce, issuer, audience, and redirect URI.
3. **Review redirect handling.** Check whether redirect URIs are exact allowlisted values or dangerously broad patterns. Use a controlled callback you own where permitted.
4. **Review state and nonce.** Determine whether they are unpredictable, bound to the initiating browser session, and rejected when missing or mismatched.
5. **Review PKCE.** For public clients, confirm the verifier/challenge relationship and that code redemption requires the matching verifier.
6. **Review code and token handling.** Check for replay protections, issuer/audience validation, expiry, and whether tokens appear in URLs, browser history, logs, or referrer flows.
7. **Review account linking.** With two controlled test accounts, verify the application binds the correct external identity and requires appropriate confirmation before linking.
8. **Check mobile deep links only when in scope.** Determine whether callback handlers validate scheme/host/path and bind the response to the initiating flow.
9. **Validate with harmless outcomes.** Use only test identities and avoid accessing protected data or modifying another account.
10. **Document the exact violated control.** A suspicious parameter or permissive-looking redirect is not enough without a demonstrated flow failure.

## Verification

A finding requires reproducible evidence that a protocol control is bypassed and that the result violates the intended identity or authorization boundary. Distinguish a redirect weakness from token leakage, account linking flaws, and authentication bypass.

## Pitfalls

- Assuming every redirect parameter is exploitable.
- Confusing OAuth authorization with user authentication.
- Ignoring PKCE, state, nonce, issuer, or audience validation.
- Testing with production accounts or real tokens.
- Claiming account takeover when only an open redirect was demonstrated.

## Remediation guidance

Use exact redirect URI allowlists, state and nonce validation, PKCE for public clients, strict issuer/audience checks, secure token storage, and explicit confirmation for sensitive account linking.

## CyberStrike integration contract

Verify actual OAuth flow capture, test-account context, browser support, and finding schema before automation. Never persist live authorization codes or tokens.

## Attribution

Adapted from Claude-BugHunter hunt-oauth: https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-oauth/SKILL.md
