---
name: attack-session
description: "Validate session issuance, binding, renewal, fixation, and revocation across authentication state changes using controlled sessions and test accounts."
category: "identity"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - session
  - cookies
  - authentication
  - revocation
  - web
tech_stack:
  - web
  - mobile
  - rest-api
  - oauth
  - oidc
cwe_ids:
  - CWE-384
  - CWE-613
  - CWE-565
chains_with:
  - attack-auth-bypass
  - attack-mfa-bypass
  - attack-ato
prerequisites: []
severity_boost:
  attack-ato: "A session-lifecycle flaw may permit takeover if a stale or attacker-influenced test session remains authorized after a required state change."
---

# Session Management Assessment

## Objective

Assess whether session identifiers are unpredictable, rotated at trust transitions, safely stored, and revoked when required. Use only browser sessions for accounts you own.

## Testing Methodology

### Phase 1: Inventory session artifacts

Record cookie names, token types, expiry metadata, device-trust artifacts, and server-side session identifiers. Never copy live tokens to external tools or reports. Capture a baseline session for a test account.

### Phase 2: Review storage controls

Check Secure, HttpOnly, SameSite, Path, Domain, expiry, issuer/audience, and refresh rotation as applicable. Inspect whether a pre-auth session ID persists after login.

### Phase 3: Test rotation at trust changes

Compare identifiers before/after login, privilege changes, password reset, MFA enrollment, and documented security transitions. Use owned sessions and avoid changing real identities or roles.

### Phase 4: Test revocation

Log out a test session or reset its test password, then use a harmless protected endpoint to check whether the prior session remains authorized. Keep the scope of this check to the test account.

### Phase 5: Check fixation and scope

If a pre-auth ID exists, verify login rotates it and that a test-supplied identifier cannot bind another user's session. Never try to fixate a third party. Inspect domain/path scope across sibling apps.

## What Constitutes a Finding

- **Candidate / lead:** cookie attributes are weak or a token remains present after logout.
- **Confirmed finding:** a prior/attacker-influenced test session still authorizes a protected action after required invalidation, or a pre-auth ID is retained across login contrary to policy.
- **Not a finding:** token presence alone, documented long expiry, or cached public content after logout.

## Evidence Requirements

- Redacted session metadata, cookie attributes, token type/expiry/issuer, and timestamp.
- Before/after identifier and matched protected-request results.
- Test account and exact transition being evaluated.
- Never include full session IDs, JWTs, refresh tokens, or private account data.

## Tools

- **Browser DevTools:** inspect cookie lifecycle and attributes.
- **Burp Suite:** compare requests using owned sessions.
- **Offline JWT decoder:** inspect test-token claims locally.
- **Source/log review:** verify rotation, expiry, and revocation.

## Session Lifecycle Matrix

| Transition | Expected property | Evidence |
|---|---|---|
| Login | Authenticated session is rotated when required | Pre-auth ID is not retained contrary to policy |
| Privilege/assurance change | Stale privilege state is invalidated/refreshed | Old session does not keep prior permissions |
| Logout | Server-side session/refresh token revoked as specified | Previous test session loses protected access |
| Password reset/account disable | Existing sessions invalidated per policy | Old session cannot execute harmless protected action |
| Refresh token | Rotation/reuse handling follows design | Reuse behavior matches the documented contract |
| Cookie scope | Domain/path limit unintended sharing | Session is not sent to unrelated hosts/paths |

**Mitigation:** rotate identifiers at trust changes, revoke server-side sessions, protect cookies, constrain token audience/scope, and test invalidation across clients.

## Verification and False Positives

- Stateless tokens may have a documented revocation window; assess against the contract.
- Browser cache can show old rendered content; verify a network action that requires authentication.
- Token existence is not proof the server trusts it.
- Never steal, replay, or share anyone else's token.

## References

- [uphiago — hunt-session](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-session)
- [Claude-BugHunter — hunt-session](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-session)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
