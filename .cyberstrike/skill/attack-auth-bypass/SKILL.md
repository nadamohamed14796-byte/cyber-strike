---
name: attack-auth-bypass
description: "Validate authentication-control failures across login, recovery, federation, and alternate API flows with test-owned identities and reproducible session checks."
category: "identity"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - authentication
  - auth-bypass
  - login
  - identity
  - api
tech_stack:
  - web
  - rest-api
  - oauth
  - saml
  - oidc
cwe_ids:
  - CWE-287
  - CWE-306
  - CWE-384
chains_with:
  - attack-ato
  - attack-mfa-bypass
  - attack-session
  - attack-sqli
  - attack-nosqli
prerequisites: []
severity_boost:
  attack-ato: "Authentication bypass can enable account takeover when a controlled account's identity or session is accepted without valid proof."
---

# Authentication Bypass Assessment

## Objective

Determine whether an in-scope application grants an authenticated identity or protected operation without enforcing its documented authentication proof. Use only test accounts, synthetic identities, and permitted flows.

## Testing Methodology

### Phase 1: Map authentication entry points

Inventory web/mobile/API login, recovery, invitations, magic links, OAuth/OIDC/SAML callbacks, legacy routes, and versioned endpoints. Verify ownership of identity-provider hosts before testing. Capture normal successful and failed baselines.

### Phase 2: Compare state transitions

Change one condition at a time: missing credential, malformed credential, expired test token, wrong audience, stale session, missing second factor, and alternate content type. Confirm the server-side identity and resulting session, not just a status code or UI.

### Phase 3: Check alternate and legacy paths

Compare UI and API behavior, old versions, remember-me endpoints, recovery completion, and federated callbacks. Use only artifacts issued to tester-owned accounts. Do not guess credentials or target another person's identifier.

### Phase 4: Verify protected action

Use a least-privileged test account and harmless protected operation. Confirm the backend resolves an authenticated principal rather than returning public content or changing only the frontend. Stop before accessing real users' data.

### Phase 5: Trace root cause

Review credential validation, session creation, callback state/nonce, token issuer/audience, challenge completion, and middleware coverage. Ensure every route applies the same server-side gate.

## What Constitutes a Finding

- **Candidate / lead:** failed login has unusual response, route lacks an obvious guard, or UI state differs from API state.
- **Confirmed finding:** a protected harmless action succeeds without required authentication proof and is repeatable with controlled identities.
- **Not a finding:** HTTP 200 alone, client-only dashboard state, generic error differences, or intentionally public functionality.

## Evidence Requirements

- Baseline success/failure request and the single altered condition.
- Test account IDs/roles, session status, endpoint, timestamp, and resulting principal.
- Minimal harmless operation proving the failed boundary.
- Redact cookies, credentials, and tokens.

## Tools

- **Burp Repeater:** compare authentication flows and API variants.
- **Browser DevTools:** inspect redirects, cookies, and frontend/server mismatch.
- **Offline token decoders:** inspect test-token claims without sending secrets to external sites.
- **Source/log review:** confirm principal resolution and guard coverage.

## Authentication Control Matrix

| Flow | Security property | Confirmation |
|---|---|---|
| Password login | Credentials validated before session issue | Invalid test credentials never yield a valid principal |
| Recovery/magic link | Token bound to account, action, expiry, and single use | Test token cannot complete another test account's flow |
| OAuth/OIDC | State, nonce, issuer, audience, redirect URI and PKCE as applicable | Callback cannot establish the wrong test identity |
| SAML | Signature, issuer, recipient, audience, and timestamps validated | Mismatched test assertion is rejected |
| API/mobile | Backend validates independently of UI | Direct API call does not bypass the same gate |
| Legacy route | Same server-side policy | Alternate route cannot permit a denied action |

**Mitigation:** centralize authentication middleware, validate protocol state server-side, bind tokens to context, and regression-test negative cases on every route.

## Verification and False Positives

- Cached pages/client navigation can appear authenticated while APIs remain protected.
- Public/guest flows require documented expected behavior.
- Response code or timing differences do not prove bypass without an authenticated principal.
- Stop if testing requires credential guessing, real-account recovery, or out-of-scope identity-provider access.

## References

- [uphiago — hunt-auth-bypass](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-auth-bypass)
- [Claude-BugHunter — hunt-auth-bypass](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-auth-bypass)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
