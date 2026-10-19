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


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue with materially distinct, authorized branches while evidence can change the conclusion; deduplicate cosmetic variants and exact retries. Stop when direct evidence resolves the hypothesis, meaningful branches are exhausted, a prerequisite is unavailable, or scope/safety requires stopping. Program rate limits and safe-production constraints remain mandatory.

Keep an attempt ledger: hypothesis, one variable changed, baseline/control, signal, interpretation, confidence and next branch. Use controlled identities/fixtures, independent corroboration, low-impact requests and minimum sanitized evidence.

### Skill-specific hypothesis order

1. Record cookie and token behavior for a normal controlled login, privilege change, password reset, and logout; use browser devtools or proxy evidence without exposing credential values.
2. Check cookie flags (Secure, HttpOnly, SameSite, Domain, Path), identifier rotation after authentication/privilege changes, and server-side invalidation after logout/reset.
3. Test session fixation/reuse only with sessions issued to your own test account; compare a pre-login identifier with the authenticated session and use a fresh browser as a negative control.
4. Verify authorization after session changes and token expiry/revocation using harmless protected resources; do not replay stolen or third-party session material.
5. Capture sanitized cookie attributes and state transitions, then provide a regression test for rotation, expiry, revocation, and scope restrictions.


### Verdict gates

- **Confirmed:** repeatable impact at an explicit in-scope boundary is demonstrated with a controlled fixture/identity and relevant control.
- **Likely / needs corroboration:** multiple independent signals support the candidate but the effect or cause remains uncertain.
- **Unconfirmed:** signal is generic, timing/cache-dependent, or not tied to a security property.
- **Refuted / false positive:** a relevant control or valid product/security behavior explains the observation; preserve the test ledger rather than claiming all theoretical vectors were attempted.
- A status code, banner, parser error, timing fluctuation, version string, or scanner alert alone is not proof.

### Safety, cleanup, and handoff

Stop on scope ambiguity, unexpected state changes, sensitive data, service degradation, secret exposure or prohibited actions. Restore synthetic state and revoke temporary credentials/sessions where possible. Report scope proof, baseline, hypothesis, attempt count, impact, controls, verdict/confidence, sanitized evidence and cleanup status. Chain into another skill only after observing its required signal.

## References

- [uphiago — hunt-session](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-session)
- [Claude-BugHunter — hunt-session](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-session)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)


## Targeted quality-loop enrichment (2026-10-19)

### Session lifecycle and privilege transition
Record session issue, storage, renewal, privilege change, logout, password reset, MFA change, and expiry as a timeline using tester-owned accounts. Reuse the same harmless authenticated endpoint as a control and verify server-side revocation/rotation, not just cookie changes in browser storage. Treat session identifiers as secrets and persist only redacted fingerprints. Consider subdomains, alternate devices, and multiple sessions only when they are part of the intended product behavior. Chain to ATO only when a controlled unauthorized principal is established, to CSRF when ambient cookie authority enables a cross-site action, and to cache deception only when personalized content crosses the cache boundary.


## Session transition and multi-client coverage

Use a timeline of events rather than checking a cookie attribute in isolation. Keep all sessions and identities under tester control.

| Event | Test observation | Control / evidence |
|---|---|---|
| Pre-auth → login | Session identifier and server principal before/after login | Fresh browser and a normal valid login control |
| Privilege/role change | Whether old session retains stale permissions | Same harmless endpoint before/after the controlled change |
| Password/MFA change | Whether old sessions are invalidated as documented | Test-owned account and explicit policy expectation |
| Logout | Whether prior session still authorizes a protected network action | Reuse only the tester's old session; ignore cached UI |
| Refresh/rotation | Whether old refresh token remains reusable | Controlled token pair and documented rotation contract |
| Multiple devices | Whether revoke-one/revoke-all semantics match the product | Two sessions created by the tester, labeled separately |
| Sibling apps/subdomains | Whether cookie scope shares authority more broadly than intended | Record domain/path and actual browser cookie send behavior |
| Long-lived socket/API token | Whether authorization is rechecked after session revocation | Harmless test message/action with synthetic data |

### Secret-safe metadata collection

Record cookie names, attributes, expiry, issuer/audience, token type, and a local redacted fingerprint. Never store the raw cookie or bearer token. If an exact token is needed to reproduce a controlled test, keep it only in the local secret mechanism and remove it after the test.

### Chain decision table

- Session remains valid after logout contrary to policy → session revocation issue; verify a protected server action, not cached content.
- Old session retains a privilege after a role/assurance change → authorization-state invalidation issue; confirm the effective permission.
- Cookie is sent cross-site and a protected mutation succeeds → CSRF review; keep the read and write properties distinct.
- Token audience/issuer validation is incorrect → JWT/OAuth review only when a wrong test principal or relying-party boundary is accepted.
- Token remains in browser storage but is rejected server-side → not session takeover; document storage exposure separately only if an actual access path exists.

Add transition_event, session_fingerprint, issued_at, expires_at, principal_before_after, permission_before_after, revocation_expected, old_session_request_result, fresh_session_control, and cleanup_verified to the private evidence record.


## Reproducible session-transition ledger

Use one record per transition and keep secret values out of the record. The fingerprint should be a keyed local digest or a one-way digest generated locally; never store the raw identifier.

```json
{
  "test_run": "session-lifecycle-<local-id>",
  "principal": "tester-owned-account-A",
  "transition": "logout",
  "session_fingerprint_before": "<redacted-local-fingerprint>",
  "session_fingerprint_after": "<redacted-local-fingerprint>",
  "expected_revocation": true,
  "old_session_protected_request": {
    "status": 401,
    "protected_synthetic_marker_present": false
  },
  "fresh_session_control": {
    "status": 200,
    "protected_synthetic_marker_present": true
  },
  "server_state_confirmed": false,
  "cleanup_verified": true,
  "raw_tokens_persisted": false
}
```

Replace example values with observations; do not treat this example as an expected result for every application. A 401/200 pair is useful only if both requests hit the same intended resource and the marker proves the protected operation.

### Extra edge cases worth checking

- Concurrent logout/revocation and refresh on two tester-owned sessions.
- Password reset or MFA change followed by use of an older refresh token.
- Cookie Domain and Path behavior across a sibling app, including whether the sibling is actually trusted.
- Session expiry vs refresh-token expiry; verify the server-side contract, not the browser display.
- Reauthentication/step-up requirements for sensitive actions after a long-lived session.
- Remembered-device state and recovery flows, only with test accounts and synthetic factors.

Keep each edge case as a separate hypothesis with a baseline and a negative control. If the application intentionally preserves other sessions, assess the documented revoke-one/revoke-all behavior rather than assuming every session must be invalidated.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Use browser DevTools' Application/Storage/Network panels, Burp Repeater/Comparer, and isolated browser profiles for controlled account/session comparisons. Use an optional password manager or OS secrets store for test credentials, not shell history.

### Installation and setup
- [Burp Suite](https://portswigger.net/burp) — official install and proxy setup.
- [Firefox downloads](https://www.mozilla.org/firefox/new/) — separate profiles help prevent session/cookie crossover.
- jq on Kali/Debian: `sudo apt update && sudo apt install jq` for local JSON metadata.
Do not export live cookies into cloud tools or public JWT/session decoders. Test revocation, rotation, and logout only using accounts you control.

### Primary resources
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) — identifier lifecycle and invalidation.
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) — session/authentication boundaries.
- [PortSwigger session management](https://portswigger.net/web-security) — controlled practice.

### Reusable helper
`python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt` compares sanitized local responses offline.

### Result handling
Keep the session cookie value secret. Report lifecycle behavior (creation, rotation, logout, expiry, privilege change) and expected/actual access using test accounts.
