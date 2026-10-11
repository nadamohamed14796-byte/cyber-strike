---
name: attack-forgot-password
description: "Validate password-reset and account-recovery token handling, account binding, expiry, single use, and identity-proof transitions using test-owned accounts."
category: "identity"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - password-reset
  - account-recovery
  - tokens
  - authentication
  - identity
tech_stack:
  - web
  - rest-api
  - email
  - sms
  - oauth
cwe_ids:
  - CWE-640
  - CWE-287
chains_with:
  - attack-ato
  - attack-auth-bypass
  - attack-session
prerequisites: []
severity_boost:
  attack-ato: "A reset weakness becomes ATO only when a tester completes the flow for an owned test account and verifies resulting identity/session."
---

# Password Recovery and Reset Assessment

## Objective

Determine whether recovery proofs are unpredictable, time-bound, single-use, and bound to the intended account and action. Use only accounts and mailboxes controlled by the tester.

## Testing Methodology

### Phase 1: Map recovery routes

Inventory reset request, email/SMS verification, token validation, completion, account enumeration, fallbacks, and session issuance. Confirm scope covers mail/SMS systems before testing them.

### Phase 2: Capture normal token lifecycle

Request a reset for a test account, record token metadata without exposing the full value, and complete the normal flow. Capture expiry policy, prior-token invalidation, and existing-session behavior.

### Phase 3: Check account and action binding

Using two test accounts, confirm a token issued for A cannot reset B and cannot authorize a different recovery action. Do not modify recovery addresses or request resets for real people.

### Phase 4: Test expiry and single use

In lab or with documented short-lived fixtures, test expired, malformed, and already-used tokens. Do not guess tokens, bulk reset requests, flood inboxes, or evade lockout controls.

### Phase 5: Review link and notification handling

Inspect host-header influence on reset links, redirects, referrer leakage, token logging, and notifications using test accounts and domains.

## What Constitutes a Finding

- **Candidate / lead:** reset response reveals account existence or generated URL appears influenced by request headers.
- **Confirmed finding:** recovery proof crosses test accounts, is reused against policy, or succeeds outside intended expiry/action bounds.
- **Impact-qualified:** reset completes for a tester-owned account and resulting credential/session control is verified.
- **Not a finding:** differing wording alone or a reset email without token misuse.

## Evidence Requirements

- Test account/mailbox ownership, endpoints, timestamps, token lifecycle, and role.
- Sanitized requests/responses and before/after recovery state; redact reset token completely.
- Evidence that token A did or did not affect test account B, plus expiry/single-use result.
- Session invalidation and cleanup status.

## Tools

- **Burp Suite:** compare reset request/verify/complete stages.
- **Dedicated test mailbox:** inspect reset links for owned accounts.
- **Browser DevTools:** inspect redirects and referrer policy.
- **Source/log review:** examine token generation, binding, expiry, and one-time consumption.

## Recovery Token Control Matrix

| Property | Test | Expected control |
|---|---|---|
| Entropy | Review generator; do not guess live tokens | Cryptographically strong random token |
| Account binding | Use two tester-owned accounts | Token cannot authorize another account |
| Action binding | Compare reset vs other recovery action | Proof only authorizes intended operation |
| Expiry | Validate timeout with controlled fixture | Expired token is rejected |
| Single use | Retry completed test token once | Reuse rejected |
| URL construction | Review canonical link behind proxy headers | Untrusted Host cannot set destination |
| Session lifecycle | Check owned sessions after reset | Revocation matches policy |

**Mitigation:** generate high-entropy tokens, bind account/action, expire and consume atomically, use a trusted canonical host, prevent token logging, and notify account owner.

## Verification and False Positives

- Recovery policy may vary; compare with product contract.
- Mail security gateways can rewrite links; compare with canonical generated URL.
- Account enumeration should not be inferred from one phrase alone.
- Stop before any account/mailbox not owned by the tester, bulk messages, or token guessing.

## References

- [Claude-BugHunter — hunt-forgot-password](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-forgot-password)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
