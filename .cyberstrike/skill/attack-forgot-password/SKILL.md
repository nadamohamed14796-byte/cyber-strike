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


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Treat the attempt budget as a ceiling for independent, evidence-producing hypotheses, not a payload quota. If the candidate remains plausible, follow the next signal-led branch up to 20 distinct hypotheses; stop sooner when impact is decisive, no relevant branch remains, or scope/safety limits apply. Cosmetic encodings of the same request do not count as separate attempts.

Maintain an attempt ledger: hypothesis, single changed variable, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer controlled identities, synthetic resources and paired requests. Preserve sanitized evidence and minimize data collected.

### Skill-specific hypothesis order

1. Baseline the reset flow for an existing test account and a synthetic nonexistent identifier; compare status/body/timing only as supporting evidence, accounting for asynchronous email and normal variance.
2. Use only inboxes and recovery channels you control to inspect token purpose, account binding, entropy evidence available to the tester, expiry, single-use behavior, and invalidation after a successful reset.
3. Change one factor at a time: expired token, reused token, changed account identifier, alternate host/header in generated URL, or concurrent reset requests within program limits.
4. Confirm whether a reset actually changes the test account's credential/session state as intended; never attempt to reset real users, spam notifications, or infer takeover from an email response alone.
5. Capture sanitized request/response and the controlled mailbox event, then retest a valid flow as a positive control and an invalid/replayed token as a negative control.


### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture and a relevant control.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause remains uncertain.
- **Unconfirmed:** response is ambiguous, cached, generic, or not linked to a security boundary.
- **Refuted / false positive:** an applicable negative control or valid policy explanation accounts for the signal. Record the attempt ledger rather than claiming every theoretical variant was exhausted.
- A 2xx status, error difference, header, schema/documentation exposure, scanner alert, or UI-only state is not proof by itself.

### Stop, cleanup, and handoff

Stop on scope ambiguity, unexpected real-user data, unexpected production state changes, service degradation, credential exposure, or a prohibited action. Restore disposable state and revoke temporary tokens/sessions where possible. Handoff target and scope proof, baseline, hypothesis, attempts used, impact, negative controls, verdict/confidence, sanitized evidence pointers, linked-skill signal, and cleanup status. Invoke a related skill only when its triggering signal is observed.

## References

- [Claude-BugHunter — hunt-forgot-password](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-forgot-password)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
