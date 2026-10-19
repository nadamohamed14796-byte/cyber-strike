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

- Python `httpx` or `curl`: compare observed reset/verify/complete requests using tester-owned accounts.
- Dedicated test mailbox/API: inspect reset links only for accounts controlled by the tester.
- `jq`: parse redacted reset response metadata.
- `rg`: review local source/configuration for token generation, account/action binding, expiry, and one-time use.
- `python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt`: compare saved responses offline.

Verify `curl --version`, the chosen Python client, and `jq --version`. Official docs: https://curl.se/docs/, https://www.python-httpx.org/, https://jqlang.org/.

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


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue with materially distinct, authorized branches while evidence can change the conclusion; deduplicate equivalent requests and cosmetic encodings. Stop when direct evidence resolves the hypothesis, meaningful branches are exhausted, a prerequisite is unavailable, or scope/safety requires stopping. Program retry limits and user-safety constraints remain mandatory.

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


## Targeted quality-loop enrichment (2026-10-19)

### Reset-token binding matrix
Use two tester-owned accounts with separate inboxes. Track token issue, delivery, expiry, single-use behavior, destination account, session binding, redirect destination, and post-reset session revocation. Change one property at a time and verify the final credential state using the disposable account—not by exposing the token in logs. Include re-requesting a token, invalidating a prior token, and completing an old link after a new request only where safe. A predictable-looking URL or email behavior is not ATO without account-control proof. Chain to host-header review only if a manipulated host changes a generated reset link; chain to session review only if old sessions remain valid after a policy-required reset.


## Recovery transaction sequence and notification safety

Treat recovery as a stateful transaction, not one endpoint. Record the stages below for the same test account and mailbox.

| Stage | Controlled check | Required observation |
|---|---|---|
| Request | Request reset for a tester-owned account | Response behavior and test mailbox event |
| Re-request | Request a second reset only within policy | Whether earlier proof is invalidated as documented |
| Verify | Submit malformed/expired/reused proof | Rejected without changing account state |
| Complete | Use valid proof for the intended account/action | Test account's credential state changes exactly once |
| Existing sessions | Reuse the tester's old session on a harmless protected endpoint | Revocation matches the product's documented policy |
| Link construction | Compare generated URL with trusted canonical host | Untrusted request authority does not control the destination |
| Notification | Inspect message headers and destination for owned mailbox | No unintended recipient or token disclosure in logs/referrer |

### Evidence hygiene

Store mailbox message ID, request correlation ID, timestamps, token metadata (not token value), account fixture, state before/after, and cleanup result. Keep raw recovery links and codes out of reports, shell history, shared notes, and commits. If a raw token accidentally appears in output, revoke it and remove the artifact.

### Chain rules

- Generated reset URL is influenced by Host/forwarded metadata → host-header review; do not follow links containing real tokens.
- Old session stays authorized after reset contrary to policy → session lifecycle review.
- Recovery proof crosses accounts or actions → identity binding defect; demonstrate only between two test-owned accounts.
- Different response wording without a reliable oracle → record as possible enumeration only if policy and repeatable evidence support it; do not overstate takeover.


## Practical tooling, references, and helper scripts (2026-10-19)

### Tools that fit this skill
- Burp Repeater and browser DevTools with controlled accounts; never print cookies, OTPs, reset links, or tokens.
- Treat CLIs as optional until locally verified. Prefer read-only checks; state-changing tests require permission and a disposable fixture.

### Primary resources
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) — auth controls.
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) — session lifecycle.
- [PortSwigger Academy](https://portswigger.net/web-security) — controlled labs.

### Small reusable helper
    python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt
Compares local artifacts offline with heuristic redaction; no requests are sent and sanitization is not guaranteed.

### Evidence and hand-off
- Keep cookies, tokens, reset links, private user data, and secret values out of notes, global research storage, and Git commits. Keep private originals local; share only reviewed derivatives.
- Mark outcomes confirmed, disproven, or still hypothetical. Record tool errors and coverage gaps rather than inventing results.

Compare baseline and control, vary one meaningful property, and record alternative explanations before confirming a lead.
