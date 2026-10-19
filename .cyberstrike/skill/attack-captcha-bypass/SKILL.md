---
name: attack-captcha-bypass
description: "Review CAPTCHA and anti-automation gates for server-side enforcement, action binding, and replay resistance using test environments and bounded requests."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - captcha
  - anti-automation
  - rate-limit
  - authentication
  - abuse-prevention
tech_stack:
  - web
  - rest-api
  - javascript
  - identity
cwe_ids:
  - CWE-804
  - CWE-307
chains_with:
  - attack-auth-bypass
  - attack-rate-limit-bypass
  - attack-ato
prerequisites: []
severity_boost:
  attack-ato: "A CAPTCHA gap supports ATO only if an authorized test-account flow demonstrates a meaningful account-security consequence."
---

# CAPTCHA and Anti-Automation Assessment

## Objective

Determine whether CAPTCHA decisions are validated server-side, bound to the intended action/session, and protected against replay. Use provider test keys or staging fixtures; do not automate real challenge solving or brute-force protected endpoints.

## Testing Methodology

### Phase 1: Map challenge workflows

Identify where challenge is shown, which action requires it, whether server-side verification occurs, and what token/session ties it to the request.

### Phase 2: Capture accepted/rejected baselines

Use provider test keys, vendor test mode, or sandbox fixtures to compare a valid challenge with absent/invalid test data. Record the server decision, not just widget display.

### Phase 3: Test action binding and replay

In a lab, check whether token is bound to action, hostname/site key, expiry, and session where required. Compare one valid token against intended and different test action only within the sandbox.

### Phase 4: Verify server enforcement

Check whether protected operation is directly reachable by API without server-validated challenge state. Use an innocuous reversible test operation.

### Phase 5: Review fail-open behavior

Inspect timeout/provider-error branches in code or staging. Do not intentionally degrade the provider in production. Confirm sensitive action follows documented fail-closed/risk policy.

## What Constitutes a Finding

- **Candidate / lead:** challenge appears client-side only or provider errors lead to success-shaped responses.
- **Confirmed finding:** test workflow executes protected action without valid server-side verification or accepts an out-of-context/replayed sandbox token.
- **Not a finding:** widget is hidden while equivalent server-side risk checks are enforced.

## Evidence Requirements

- Endpoint, provider test mode, timestamp, test session, and policy.
- Valid/invalid/missing/replayed test-token requests with secrets redacted.
- Authoritative server decision and harmless operation state.
- No real challenge-solving services, bulk retries, or real-user challenge data.

## Tools

- **Browser DevTools:** trace challenge and verification calls.
- **Burp Suite:** compare direct API requests in a sandbox.
- **Provider sandbox keys:** deterministic positive/negative test cases.
- **Source/log review:** confirm token verification, action/host binding, and error handling.

## Challenge Enforcement Matrix

| Condition | Expected result | Risk signal |
|---|---|---|
| Valid test token | Allowed for intended action | Token is not bound to the expected action/host when required |
| Missing/invalid token | Protected action denied | Server trusts a frontend flag alone |
| Expired/replayed token | Rejected per provider contract | One token authorizes unrelated/repeated test actions |
| Provider timeout | Bounded failure behavior | Sensitive action fails open contrary to policy |
| Direct API request | Backend verifies challenge | Client-side-only control |
| Alternate route/version | Same enforcement policy | Legacy route omits verification |

**Mitigation:** verify tokens server-side, bind action/host, define failure policy, responsibly rate-limit, and use provider test modes for regressions.

## Verification and False Positives

- Risk-based flows may omit a visible widget while server-side scoring remains enforced.
- Provider token behavior changes; verify official docs and sandbox.
- A 200 response may still mean denial; inspect state.
- Avoid challenge-solving services, high-volume retries, credential stuffing, and production load tests.


## Adaptive Verification Contract (evidence-driven; no arbitrary attempt ceiling)

Continue testing materially distinct, evidence-producing hypotheses while the candidate remains plausible and a meaningful next branch exists. Do not impose a fixed attempt ceiling or count cosmetic retries as new hypotheses. Stop when direct evidence confirms or disproves this hypothesis, no meaningful new branch remains, a valid prerequisite is unavailable, or program/safety rules require stopping; unresolved cases remain inconclusive.

Keep a compact ledger for every attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve raw evidence locally, redact secrets, and avoid collecting unrelated user data.

### Skill-specific hypothesis order

1. Use only test-owned accounts and a program-approved test flow; capture the normal challenge issuance, token submission, success/failure outcome, and retry behavior.
2. Check server-side enforcement at each relevant step: challenge omission, empty/expired token, invalid token, token replay, and challenge/session mismatch. Change only one condition per request.
3. Compare login, registration, password recovery, and other routes only if they exist and share the same documented security requirement; a route with no CAPTCHA requirement is not inherently vulnerable.
4. Measure whether the challenge actually gates the protected operation using a harmless canary or test account, while respecting retry caps and avoiding account lockouts or third-party CAPTCHA-solving services.
5. Repeat with a fresh valid challenge as a positive control and an invalid challenge as a negative control. Report the control failure only when an action proceeds without the required server-side verification.


### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture, with a relevant control and a clear trust-boundary failure.
- **Likely / needs corroboration:** multiple independent signals support the hypothesis, but the security consequence or root cause is not yet established.
- **Unconfirmed:** evidence is incomplete, ambiguous, cached, or indistinguishable from a generic response.
- **Refuted / false positive:** a relevant negative control, valid authorization explanation, or repeatable contradictory evidence explains the signal. Record what was tested; do not claim that every theoretical variant was exhausted.
- A status code, banner, stack trace, response-length difference, endpoint existence, tool alert, or visible frontend state is never sufficient on its own.

### Stop and cleanup rules

Stop immediately on an out-of-scope boundary, unexpected real-user data, production side effects, rate-limit/availability degradation, credential exposure, or a request to perform a prohibited action. Do not continue merely to spend the budget. Restore disposable test state, revoke temporary sessions/tokens where possible, and record cleanup status.

### Agent handoff record

Return: skill, target asset, in-scope evidence, baseline, candidate hypothesis, attempts used, observed impact, negative controls, confidence/verdict, related-skill signal, sanitized evidence references, and cleanup status. Invoke a chained skill only when the stated signal is independently observed; do not chain from name similarity alone.

## References

- [Claude-BugHunter — hunt-captcha-bypass](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-captcha-bypass)
- [OWASP Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)


## Safe validation pattern
Use a staging instance or an explicitly authorized test account and a normal first-party client flow. Capture baseline attempts with valid and invalid challenge state, then determine server-side enforcement without automating large submission volumes or trying to evade service controls.

```text
Record: action, test account, challenge provider, challenge token age, server decision, retry-after/lockout behavior
Compare: normal flow vs missing/expired/replayed test token; keep other request fields identical
Verify: server-side action did not occur when challenge validation should fail
```

Do not use proxy rotation or solve/bypass services against a live program. Impact is a demonstrated abuse-sensitive action available without an enforced control, not merely a client-side challenge disappearing. Chain to attack-rate-limit-bypass only when the program permits abuse-control validation and there is a separately observed enforcement weakness.


## Enrichment: safe server-side validation
Use staging or an expressly authorized test account. Compare a normal action with a missing, expired, or replayed challenge token while keeping the rest of the request unchanged. Confirm from server-side state whether the action was rejected. Do not use proxy rotation, third-party solving services, or high-volume submissions against a live program. A client-side challenge disappearing is not impact; the server must actually permit an abuse-sensitive action that policy says should be blocked. Chain to rate-limit testing only where program rules expressly permit that assessment.
