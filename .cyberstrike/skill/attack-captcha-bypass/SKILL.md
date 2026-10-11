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

## References

- [Claude-BugHunter — hunt-captcha-bypass](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-captcha-bypass)
- [OWASP Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
