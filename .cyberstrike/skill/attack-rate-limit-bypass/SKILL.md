---
name: attack-rate-limit-bypass
description: "Assess rate-limit enforcement and identity keying with low-volume, policy-compliant tests"
category: "web-application"
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [rate-limit, abuse-prevention, authentication, api]
tech_stack: [http, api, web]
cwe_ids: [CWE-307]
chains_with: [attack-triage-validation]
prerequisites:
  - "Explicit authorization for rate-limit testing"
  - "Known test account, documented request budget, and stop threshold"
sources:
  - "https://github.com/uphiago/recon-skills"
  - "https://owasp.org/www-project-web-security-testing-guide/"
---

# Rate-Limit Enforcement Assessment

## Objective

Determine whether a security-sensitive action is protected by effective server-side rate limits and whether limits are keyed to the appropriate identity and resource. Do not attempt to overwhelm the service or bypass limits using real-user identities.

## Safety gates

- Confirm the exact endpoint and permitted request count.
- Use a dedicated account and low-volume tests; stop at the first lockout, CAPTCHA, throttling response, or service instability.
- Do not rotate real IPs, use proxy networks, or automate credential guessing. Header variations should be limited to verifying documented proxy trust behavior, not evading protections at scale.
- Never test password spraying or credential stuffing under this skill.

## Procedure

### 1. Define the protected action

Identify login, password reset, OTP, invitation, coupon, search, export, or API operation. Record the expected policy: requests per identity, IP, device, resource, or time window.

### 2. Establish a baseline

Make a small number of normal requests with a controlled account and record status, response headers, retry guidance, CAPTCHA/lockout behavior, and timing. Confirm the test endpoint is not shared with real users.

### 3. Check enforcement consistency

Within the approved budget, compare equivalent requests across relevant dimensions: authenticated vs anonymous, account vs IP, alternate HTTP methods where supported, normalized path variants, and different test-owned accounts. Do not assume headers such as `X-Forwarded-For` are trusted or safe to manipulate; verify proxy configuration only when explicitly permitted.

### 4. Validate limit state

Confirm whether the server actually blocks or slows requests after the allowed threshold and whether the window resets as documented. Distinguish edge/CDN throttling from application-level enforcement. Do not continue after a limit is reached merely to search for a bypass.

### 5. Assess impact

Explain the security control being bypassed and the bounded action enabled, such as excessive OTP requests or repeated password attempts. Missing limits on a low-risk endpoint are not automatically a vulnerability; severity depends on reachable abuse and mitigations.

## Common false positives

- A rate limit exists at a gateway not visible from the response.
- A test did not reach the configured threshold.
- A 429 response comes from an intermediary rather than the application.
- Different endpoints intentionally have different budgets.
- A theoretical header bypass was not verified with an approved proxy configuration.

## Output contract

Return `endpoint`, `action_type`, `test_account`, `request_budget`, `limit_key_hypothesis`, `threshold_observed`, `retry_behavior`, `impact`, `stop_reason`, `confidence`, and redacted evidence.


## Targeted quality-loop enrichment (2026-10-19)

### Rate-control semantics and business consequence
Determine the key the control appears to count (account, session, client, source IP, route, action, or time window) using a small approved set of test-owned identities in staging/sandbox. Record reset window, retry semantics, response headers, server-side outcome, and a normal/blocked control. Do not rotate proxies, evade detection, brute force credentials, or generate load on a production service. A missing 429 is not proof if downstream action is still protected. Assess a realistic consequence such as one-use challenge replay only with vendor test fixtures; route login/MFA outcomes to auth skills and paid/limited business operations to workflow review.
