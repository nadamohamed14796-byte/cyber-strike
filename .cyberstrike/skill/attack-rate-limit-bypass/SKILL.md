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


## Rate-control evidence matrix

| Protected action | Control to record | Safe evidence |
|---|---|---|
| Login / MFA | Test account, challenge lifecycle, lockout/reset behavior | Provider test account only; no credential guessing or spraying |
| Password reset / invitation | Per-account and per-resource limits | Test-owned destination and synthetic workflow |
| Search / export | Per-identity, tenant, route, and cost unit | Small read-only samples plus documented policy |
| Coupon / one-time benefit | Replay/idempotency vs rate limit | Disposable non-monetary fixture; persisted redemption state |
| API quota | Authenticated principal, API key/client, tenant | Two controlled identities and response/quota telemetry |
| Proxy-derived identity | Trusted edge configuration and origin behavior | Configuration/log review; no spoofed-header bypass attempts on production |

### What to record per observation

Store action_id, policy_source, identity_key_hypothesis, window_start/end, configured_threshold_if_known, request_sequence_ref, server_decision, quota_state, downstream_action_state, edge_or_origin_attribution, stop_reason, and cleanup. Do not infer the configured threshold from a few requests if the limit was not reached.

### Chain routing

- Limit failure enables repeated OTP/password attempts → authentication/MFA review, but do not perform credential guessing.
- Duplicate one-time operation succeeds because state transition is not atomic → business-logic/race review with a disposable fixture.
- Only expensive query cost is unbounded → API resource-consumption review.
- A limit is absent but the action is harmless/public and no meaningful abuse path is demonstrated → document the control observation without claiming high severity.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Use Burp Repeater/Comparer to observe the application's documented rate-limit behavior and a tiny, controlled request set. Burp Intruder or equivalent automation is optional and should only be used where program rules permit the exact test rate.

### Installation and setup
- [Burp Community](https://portswigger.net/burp/communitydownload) — official installer and browser setup.
- jq on Kali/Debian: `sudo apt update && sudo apt install jq` for local response metadata.
Do not use proxy rotation, distributed sources, account farms, CAPTCHA-solving services, or other methods intended to evade the program's protections. The aim is to verify security control behavior using a controlled test account, not to exceed a real user's permitted quota.

### Primary resources
- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x00-header/) — resource-consumption risk context.
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) — login protection.
- [PortSwigger rate limiting research/labs](https://portswigger.net/web-security) — controlled test environments.

### Reusable helper
`python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt` compares saved response artifacts offline and generates no traffic.

### Result handling
Record the documented limit, request spacing/count, status/headers, reset behavior, and user-visible impact. Stop as soon as a safe, reproducible control failure is established.

## Agent-executable CLI tooling, resources, and helper scripts

Use CLI tools and local scripts directly. Browser UI, browser extensions, and interactive intercepting proxies are not dependencies. Check availability/version and official documentation before use; active tests require explicit authorization and low-impact settings.

### Recommended tools
- curl/Python requests — single-variable rate-limit checks
- jq — parse rate-limit headers and JSON responses
- A local request ledger with timestamps and retry-after tracking
- http_response_diff.py — compare baseline and throttled behavior

### Resources
- https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- https://portswigger.net/web-security/race-conditions
- https://github.com/vavkamil/awesome-bugbounty-tools

Treat community lists as discovery aids and verify current maintenance and behavior from official sources.

### Helper-script contract
Use a conservative explicitly authorized request budget and stop on degradation or server errors. Record identity/key scope, window, retry-after, response codes, and reset behavior; don't bypass controls at scale.

Preserve raw evidence separately from normalized results; record tool/version, timestamps, identity/context, errors, confidence, redaction, and output paths. Use structured output and deterministic local fixtures.

### Handoff
Return actual command/version, input/output paths, request counts, controls, errors, confidence, limitations, and next skill. Blocked or unexecuted tests must remain inconclusive.
