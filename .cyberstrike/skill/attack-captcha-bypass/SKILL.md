---
name: attack-captcha-bypass
description: "Assess CAPTCHA and anti-automation controls with bounded, policy-compliant tests"
category: "web-application"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [captcha, anti-automation, rate-limit, authentication]
tech_stack: [web, browser, http]
prerequisites:
  - "Explicit permission to test the relevant workflow"
  - "Dedicated test account and documented request/attempt limits"
chains_with: [attack-rate-limit-bypass, attack-auth-bypass, attack-ato, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-captcha-bypass/SKILL.md"
---

# CAPTCHA and Anti-Automation Assessment

## When to use

Use when CAPTCHA, bot detection, challenge tokens, or anti-automation controls protect a login, signup, recovery, search, or other sensitive workflow.

## Safety gate

Do not solve or outsource large volumes of challenges, bypass third-party service terms, spray credentials, or trigger high-volume account creation. Test only the permitted workflow with a small number of requests and stop at rate limits.

## Procedure

1. Map where the challenge appears and which server-side action it is meant to protect.
2. Capture a normal successful test-account flow and record challenge token issuance, binding, expiry, and verification response.
3. Check whether the protected endpoint rejects missing, malformed, expired, or already-used challenge tokens using a small number of controlled requests.
4. Compare browser and direct API paths only when both are in scope; the server must enforce the challenge, not rely solely on a hidden UI element.
5. Check whether the token is bound to the intended action/session and whether a token issued for one workflow can be replayed in another.
6. Verify the actual protected action remains blocked when challenge verification fails. Do not perform repeated attempts to discover thresholds.
7. Record response semantics, expected control, and any program-approved test limits.

## Pitfalls

- A challenge appearing in the UI does not prove server enforcement.
- Different challenge behavior across browsers may be expected.
- CAPTCHA alone is not a substitute for rate limiting and abuse monitoring.
- Do not infer a bypass from a single unusual response.

## Verification

Confirm a protected action can be completed despite a failed or absent challenge, within the explicitly allowed test boundary. Document the minimal request pair and impact without using real accounts or high-volume automation.
