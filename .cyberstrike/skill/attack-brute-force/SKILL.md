---
name: attack-brute-force
description: "Assess authentication throttling and lockout controls without credential spraying"
category: "authentication"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [brute-force, rate-limit, lockout, authentication]
tech_stack: [web, http, api]
prerequisites:
  - "Explicit permission for authentication-control testing"
  - "Dedicated test account and documented attempt limits"
chains_with: [attack-rate-limit-bypass, attack-captcha-bypass, attack-ato, attack-auth-bypass]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-brute-force/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/redteam/password-spray-methodology/SKILL.md"
---

# Brute-Force Control Assessment

## When to use

Use when checking whether login, recovery, OTP, or verification workflows enforce appropriate throttling and lockout controls.

## Safety gate

Never run password spraying, credential stuffing, leaked-password tests, or high-volume guessing against real accounts. Use a dedicated test account, a small approved number of invalid attempts, and stop at the documented threshold.

## Procedure

1. Confirm the test endpoint, account, program limit, and expected lockout/throttle policy.
2. Capture baseline behavior for one successful test-account login and one invalid attempt.
3. Perform only a small, explicitly permitted sequence of invalid attempts using a known invalid value.
4. Observe rate-limit headers, cooldown behavior, challenge escalation, lockout notifications, and whether the counter is shared across equivalent endpoints.
5. Check alternate login surfaces only if they are in scope and have a concrete reason to differ.
6. Verify whether the limit applies per account, IP, device, session, or combination; do not rotate identities/IPs to defeat a control.
7. Confirm that legitimate access recovers as documented and avoid locking the account.
8. Document limits observed and the safe stopping point.

## Pitfalls

- One successful attempt does not prove no rate limiting.
- Rate limits may be adaptive or shared across services.
- CAPTCHA and MFA are complementary controls, not substitutes for throttling.
- A numeric threshold is not a vulnerability without policy and impact context.

## Verification

Report the exact bounded test sequence, expected policy, observed throttling/lockout, account state, and impact. Do not extrapolate to high-volume attack success.
