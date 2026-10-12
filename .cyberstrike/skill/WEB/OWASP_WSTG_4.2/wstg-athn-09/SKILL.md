---
name: wstg-athn-09
description: "Testing for Weak Password Change or Reset Functionalities"
category: authentication
owasp_id: WSTG-ATHN-09
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [authentication, password-reset, recovery, sessions, wstg]
tech_stack: [http, web, api]
cwe_ids: [CWE-640, CWE-620]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-forgot-password/SKILL.md"
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-ato/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
  - "https://owasp.org/www-project-web-security-testing-guide/"
---

# WSTG-ATHN-09: Password Change and Reset

## Objective

Assess whether password change and recovery flows correctly bind tokens to the intended account, enforce expiry and single-use behavior, require appropriate identity verification, and invalidate sessions according to policy.

## Preconditions and safety

Use only accounts and email addresses you control. Do not trigger reset messages to real users, guess tokens, brute-force codes, or collect another person's recovery link. Respect rate limits and stop before lockout or notification flooding.

## Procedure

1. Map password change, forgotten-password, email verification, MFA recovery, and session revocation flows.
2. Establish a baseline using a controlled account and record the expected verification steps and recovery delivery channel.
3. Check token lifecycle: expiration, single use, replay rejection, account binding, and invalidation after a new reset or password change. Use only issued test tokens.
4. Check whether the reset request reveals whether an account exists. Evaluate response body, timing, and delivery behavior conservatively; do not enumerate real users.
5. Verify whether changing email/password requires reauthentication or confirmation according to the application's security model.
6. Check whether a reset token can be used across accounts or sessions only with test-owned accounts. Never attempt to reset a third party's account.
7. After a controlled password reset, verify whether existing sessions, refresh tokens, and remember-me tokens are invalidated as documented.
8. Check low-volume rate limiting and anti-automation controls without continuing after throttling or lockout signals.
9. Restore account state and revoke test sessions where permitted.

## Common false positives

- A reset token is visible to the owner through the expected delivery channel.
- A generic response differs in timing due to network noise.
- A session remains active by documented design and has compensating protections.
- An endpoint returns success but does not actually change the password.
- A theoretical token-replay path was not tested on a controlled account.

## Evidence and output

Record flow, test account, redacted token metadata (never the token value), expiry/replay result, account-binding result, session invalidation, rate-limit behavior, cleanup, impact, and confidence. Recommend cryptographically random single-use tokens, short expiry, uniform responses, secure delivery, reauthentication for sensitive changes, and documented session revocation.
