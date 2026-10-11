---
name: attack-session-management
description: "Review session lifecycle, cookie protections, fixation risk, and revocation behavior"
category: "authentication"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [sessions, cookies, authentication, revocation]
tech_stack: [http, cookies, web, api]
prerequisites:
  - "Authorized application and dedicated test account"
  - "Permission for login/logout and session lifecycle tests"
chains_with: [attack-auth-bypass, attack-ato, attack-password-reset, attack-mfa-bypass]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-session/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
---

# Session Management Assessment

## When to use

Use when evaluating session cookies, refresh tokens, logout, password change, privilege change, session renewal, or concurrent-session behavior.

## Safety gate

Only use test accounts and tokens you control. Do not copy or replay another user's session, expose live tokens in evidence, or invalidate sessions for real users.

## Procedure

1. Capture cookie and token attributes: Secure, HttpOnly, SameSite, domain/path scope, expiry, and rotation behavior.
2. Record the session identifier before and after login, privilege changes, and reauthentication to check whether rotation occurs where expected.
3. Verify logout invalidates the current session and, where documented, refresh tokens or server-side sessions.
4. Change the test account's password and verify prior sessions behave according to the application's stated policy.
5. Check whether session tokens are bound to the correct account and environment; avoid fingerprint-based assumptions without evidence.
6. Review idle and absolute timeouts using a controlled session and short, permitted waits.
7. Compare browser and API session handling only when both surfaces are in scope.
8. Record each transition and redact all token values.

## Pitfalls

- Cookie attributes reduce risk but do not prove full session security.
- Client-side token deletion may not revoke a server-side session.
- Persistent login can be intentional if protected by rotation and revocation.
- Do not claim session fixation solely from a stable token unless the threat model and control failure are demonstrated.

## Verification

Provide session lifecycle timeline, relevant headers with token values removed, expected policy, observed revocation/rotation behavior, and impact.
