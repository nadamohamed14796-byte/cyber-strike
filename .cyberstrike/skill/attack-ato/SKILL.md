---
name: attack-ato
description: "Assess account-takeover paths through controlled authentication and recovery testing"
category: "authentication"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [ato, authentication, sessions, recovery, authorization]
tech_stack: [web, http, api, browser]
prerequisites:
  - "Explicit authorization for authentication testing"
  - "Dedicated test accounts and documented lockout/rate-limit policy"
chains_with: [attack-auth-bypass, attack-password-reset, attack-mfa-bypass, attack-oauth, attack-saml, attack-idor-automation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-ato/SKILL.md"
---

# Account Takeover (ATO) Assessment

## When to use

Use when an observed workflow could let an attacker gain control of an account without its owner's authorization: login, password recovery, email/phone change, MFA enrollment/removal, session management, OAuth linking, or account invitation.

## Safety gate

Only test dedicated accounts you control and that are explicitly permitted by the program. Never target real users, send unsolicited recovery messages, guess real credentials, reuse leaked credentials, or attempt high-volume credential stuffing. Respect lockout thresholds and stop before triggering account lockout or notification floods.

## Procedure

1. **Map the account lifecycle.** List login, logout, password reset, email verification, MFA, trusted devices, session revocation, OAuth linking, and account deletion flows.
2. **Create a baseline.** Use two test accounts you control where cross-account comparisons are needed. Record the expected owner, email, session, and recovery state.
3. **Test recovery token properties.** Review expiry, single-use behavior, binding to the intended account, invalidation after password change, and resistance to replay. Do not brute-force tokens; use only issued tokens for your test accounts.
4. **Test identity changes.** Check whether changing email, phone, password, or MFA requires reauthentication or confirmation as documented. Use only controlled accounts and reversible changes.
5. **Test session lifecycle.** After a controlled password reset or logout-all action, verify whether prior sessions and refresh tokens are invalidated according to policy.
6. **Test account linking.** Verify OAuth/SSO identities are bound to the correct local account and cannot silently link to an account with a different verified identity. Do not link third-party identities you do not control.
7. **Test rate limits conservatively.** Use a small, program-permitted number of attempts. Record throttling and stop at the documented limit; no password spraying or credential stuffing.
8. **Validate the chain.** Each step must be demonstrated on the controlled account. Do not label a theoretical sequence as ATO unless the full unauthorized control path is reproducible.
9. **Restore state.** Remove temporary links, revoke sessions, and return test accounts to their original state where permitted.

## Pitfalls

- A reset token appearing in a response is not automatically a vulnerability if it is only delivered to the account owner.
- A login error difference is not proof of account takeover by itself.
- Missing rate limiting requires policy context and safe bounded testing.
- Account enumeration, session fixation, password reset, OAuth, and MFA may need separate focused validation.

## Verification

Demonstrate the exact unauthorized control boundary using accounts you own: which step bypassed which expected control, what state changed, and how the new state was verified. If proof requires access to a real user's account, stop and report the suspected path without attempting it.

## Evidence

Keep a timeline of requests, test-account identifiers (not passwords), token lifecycle observations, session invalidation results, and redacted responses. Never save live credentials or recovery tokens in committed files.
