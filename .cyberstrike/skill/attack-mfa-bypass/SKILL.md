---
name: attack-mfa-bypass
description: "Assess MFA enforcement, recovery, and step-up authentication using controlled test accounts"
category: "authentication"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [mfa, 2fa, authentication, recovery, rate-limit]
tech_stack: [http, browser, otp, identity]
prerequisites:
  - "Explicit authorization and test accounts with MFA enabled"
  - "Program-approved limits for OTP and recovery-flow checks"
chains_with: [attack-auth-bypass, attack-password-reset, attack-triage-validation, attack-evidence-hygiene]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-mfa-bypass/SKILL.md"
---

# Multi-Factor Authentication Assessment

## When to use

Use when login, sensitive account actions, session elevation, recovery codes, or alternate authentication routes rely on MFA or step-up authentication.

## Preconditions and safety

Use only controlled accounts. Do not brute-force OTPs, trigger push fatigue, test real users, or attempt account takeover. Rate-limit testing must stay within explicitly approved low attempt counts and stop immediately on lockout or provider warnings.

## Procedure

1. **Map the states.** Record pre-login, password-accepted, MFA-pending, MFA-verified, recovery, and logged-out states.
2. **Capture the normal flow.** Complete a successful test login and identify the server-side signal that represents MFA completion.
3. **Check route consistency.** Verify that sensitive endpoints enforce the required MFA state, including direct navigation and API calls, without changing sensitive data.
4. **Check session transitions.** Confirm that session identifiers or claims are appropriately updated after MFA and invalidated at logout or security-sensitive changes.
5. **Review recovery methods.** Inspect documented recovery-code handling and factor replacement flows using controlled accounts. Verify that recovery requires the intended identity proof and that consumed codes cannot be reused in a test fixture.
6. **Review rate limits safely.** Inspect configured limits and perform only a few approved negative tests. Do not enumerate a full OTP keyspace or automate high-volume attempts.
7. **Check factor downgrade.** Determine whether a weaker factor can be selected without the required verification or policy approval, using a test account only.
8. **Validate the outcome.** Demonstrate access to a harmless protected test resource without the required MFA state; do not chain to real account changes.
9. **Record evidence.** Include flow state, request, response, expected enforcement, and observed result.

## Verification

A finding requires proof that a controlled session can access a resource or complete an action that requires MFA without completing the required factor. A missing UI prompt is not enough if the server enforces MFA.

## Pitfalls

- Treating client-side navigation as proof of server-side bypass.
- Performing high-volume OTP attempts.
- Triggering push notifications to real users.
- Ignoring recovery and factor-change policy.
- Claiming account takeover without demonstrating the relevant impact.

## Remediation guidance

Enforce MFA server-side at every sensitive boundary, bind session state to successful factor completion, rate-limit verification attempts, make recovery codes single-use, and require strong reauthentication for factor replacement.

## CyberStrike integration contract

Verify the auth-state model, rate limiter, safe test-account support, and evidence schema before automation. High-volume MFA attempts must remain disabled.

## Attribution

Adapted from Claude-BugHunter hunt-mfa-bypass: https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-mfa-bypass/SKILL.md
