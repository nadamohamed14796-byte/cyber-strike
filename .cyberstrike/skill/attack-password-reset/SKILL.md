---
name: attack-password-reset
description: "Assess password-reset and account-recovery controls with test identities and low-impact validation"
category: "authentication"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [password-reset, recovery, tokens, authentication]
tech_stack: [http, email, browser, api]
prerequisites:
  - "Authorized application and controlled test email accounts"
  - "A reset flow that can be safely exercised and cleaned up"
chains_with: [attack-auth-bypass, attack-mfa-bypass, attack-triage-validation, attack-evidence-hygiene]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-forgot-password/SKILL.md"
---

# Password Reset and Account Recovery

## When to use

Use when an application supports password reset, email verification, recovery links, backup factors, or account unlock flows.

## Preconditions and safety

Use only accounts and mailboxes you control. Do not request resets for real users, intercept third-party emails, or change another user's password. Follow email-volume limits and avoid repeated requests that could trigger lockouts or abuse controls.

## Procedure

1. **Map the full flow.** Record reset initiation, response behavior, email delivery, token validation, password change, token consumption, and session invalidation.
2. **Compare responses safely.** Using controlled valid and invalid test addresses, check whether response text, status, or timing reveals account existence. Keep request counts minimal.
3. **Review token exposure.** Check whether reset tokens appear in unintended responses, logs, referrers, analytics, or browser history. Never publish or reuse a live token.
4. **Check token properties.** Verify that tokens expire, are bound to the intended account and purpose, and are invalidated after successful use.
5. **Check replay with a test account.** After consuming a reset token on your own account, confirm that the same token cannot be used again.
6. **Check flow binding.** Determine whether the token is bound to the expected account and action. Use controlled test identities and do not attempt cross-account resets.
7. **Review rate limits.** Check documented controls and perform only a small approved number of requests. Do not run automated high-volume enumeration.
8. **Check session consequences.** Confirm whether password reset invalidates existing sessions or requires reauthentication, according to policy.
9. **Record evidence.** Save sanitized requests, response differences, token lifecycle observations, and the exact violated control.

## Verification

A finding requires a reproducible security-relevant failure such as reusable/incorrectly bound reset tokens, unintended token disclosure, or a demonstrated account-enumeration channel accepted by the program policy. Do not claim account takeover unless it is safely and explicitly demonstrated with controlled accounts.

## Pitfalls

- Using real users' email addresses.
- Exposing live reset tokens in logs or reports.
- Treating minor timing variance as enumeration without repeated controlled observations.
- Reusing a token beyond the authorized test.
- Ignoring rate limits or session invalidation behavior.

## Remediation guidance

Use cryptographically random single-use tokens, short expiry, purpose and account binding, generic initiation responses, rate limiting, secure token transport, and appropriate session invalidation.

## CyberStrike integration contract

Verify test-mailbox support, token redaction, safe state-change controls, and evidence storage before automation. Do not send reset emails to uncontrolled recipients.

## Attribution

Adapted from Claude-BugHunter hunt-forgot-password: https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-forgot-password/SKILL.md
