---
name: wstg-athn-09
description: "Testing for Weak Password Change or Reset Functionalities"
category: authentication
owasp_id: WSTG-ATHN-09
version: "1.2.0"
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

Assess whether password change, recovery, and account re-verification flows correctly establish user intent, bind reset capabilities to the intended account, enforce token lifecycle rules, protect recovery channels, and revoke sessions according to the application's security model.

## Preconditions and safety

- Confirm written authorization, in-scope hosts, test window, accounts, mailboxes, and request limits.
- Use only accounts, addresses, devices, and recovery channels controlled by the tester. Prefer a dedicated disposable account.
- Do not guess or brute-force tokens, collect another person's recovery link, send reset mail to real users, or attempt account takeover.
- Use a small number of deliberate requests. Stop immediately on throttling, lockout warnings, unexpected notifications, or production impact.
- Keep token values and passwords out of reports, terminal transcripts, screenshots, and persistent notes. Redact secrets before storing evidence.

## Workflow map and baseline

1. Inventory password change, forgotten-password, recovery-code, email/phone change, MFA recovery, and session-revocation paths exposed by the UI, API schema, and in-scope traffic.
2. Record each endpoint's method, required authentication, CSRF protection where applicable, expected identity proof, response behavior, and delivery channel.
3. Establish a baseline with a controlled account: request recovery, receive the expected message, use the issued link/code once, set a known test password, and verify the documented result.
4. Save redacted request/response pairs and timestamps. Store only token metadata (format, issue time, expiry observation, and whether consumed), never the token itself.
5. Separate flows that share a UI but use different backends or token types; do not assume password reset, email verification, and MFA recovery have identical guarantees.

## Test procedure

### 1. Identity proof and reauthentication

- Check whether a logged-in user must provide the current password or a recent authentication step before changing credentials, disabling MFA, or changing recovery channels.
- Determine whether sensitive actions require confirmation through a previously verified channel.
- Compare behavior for a normal session and a deliberately expired or reauthenticated test session.
- Verify server-side enforcement; hiding a form field or disabling a button is not sufficient evidence.
- Treat product-specific exceptions as hypotheses until confirmed against documented policy.

### 2. Token binding, lifetime, and single use

- Use only tokens issued to the controlled test account.
- Confirm a newly issued token works for its intended flow and becomes unusable after successful consumption.
- If the application issues a second token, verify that superseding a token invalidates the older token when that is documented policy.
- Observe expiration naturally within the permitted test window; do not manipulate another user's token or attempt to predict token values.
- Confirm a token cannot be used for a different controlled account or purpose, such as an email-verification token as a password-reset token.
- Record outcomes for expired, consumed, superseded, malformed, and wrong-purpose tokens. Avoid repeatedly submitting invalid values.

### 3. Account enumeration and response consistency

- Compare one known test account with one deliberately nonexistent address reserved for testing.
- Compare response semantics, status, body shape, and obvious timing differences across a small number of requests; account for network noise and asynchronous email delivery.
- Do not enumerate lists of real addresses or use bulk requests.
- A different response is a lead, not proof by itself. Confirm that an unauthenticated party can reliably infer account existence and document practical impact.

### 4. Recovery-link construction and leakage

- Inspect generated links using the controlled mailbox. Verify the destination host is the expected canonical application origin and does not derive from an untrusted Host, Forwarded, or X-Forwarded-Host value.
- Only in a dedicated authorized environment, change one forwarding header on a single test request and inspect the resulting message. Do not send a link to an external collector or open a malicious link.
- Review whether recovery tokens can leak through referrer headers, analytics, third-party resources, application logs, browser history, or redirect parameters.
- Confirm TLS is used and the token is not unnecessarily copied into unrelated redirects or client-visible telemetry.
- Redact the link immediately after recording non-secret metadata.

### 5. Password policy and state transition

- Verify the server enforces the documented password policy and rejects invalid or disallowed values, regardless of client-side validation.
- Use only a test account and a small set of representative boundary cases; do not use password spraying or credential stuffing.
- Confirm the account's credential state changes only after a successful authorized operation.
- Check whether password-change and reset flows return consistent errors without exposing secrets or internal implementation details.
- Confirm any required notification is sent to the expected, controlled channel.

### 6. Session and credential revocation

- Before changing a test password, record behavior of a second session that also belongs to the tester.
- Complete a controlled password change/reset, then verify whether existing sessions, refresh tokens, remembered devices, app passwords, and recovery tokens are revoked according to policy.
- Distinguish documented session-preservation behavior from a genuine failure; some systems intentionally preserve the current session while revoking other sessions.
- Do not test session revocation using another person's session or credentials.

### 7. Rate limiting and recovery abuse controls

- Review visible policy and headers for throttling, cooldowns, CAPTCHA, notification limits, and lockout protections.
- Use a few low-volume requests only. Do not automate token guesses, flood a mailbox, or continue after a throttle/lockout signal.
- Check whether a resend action invalidates old tokens and whether the UI clearly communicates cooldown behavior.
- Report bypasses only when demonstrated within the approved request budget and without causing account lockout or notification flooding.

### 8. Cleanup and repeatability

- Restore the controlled account to its agreed state, revoke temporary sessions, remove test recovery artifacts, and record any cleanup that could not be completed.
- Repeat a result only when needed to exclude transient behavior and still within approved limits.
- Preserve a minimal reproduction that another authorized tester can run without access to the original secret token.

## Decision criteria and common false positives

A finding requires a security-relevant, reproducible deviation from expected policy, not merely an unusual response.

Common false positives:
- A reset token is visible to its intended owner through the normal delivery channel.
- A generic response differs slightly in timing due to network or mail-delivery noise.
- The current session remains active by documented design while other sessions are revoked.
- An endpoint returns success but the credential state does not change.
- A token replay hypothesis was not tested using an issued token on a controlled account.
- A security control is asynchronous and the tester did not wait for the documented completion window.

## Evidence contract

Return:
- flow_map: relevant routes, methods, and channels, without secrets.
- test_account: opaque alias, never an email address or personal identifier.
- baseline: expected policy and redacted baseline references.
- token_lifecycle: issue/expiry/consumption/supersession observations without token values.
- identity_binding: result for account and purpose binding.
- enumeration_signal: controlled comparison, confidence, and noise limitations.
- session_effect: observed revocation behavior and documented expectation.
- rate_limit_behavior: request count and stop condition.
- impact, reproduction, cleanup_status, and confidence.

## Remediation guidance

Use cryptographically secure, single-use, purpose-bound tokens with appropriate short expiry; invalidate superseded tokens; rate-limit recovery requests; avoid account-enumerating responses; construct links from a trusted canonical origin; protect tokens from logs/referrers/analytics; require reauthentication for sensitive changes; and document session-revocation behavior.
