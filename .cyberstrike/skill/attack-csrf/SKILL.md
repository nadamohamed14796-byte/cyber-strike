---
name: attack-csrf
description: "Assess whether browser-authenticated state changes lack effective cross-site request protections"
category: "web-application"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [csrf, cookies, origin, browser-security]
tech_stack: [http, browser, web, api]
prerequisites:
  - "Authorized application and controlled test account"
  - "A reversible, low-impact state change approved for testing"
chains_with: [attack-triage-validation, attack-evidence-hygiene, attack-report-writing]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-csrf/SKILL.md"
---

# Cross-Site Request Forgery (CSRF)

## When to use

Use when an authenticated browser can change server-side state and the application relies on ambient credentials such as cookies. Prioritize profile preferences or disposable test records over sensitive account changes.

## Preconditions and safety

Use a controlled account and a reversible, low-impact operation. Do not test transfers, password/email changes, account linking, destructive actions, or actions affecting another user unless the program explicitly authorizes that exact scenario. A raw HTTP client can forge headers; that alone does not prove a browser can deliver a cross-site request.

## Procedure

1. **Inventory state-changing requests.** Record method, endpoint, content type, cookie behavior, CSRF token use, Origin/Referer checks, and SameSite attributes.
2. **Capture a legitimate baseline.** Use the controlled account to perform a harmless reversible action and record the request and result.
3. **Inspect protections.** Check token generation/validation, request method, Origin/Referer enforcement, cookie SameSite settings, and whether alternate content types or routes use different middleware.
4. **Model browser delivery.** Determine whether a cross-origin page can actually cause the browser to send the relevant request with the victim's ambient credentials. Do not infer this from a forged Origin header in curl or a proxy.
5. **Test a harmless state change.** If allowed, reproduce using a controlled browser context and a separate test origin. Confirm the request was cross-site and the server accepted the state change.
6. **Check token behavior.** Verify missing, invalid, or mismatched CSRF tokens only on the approved test operation. Avoid repeated attempts that could lock accounts or trigger side effects.
7. **Verify outcome and cleanup.** Confirm the intended test state changed, then restore it if permitted.
8. **Document constraints.** Include cookie settings, browser context, request, expected rejection, observed result, and required victim interaction.

## Verification

A CSRF finding requires a browser-reachable cross-site request that uses the victim's authenticated context and causes a security-relevant state change without the required authorization intent. A missing token alone is not enough if other effective controls block the attack.

## Pitfalls

- Using raw HTTP clients as proof of cross-site browser delivery.
- Ignoring SameSite cookie behavior and browser restrictions.
- Testing high-impact account or financial changes without explicit approval.
- Treating a read-only request as CSRF without a demonstrated state change.
- Failing to account for reauthentication or user interaction requirements.

## Remediation guidance

Use framework CSRF protection, unpredictable per-session/request tokens where appropriate, strict Origin/Referer validation, safe SameSite cookie settings, and non-state-changing GET routes. Treat CORS as a separate control, not a general CSRF defense.

## CyberStrike integration contract

Verify browser automation, scope enforcement, state-change permissions, cleanup handling, and evidence capture before runtime integration. A skill must not run state-changing tests by default.

## Attribution

Adapted from Claude-BugHunter hunt-csrf: https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-csrf/SKILL.md
