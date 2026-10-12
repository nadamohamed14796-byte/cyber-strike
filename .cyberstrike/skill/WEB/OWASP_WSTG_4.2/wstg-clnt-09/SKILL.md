---
name: wstg-clnt-09
description: "Testing for Clickjacking"
category: client-side
owasp_id: WSTG-CLNT-09
version: "1.2.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [client-side, clickjacking, framing, csp, wstg]
tech_stack: [http, browser, html, csp]
cwe_ids: [CWE-1021]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-clickjacking/SKILL.md"
  - "https://owasp.org/www-project-web-security-testing-guide/"
---

# WSTG-CLNT-09: Clickjacking

## Objective

Determine whether a sensitive page can be framed by an untrusted origin and whether UI redress could induce a meaningful action. Missing framing headers alone do not prove exploitable clickjacking; browser behavior, authenticated state, available actions, and compensating controls matter.

## Preconditions and safety

Use a local proof page and a disposable account. Never send a deceptive page to real users or test real payments, account deletion, MFA changes, or other destructive actions. Confirm browser testing is permitted. Redact cookies, tokens, and personal data from evidence.

## Procedure

### 1. Identify the sensitive surface

1. Select a specific in-scope page that exposes a meaningful state-changing action.
2. Record required authentication, expected role, whether the action needs a CSRF token, and the impact if a user activates it unintentionally.
3. Confirm the page is reachable directly and determine whether it redirects to a different origin.
4. Do not treat a public landing page or a page with no meaningful action as a finding solely because it can be framed.

### 2. Inspect effective anti-framing controls

- Capture the final response headers after redirects, including Content-Security-Policy and its frame-ancestors directive, plus X-Frame-Options.
- Check the actual route and relevant response variants, not only the login or home page.
- Determine whether the policy is applied consistently to sensitive pages and error/alternate responses.
- Note that frame-ancestors is enforced by browsers and is not equivalent to default-src. A CSP report-only policy does not block framing.
- Do not conclude protection is absent based only on one scanner's header check.

### 3. Verify browser framing behavior

1. Create a local HTML proof page that embeds only the authorized test route in an iframe.
2. Test without an authenticated session, then with a controlled authenticated session only if permitted.
3. Record whether the browser loads the frame, emits a CSP/X-Frame-Options console error, or blocks navigation.
4. Confirm the route is genuinely interactive in the framed context; a blank frame or browser error is not a bypass.
5. If the application has multiple origins or subdomains, test only those relevant to the policy and within scope.

### 4. Assess interaction and compensating controls

- Use a harmless action on a disposable object to determine whether the framed page can perform a state change.
- Do not create deceptive overlays for real users or trigger a destructive workflow.
- Review whether CSRF tokens, SameSite cookie behavior, origin checks, reauthentication, confirmation dialogs, or step-up authentication alter the attack path.
- Treat each mitigation independently; CSRF protection and clickjacking protection address different threat models.
- Record whether user interaction is required and whether the action can be reversed.

### 5. Determine practical impact

Describe the affected route, authenticated role, user gesture required, expected versus actual state change, and realistic attacker preconditions. Do not claim account takeover or sensitive action execution unless the controlled proof demonstrates it.

### 6. Cleanup and retest

Close the proof page, remove test records, and restore the disposable account. After remediation, repeat the same browser test and confirm the sensitive route is no longer frameable by an untrusted origin.

## Common false positives

- Missing headers on a non-sensitive public page.
- Framing works but the sensitive action is unavailable or requires reauthentication.
- The browser blocks framing due to an effective CSP or X-Frame-Options policy.
- A header scanner reports absence without browser validation.
- A click is blocked by an independent server-side authorization or CSRF check.

## Evidence contract

Return sensitive_page, action, required_role, final_response_headers, CSP frame-ancestors, X-Frame-Options, browser_framing_result, interaction_proof, compensating_controls, impact, cleanup_status, and confidence. Include a minimal screenshot or recording with secrets redacted.

## Remediation guidance

Set an explicit CSP frame-ancestors policy appropriate to the product, use X-Frame-Options for legacy browser compatibility where relevant, apply protection consistently to sensitive routes, and retain server-side authorization and CSRF controls as separate defenses.
