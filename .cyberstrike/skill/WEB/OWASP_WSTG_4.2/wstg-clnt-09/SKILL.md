---
name: wstg-clnt-09
description: "Testing for Clickjacking"
category: client-side
owasp_id: WSTG-CLNT-09
version: "1.1.0"
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

Determine whether a sensitive page can be framed by an untrusted origin and whether user-interface redress could induce a meaningful action. Missing framing headers alone do not prove exploitable clickjacking.

## Preconditions and safety

Use a local proof page and a disposable account. Never send a deceptive page to real users or test real payments, account deletion, MFA changes, or other destructive actions. Confirm browser testing is permitted.

## Procedure

1. Identify the sensitive page and action; document authentication, user role, and expected framing policy.
2. Capture the final response headers after redirects, including CSP `frame-ancestors` and `X-Frame-Options`.
3. Create a local iframe test and observe whether the browser permits framing. Test the actual sensitive route, not just the login or landing page.
4. Repeat only with a controlled authenticated session if permitted. Record whether the page remains interactive and whether any anti-framing control is enforced.
5. If an interaction proof is needed, use a harmless action on a disposable object and restore the state. Do not overlay deceptive controls for real users.
6. Review whether CSRF protection, reauthentication, confirmation steps, or same-site cookie policy changes the attack path. Do not assume these controls always prevent clickjacking.
7. Confirm meaningful impact and capture a minimal browser recording/screenshot plus headers. Redact tokens and personal data.

## Common false positives

- Missing headers on a non-sensitive public page.
- Framing works but the sensitive action is not available or requires reauthentication.
- The browser blocks framing due to CSP or another effective control.
- A header scanner reports absence without browser validation.

## Evidence and output

Return `sensitive_page`, `action`, `csp_frame_ancestors`, `x_frame_options`, `browser_framing_result`, `interaction_proof`, `mitigations`, `impact`, and confidence. Recommend an appropriate CSP `frame-ancestors` policy and consistent framing protection on sensitive routes.
