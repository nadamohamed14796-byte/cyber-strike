---
name: attack-clickjacking
description: "Validate framing protections and user-interface redress risk with a controlled test page"
category: "web-application"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [clickjacking, framing, csp, x-frame-options, ui-redress]
tech_stack: [http, browser, html, csp]
prerequisites:
  - "Authorized in-scope page and permission to run browser-based validation"
  - "A local controlled test page and test account if authentication is required"
chains_with: [attack-csrf, attack-auth-bypass, attack-triage-validation, attack-report-writing]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-clickjacking/SKILL.md"
---

# Clickjacking and UI Redress

## When to use

Use when a sensitive page may be framed by another origin and user interaction could be tricked into performing a meaningful action.

## Safety and prerequisites

Test only an authorized page. Use a local proof page and a disposable account. Do not induce real users to click a deceptive page, perform payments, change security settings, or trigger destructive actions.

## Procedure

1. **Identify the sensitive page.** Record whether it is authenticated, what action it exposes, and whether that action has meaningful impact.
2. **Inspect framing headers.** Capture `Content-Security-Policy` and its `frame-ancestors` directive, plus `X-Frame-Options`. Check the final response after redirects and on the actual sensitive route.
3. **Create a local framing test.** In a local HTML file, attempt to load the page in an iframe. Do not host a deceptive page publicly or send it to other people.
4. **Test while authenticated only with a controlled account.** Observe whether the browser blocks framing and whether the page is usable when framed. A login page may behave differently from the authenticated action page.
5. **Assess exploitability context.** Determine whether a meaningful action is exposed, whether user interaction is required, and whether reauthentication, CSRF tokens, or confirmation screens mitigate the scenario.
6. **Use a harmless action.** If a proof of interaction is needed, use a non-destructive toggle or disposable object and restore it afterward.
7. **Capture evidence.** Save the relevant headers, browser result, URL, and action context. Redact cookies and personal data.

## Pitfalls

- Missing headers on a public, non-sensitive page may have no meaningful impact.
- `X-Frame-Options` alone may not fully describe modern browser behavior; evaluate CSP and actual browser enforcement.
- Framing permission is not automatically exploitable clickjacking.
- Do not test deceptive overlays against real users.

## Verification

Confirm both the framing behavior and a credible security-relevant action path. If no sensitive action or meaningful user impact is demonstrated, report the header observation separately rather than claiming confirmed clickjacking.
