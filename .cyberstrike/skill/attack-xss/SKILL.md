---
name: attack-xss
description: "Validate reflected, stored, and DOM XSS using controlled canaries and context-aware evidence"
category: "web-application"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [xss, dom, reflected, stored, client-side]
tech_stack: [html, javascript, browser, web]
prerequisites:
  - "Authorized in-scope application and permitted test account"
  - "A harmless unique test marker and evidence redaction"
chains_with: [attack-web-enumeration, attack-triage-validation, attack-evidence-hygiene, attack-report-writing]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-xss/SKILL.md"
---

# Cross-Site Scripting (XSS)

## When to use

Use when untrusted input may reach HTML, an HTML attribute, a JavaScript string, a URL sink, a DOM API, or a stored view. Distinguish executable XSS from plain HTML injection.

## Preconditions and safety

Test only in scope. Prefer a dedicated test account and a harmless unique canary. Do not use payloads that steal cookies, exfiltrate data, change accounts, or execute actions as other users. For stored input, use a disposable record and remove it after testing if permitted.

## Procedure

1. **Identify the source and sink.** Trace the input from URL, form, API, message, or stored field to the rendered page or DOM operation.
2. **Capture a baseline.** Record the normal response and rendering behavior.
3. **Use a unique harmless marker.** Choose a value unlikely to appear elsewhere so the test can be distinguished from example text or an existing payload.
4. **Check output encoding.** Determine whether the marker is HTML-encoded, attribute-encoded, escaped in JavaScript, or inserted into a dangerous context.
5. **Test context-specific behavior safely.** In a controlled test account, use a benign proof-of-execution canary such as a simple local dialog only when program policy permits browser execution. Never chain the test to session theft or account actions.
6. **Check stored behavior.** If the input persists, view it only through the controlled test account and verify whether the canary executes in the intended context.
7. **Check DOM behavior.** Review client-side sources and sinks such as unsafe HTML insertion, URL handling, and message events. Confirm exploitability in a browser rather than relying only on a string match.
8. **Validate boundaries.** Test only the relevant role, page, or origin needed to demonstrate impact. Do not send payloads to real users.
9. **Record evidence.** Capture the input, rendered context, browser result, expected behavior, and redacted request/response.

## Verification

A finding requires proof that attacker-controlled input can execute script in a victim-relevant security context. A reflected string, raw angle brackets, or HTML rendering alone is not sufficient. Record whether the issue is reflected, stored, or DOM-based and which origin/context executes it.

## Pitfalls

- Treating HTML injection as XSS without script execution.
- Confusing an example payload already present in the page with the test canary.
- Ignoring encoding differences between HTML, attributes, JavaScript, and URLs.
- Claiming impact from browser execution without identifying whose browser or origin is affected.
- Using credential theft or data exfiltration to prove a point that a harmless canary already establishes.

## Remediation guidance

Use context-aware output encoding, safe DOM APIs, robust sanitization for allowed rich HTML, and restrictive CSP as defense in depth. Avoid inserting untrusted strings into executable contexts.

## CyberStrike integration contract

Verify the browser automation, request capture, scope gate, and finding schema before runtime wiring. Do not claim XSS from a scanner signature alone.

## Attribution

Adapted from Claude-BugHunter hunt-xss: https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-xss/SKILL.md
