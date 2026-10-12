---
name: wstg-inpv-01
description: "Testing for Reflected Cross-Site Scripting (XSS)"
category: input-validation
owasp_id: WSTG-INPV-01
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [injection, input-validation, xss, reflected, wstg, inpv]
tech_stack: [html, javascript, http, browser]
cwe_ids: [CWE-79]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-xss/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-xss/SKILL.md"
  - "https://owasp.org/www-project-web-security-testing-guide/"
---

# WSTG-INPV-01: Reflected XSS

## Objective

Determine whether untrusted input is reflected into an executable browser context without the required context-aware encoding. A reflected string or HTML snippet is not automatically XSS; prove browser interpretation safely.

## Preconditions and safety

- Confirm the endpoint and test parameter are in scope.
- Use a unique harmless marker and a controlled browser/test account.
- Never use payloads that steal cookies, tokens, or page data, or send data to an external collector.
- Use a benign proof of execution only when permitted; do not target other users.

## Procedure

1. **Map source and sink.** Identify query, path, form, header, or API input and where it appears in the response or DOM.
2. **Capture baseline.** Save the original request and response with secrets redacted. Note content type, encoding, and reflection location.
3. **Place a unique marker.** Use a random inert string to locate the exact reflection point and rule out unrelated page content.
4. **Identify output context.** Determine whether the value is in HTML text, an attribute, a JavaScript string, CSS, or a URL. Check whether encoding matches that context.
5. **Check parser boundaries safely.** Use harmless context-specific probes in a controlled test account. Do not assume HTML injection is executable JavaScript.
6. **Confirm browser execution.** If policy permits, use a benign local canary that proves execution without accessing or transmitting sensitive data. Verify in the browser, not only with curl.
7. **Test encoding and sanitization.** Compare special-character handling and confirm whether the output is encoded at the final sink. Avoid broad payload lists unless specifically authorized.
8. **Assess impact.** Explain the affected origin, victim interaction required, authentication context, and reachable data/action. Do not claim session theft without proof.
9. **Clean up.** Remove test input from the disposable record where possible.

## Common false positives

- Input is reflected but HTML-encoded.
- HTML injection is mistaken for script execution.
- A scanner string appears in source code or an unrelated response.
- A browser extension or local tool causes the observed execution.
- A CSP warning is reported as XSS without a vulnerable sink.

## Evidence and output

Record endpoint, parameter, context, redacted request/response, encoding behavior, controlled browser result, prerequisites, impact, cleanup, and confidence. Return a minimal reproducible proof and remediation guidance such as context-aware output encoding and safe DOM APIs.
