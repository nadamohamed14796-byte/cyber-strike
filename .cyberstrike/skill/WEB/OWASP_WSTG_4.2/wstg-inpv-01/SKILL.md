---
name: wstg-inpv-01
description: "Testing for Reflected Cross-Site Scripting (XSS)"
category: input-validation
owasp_id: WSTG-INPV-01
version: "1.2.0"
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

Determine whether untrusted input is reflected into an executable browser context without context-aware encoding or safe handling. Reflection or HTML injection alone is not proof of XSS; validate browser interpretation and practical impact safely.

## Preconditions and safety

- Confirm endpoint, parameter, account, and browser are in scope.
- Use a unique inert marker first and a controlled browser/test account.
- Never use payloads that steal cookies, tokens, DOM contents, or page data, or transmit information to an external collector.
- Use a benign proof of execution only if program rules permit it; do not target other users or shared/public content.
- Redact cookies, authorization headers, personal data, and any secrets from saved traffic.

## Procedure

### 1. Map sources, transformations, and sinks

1. Identify inputs from query/path parameters, form fields, headers, JSON bodies, fragments, and client-side route state.
2. Capture a baseline request and response, including content type, status, relevant security headers, and the exact rendering route.
3. Insert a unique inert marker and search the raw response and rendered DOM to establish whether the value is reflected.
4. Record any transformations: HTML encoding, URL decoding, JSON serialization, template rendering, sanitization, or client-side concatenation.
5. Determine whether the same value reaches multiple sinks, such as an HTML text node, attribute, inline script, URL, CSS value, or DOM API.

### 2. Identify the output context

- HTML text: verify special characters are encoded as text rather than parsed as markup.
- HTML attribute: check quoting and context-aware encoding; note whether event-handler or URL attributes are involved.
- JavaScript/JSON: determine whether the value is serialized as data or concatenated into executable source.
- URL: check scheme allowlisting and whether the value can alter navigation or a resource destination.
- DOM-based rendering: trace the source to the sink and check whether safe text APIs or unsafe HTML parsing are used.
- CSS: verify values cannot escape the intended property or introduce an active URL/context.
- Do not treat a string appearing in page source as proof that the browser executes it.

### 3. Validate a suspected context break

1. Change one input at a time and keep a known-good baseline.
2. Use harmless context-specific probes that demonstrate parsing boundaries without accessing sensitive data or making network callbacks.
3. Compare raw response bytes with the final DOM; client-side frameworks may transform the value after initial load.
4. Check whether a sanitizer is appropriate for the intended content and whether encoding happens at the final output sink.
5. If execution proof is authorized, use a benign local canary that only changes a visible test-page marker. Verify it in a controlled browser and capture the result.
6. Stop once the minimum proof is established; do not chain the issue into account actions or data access.

### 4. Evaluate exploitability and impact

Record whether an attacker must persuade a victim to open a crafted link, whether authentication is required, which origin executes the content, and what browser security controls apply. Describe realistic reachable actions without claiming cookie theft or account takeover unless that impact is separately and safely demonstrated.

### 5. Verify remediation and clean up

Remove test input where possible. Re-test the same route after a fix and confirm that encoding or safe DOM handling remains effective in each rendering context.

## Common false positives

- Input is reflected but encoded for the correct context.
- HTML injection is mistaken for executable script.
- A marker appears in source code or unrelated page content.
- Browser extensions or local developer tools caused the observed behavior.
- A CSP warning is reported as XSS without a vulnerable sink.
- A scanner finding cannot be reproduced in the browser.

## Evidence contract

Record endpoint, parameter, role, raw response reflection, exact output context, transformations, redacted request/response, controlled browser result, victim interaction required, impact, cleanup, and confidence. Preserve a minimal reproducible proof without secrets or external callbacks.

## Remediation guidance

Prefer context-aware output encoding, safe template defaults, safe DOM APIs such as text insertion, strict allowlists for URL schemes, and narrowly configured sanitization when rich HTML is a product requirement. Avoid concatenating untrusted values into executable source.
