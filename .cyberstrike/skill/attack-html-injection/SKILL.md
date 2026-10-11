---
name: attack-html-injection
description: "Assess HTML injection separately from script execution and context-aware XSS"
category: "web-application"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [html-injection, output-encoding, xss, web]
tech_stack: [html, javascript, http, browser]
prerequisites:
  - "Authorized endpoint and a harmless unique test marker"
  - "Controlled test account for stored content where applicable"
chains_with: [attack-xss, attack-csrf, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-html-injection/SKILL.md"
---

# HTML Injection Assessment

## When to use

Use when untrusted input appears in rendered HTML and may alter page structure, links, text, or form presentation without necessarily executing JavaScript.

## Safety gate

Use a harmless marker in a controlled account. Do not create deceptive content for real users, insert active scripts, or use the issue to trigger external navigation or state-changing actions.

## Procedure

1. Trace the input source and rendered output context.
2. Capture a baseline and submit a unique inert marker.
3. Determine whether output is text-escaped, attribute-escaped, or inserted as raw markup.
4. If permitted, use a benign non-script HTML element in a test-only view to confirm markup interpretation.
5. For stored fields, view only through the controlled test account and clean up the test record.
6. Assess impact separately: content spoofing, phishing-enabling UI changes, link injection, or script execution.
7. If script execution is suspected, hand off to `attack-xss` and follow its safety gate.
8. Record the exact sink and minimal rendered evidence.

## Pitfalls

- Markup reflection may be escaped or displayed as text.
- HTML injection is not automatically XSS.
- A visual change may have no security impact without a credible user or trust-boundary effect.

## Verification

Confirm raw markup interpretation and describe the demonstrated consequence. Do not report XSS unless script execution is independently validated.
