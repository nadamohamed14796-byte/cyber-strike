---
name: wstg-inpv-02
description: "Testing for Stored Cross-Site Scripting (XSS)"
category: input-validation
owasp_id: WSTG-INPV-02
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [injection, input-validation, xss, stored, wstg, inpv]
tech_stack: [html, javascript, http, browser, api]
cwe_ids: [CWE-79]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-xss/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-xss/SKILL.md"
  - "https://owasp.org/www-project-web-security-testing-guide/"
---

# WSTG-INPV-02: Stored XSS

## Objective

Determine whether an application stores attacker-controlled content and later renders it in an executable browser context for a user who views the affected record.

## Preconditions and safety

Use a disposable record and dedicated test account. Confirm storage and cleanup are allowed. Do not submit content to public profiles, shared feeds, customer-visible messages, or records viewed by real users. Never use payloads that steal session data or transmit information externally.

## Procedure

1. Identify persistent input surfaces such as profile fields, comments, descriptions, support tickets, uploaded metadata, or API-managed records.
2. Capture the normal create/update request and the page that renders the value.
3. Insert a unique inert marker and verify where it is stored and where it reappears.
4. Determine the output context for every rendering location; the same field may appear in several views with different encoding.
5. Check HTML, attribute, JavaScript, URL, and DOM contexts using harmless controlled probes. Do not confuse stored HTML with executable script.
6. If permitted, confirm execution in a controlled browser using a benign local canary. Test only with your own account and record.
7. Check whether the content is rendered to another role only through a test tenant/account that you control. Do not cause real users or administrators to view the test.
8. Verify persistence by reloading through a clean session, then remove the test record or restore its original content.
9. Assess scope and impact based on the actual viewers, privileges, and data/actions reachable from the affected origin.

## Common false positives

- The value is stored but always rendered as text.
- Execution occurs only in a local developer console.
- A browser preview differs from the actual user-facing page.
- A test record is not visible to the claimed victim role.
- The finding relies on real users viewing attacker-controlled content.

## Evidence and output

Include the create/update request, redacted stored value, exact rendering URL, output context, controlled browser result, test-account role, cleanup status, impact, and confidence. Recommend context-aware encoding, safe templating, sanitization appropriate to the intended content, and safe DOM APIs.
