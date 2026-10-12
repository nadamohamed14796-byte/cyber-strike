---
name: wstg-inpv-02
description: "Testing for Stored Cross-Site Scripting (XSS)"
category: input-validation
owasp_id: WSTG-INPV-02
version: "1.2.0"
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

Determine whether an application persists attacker-controlled content and later renders it in an executable browser context. Assess the storage path, all rendering locations, affected viewer roles, persistence, and cleanup without exposing real users.

## Preconditions and safety

Use a disposable record and dedicated test account. Confirm storage and cleanup are permitted. Do not submit test content to public profiles, shared feeds, customer-visible messages, or records viewed by real users. Never use payloads that steal session data or transmit information externally.

## Procedure

### 1. Identify persistence and viewers

1. Inventory persistent inputs such as profile fields, comments, descriptions, support tickets, project names, uploaded metadata, markdown/rich-text fields, and API-managed records.
2. Record create, update, list, detail, search, preview, export, notification, and administrative rendering paths that are in scope.
3. Establish the expected storage format and identify which roles can view the record.
4. Use a dedicated test tenant or account; never rely on an unsuspecting real user or administrator to view the test.

### 2. Trace the value through storage

1. Capture the normal create/update request and its response.
2. Insert a unique inert marker and verify where it is stored and where it reappears.
3. Reload the record through a clean session and inspect both the raw response and rendered DOM.
4. Check whether the value is transformed at input time, storage time, API serialization, or each output sink.
5. Repeat the context review for every distinct rendering location; one field may be safe in a detail page but unsafe in a preview, notification, or export.

### 3. Determine rendering context

- Distinguish plain text from rich HTML and confirm whether that behavior is intentional.
- Inspect HTML text, attribute, JavaScript, URL, and client-side DOM contexts separately.
- Review markdown converters, syntax highlighters, preview panes, and third-party rendering components when present.
- Check whether output encoding occurs at the final sink rather than relying only on input filtering.
- Treat a stored tag or HTML snippet as non-executable unless browser behavior proves otherwise.

### 4. Validate safely

1. Use harmless context-specific probes on the disposable record and change one variable at a time.
2. If authorized, confirm execution in a controlled browser with a benign local canary that only changes a visible marker.
3. Do not use external callbacks, credential access, data exfiltration, destructive actions, or cross-user delivery.
4. Verify whether a separate test-owned role sees the same record only when the program explicitly permits multi-role testing.
5. Stop immediately if the content becomes visible to real users or a privileged user outside the test setup.

### 5. Assess scope and impact

Document the origin, storage duration, viewer roles, navigation required, and whether the issue executes on each view or only one path. Explain reachable impact realistically; do not infer session theft or administrator compromise from execution alone.

### 6. Cleanup and retest

Delete the test record or restore its original content. Clear previews or caches where supported. After remediation, verify that stored content is safely encoded in every rendering path, including older records and cached views.

## Common false positives

- The value is stored but always rendered as text.
- Execution occurs only in a local developer console.
- A preview differs from the actual user-facing page.
- The claimed victim role cannot access the record.
- A finding depends on real users viewing attacker-controlled content.
- The sanitizer changes the value but the final sink remains non-executable.

## Evidence contract

Include create/update request, redacted stored value, exact rendering URL and role, output context, controlled browser result, persistence behavior, cleanup status, impact, and confidence. Use synthetic data only.

## Remediation guidance

Use context-aware output encoding, safe templating and DOM APIs, a well-maintained sanitizer when rich HTML is required, and consistent sanitization/encoding across detail pages, previews, notifications, exports, and APIs. Add regression tests for every affected sink.
