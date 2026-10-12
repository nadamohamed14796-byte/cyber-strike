---
name: wstg-inpv-11.1
description: "Testing for File Inclusion (LFI/RFI)"
category: input-validation
owasp_id: WSTG-INPV-11.1
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [injection, input-validation, lfi, rfi, file-inclusion, wstg]
tech_stack: [http, web, php]
cwe_ids: [CWE-98, CWE-22]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-lfi/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
  - "https://owasp.org/www-project-web-security-testing-guide/"
---

# WSTG-INPV-11.1: File Inclusion (LFI/RFI)

## Objective

Determine whether a user-controlled path or resource identifier causes the application to include or read a file outside the intended boundary, or fetch a remote resource in a server-side include context.

## Preconditions and safety

Use a test environment or a harmless, application-owned marker file. Do not read system files, credentials, environment variables, source secrets, or other users' files on production. Do not use remote payloads that execute code or create callbacks unless explicitly approved.

## Procedure

1. Identify path-like inputs such as template, language, page, download, include, export, or document parameters. Record normal accepted values and the expected directory/resource boundary.
2. Capture a baseline request and response using a legitimate in-scope file or template.
3. Test normalization and allowlist behavior with harmless invalid paths. Change one variable at a time and observe whether the server canonicalizes, rejects, or resolves the input.
4. In a controlled environment, use an application-owned marker file outside the intended directory to verify whether path traversal or inclusion crosses the boundary. Avoid sensitive system paths.
5. Distinguish file download from server-side inclusion: determine whether the content is merely returned as a file, parsed as a template, or executed by a runtime.
6. Assess remote inclusion only if the application demonstrably supports fetching remote resources and the rules explicitly allow it. Use a controlled test host; do not target internal services.
7. Verify authorization and canonical path checks, symlink handling, extension restrictions, and whether alternate encodings bypass the same validation layer.
8. Confirm impact with the smallest non-sensitive marker and stop once the boundary violation is proven.
9. Clean up test files and restore disposable state.

## Common false positives

- A 200 response is a generic error page or application fallback.
- The application returns a file identifier but never reads a filesystem path.
- Encoded traversal is normalized or rejected before file access.
- A file is publicly downloadable by design.
- The result is SSRF rather than file inclusion.

## Evidence and output

Record input parameter, expected path boundary, baseline/test request pair, marker location, canonicalization behavior, read/include semantics, authorization context, cleanup, impact, and confidence. Recommend server-side identifier-to-file mapping, canonical path validation, safe storage boundaries, and disabling remote inclusion where unnecessary.
