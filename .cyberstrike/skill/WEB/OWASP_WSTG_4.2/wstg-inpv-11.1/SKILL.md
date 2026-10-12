---
name: wstg-inpv-11.1
description: "Testing for File Inclusion (LFI/RFI)"
category: input-validation
owasp_id: WSTG-INPV-11.1
version: "1.2.0"
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

Determine whether a user-controlled path or resource identifier causes the application to read or include a resource outside its intended boundary, or fetch a remote resource in a server-side include context. Distinguish file download, path traversal, template inclusion, and SSRF.

## Preconditions and safety

Use a test environment or a harmless application-owned marker file. Do not read system files, credentials, environment variables, source secrets, or other users' files on production. Do not use remote payloads that execute code or create callbacks unless explicitly approved. Confirm cleanup permissions before creating test files.

## Procedure

### 1. Map path-like inputs

1. Identify template, language, page, download, include, export, document, archive, and resource identifier parameters.
2. Record accepted values, expected directory/resource boundary, file extension rules, and the normal response.
3. Determine whether the application accepts a logical identifier that maps to a server-side file or a raw path from the client.
4. Capture a baseline request/response and redact any private content.

### 2. Check normalization and allowlists

- Use harmless invalid values to determine whether input is rejected, normalized, or mapped to a known resource.
- Change one variable at a time and compare behavior across URL decoding, path separator handling, and canonicalization.
- Review whether validation occurs before or after decoding and whether every downstream component uses the same canonical path.
- Check allowlist behavior for known template names and whether unexpected extensions are rejected.
- Do not use sensitive operating-system paths as test markers.

### 3. Verify a boundary violation safely

- In a controlled environment, create a non-sensitive marker file in a permitted test directory outside the intended include directory.
- Use the smallest test input needed to determine whether the application resolves the marker outside its intended boundary.
- Confirm the response actually contains the marker or that a controlled template is processed; a 200 response alone is not proof.
- Stop once the boundary violation is demonstrated. Do not read configuration files, credentials, source secrets, or unrelated files.
- If filesystem setup is not permitted, report the hypothesis as unconfirmed rather than probing sensitive paths.

### 4. Distinguish read, download, include, and execution

- File download: the application returns bytes as an attachment or resource.
- File read: content is returned in a response or rendered view.
- Server-side include: the application parses a template or processes content within a server context.
- Remote resource fetch: the application retrieves a URL; this may be SSRF rather than file inclusion.
- Code execution must not be inferred from file inclusion alone and should not be attempted on production without explicit authorization and a dedicated safe environment.

### 5. Review alternate paths and authorization

- Check equivalent routes such as preview, export, localization, attachment, archive extraction, and image/document conversion when in scope.
- Verify that authorization is checked before resolving the resource and that tenant-specific files cannot cross boundaries.
- In a controlled environment, consider symlink and canonical-path behavior using harmless test directories.
- Avoid path fuzzing at high volume and stop if unexpected sensitive content is returned.

### 6. Assess remote inclusion only when relevant

- First confirm the application actually supports remote resource retrieval.
- Use only a controlled test host and explicitly approved callback mechanism; never target internal services or cloud metadata endpoints as part of this skill.
- Route generic URL-fetch behavior to the SSRF skill when the issue is server-side network access rather than include semantics.
- Do not use remote code execution payloads.

### 7. Cleanup and retest

Remove marker files and restore disposable state. After remediation, repeat the same minimal test and confirm the server resolves only approved resources.

## Common false positives

- A 200 response is a generic error page or application fallback.
- The application returns a logical file identifier but never reads a filesystem path.
- Encoded traversal is normalized or rejected before file access.
- A file is publicly downloadable by design.
- The result is SSRF rather than file inclusion.
- The application reads a permitted marker but not outside the intended boundary.

## Evidence contract

Record input parameter, expected path boundary, baseline/test request pair, marker location, canonicalization behavior, read/include semantics, authorization context, cleanup, impact, and confidence. Do not retain sensitive file contents.

## Remediation guidance

Prefer server-side identifier-to-file mapping, canonical path validation, strict storage boundaries, allowlisted templates, careful symlink handling, least-privilege filesystem permissions, and disabling remote inclusion where unnecessary.
