---
name: attack-lfi
description: "Assess suspected local file inclusion with bounded, non-sensitive validation"
category: "web-application"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [lfi, path-traversal, file-access, web]
tech_stack: [http, web, php, java, nodejs]
prerequisites:
  - "Authorized endpoint and permission for file-path validation"
  - "A harmless known test file or isolated staging environment"
chains_with: [attack-web-enumeration, attack-api-misconfig, attack-triage-validation, attack-evidence-hygiene]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-lfi/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
---

# Local File Inclusion Assessment

## When to use

Use when user-controlled paths, template names, include parameters, archive paths, or file identifiers may influence server-side file resolution.

## Safety gate

Do not read credential files, private keys, environment files, or real user data on production. Use a harmless application-owned file or a test environment. Avoid writing files, log poisoning, and command execution unless explicitly authorized.

## Procedure

1. Identify the path-bearing parameter and capture a normal successful request.
2. Determine expected path semantics and whether the server resolves identifiers, filenames, or filesystem paths.
3. Use a harmless marker or known non-sensitive file within the application's permitted test fixture. Try only a small number of normalized/encoded variants.
4. Compare response content and error behavior to baseline; confirm that returned bytes are from the intended file rather than a generic error or cache.
5. Check path normalization, extension enforcement, allowlists, and whether the resolved path can escape the intended directory.
6. If production proof risks sensitive access, stop at a non-sensitive marker and report the suspected boundary.
7. Do not chain into log poisoning, secret reads, or code execution unless the scope explicitly permits that escalation.

## Pitfalls

- A path string reflected in an error does not prove file inclusion.
- A 200 response may be a generic page.
- File download functionality may be intentional and separately access-controlled.
- Do not infer RCE from LFI without a demonstrated execution path.

## Verification

Provide the baseline and test request, minimal non-sensitive file content, path boundary, authentication context, and impact. Redact all private content.
