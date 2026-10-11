---
name: attack-file-upload
description: "Assess upload and import workflows for unsafe file handling using harmless controlled fixtures"
category: "web-application"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [file-upload, import, storage, validation, traversal]
tech_stack: [http, web, file-formats]
prerequisites:
  - "Authorized upload/import endpoint and a controlled test account"
  - "A harmless test file and cleanup permission"
chains_with: [attack-web-enumeration, attack-triage-validation, attack-evidence-hygiene, attack-report-writing]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-file-upload/SKILL.md"
---

# File Upload and Import Security

## When to use

Use when an application accepts avatars, attachments, documents, archives, imports, media, or other user-supplied files. Include downstream preview, conversion, extraction, and download behavior.

## Preconditions and safety

Confirm upload testing is in scope and use a disposable account and harmless marker file. Do not upload web shells, malware, active scripts, destructive archives, or files designed to execute commands on production. Use a lab or staging system for exploit-specific validation.

## Procedure

1. **Map the workflow.** Record endpoint, accepted formats, filename rules, size limits, storage location if known, access controls, and post-upload processing.
2. **Establish a safe baseline.** Upload a small benign file of an allowed type and verify expected storage and retrieval behavior.
3. **Check validation consistency.** Compare extension, declared content type, and actual file signature using harmless fixtures. Confirm whether server-side validation is authoritative.
4. **Check authorization.** Use two controlled accounts and a disposable upload to test whether only the owner or intended audience can retrieve it. Avoid touching another user's real files.
5. **Check filename and path handling.** Use benign unusual filenames within program policy to determine whether names are normalized, displayed safely, and kept within the intended storage location. Do not attempt writes to system paths.
6. **Review preview and conversion.** Determine whether uploaded SVG/HTML, office documents, images, or archives are rendered or processed by separate services. Use inert test content; do not embed active payloads in production.
7. **Review archive extraction in a lab.** If archive traversal or parser exploitation is suspected, reproduce with a disposable local fixture or staging environment. Do not upload an archive that attempts to overwrite production files.
8. **Check limits and cleanup.** Confirm size/type limits and delete test artifacts if permitted.
9. **Record minimum evidence.** Preserve the harmless file, sanitized request, returned object identifier, access result, and expected versus actual behavior.

## Verification

A finding needs a demonstrated security failure, such as unauthorized retrieval of a controlled file, storage outside the intended boundary, unsafe active rendering, or a validation bypass with meaningful impact. Accepting an unexpected extension alone is not proof of code execution.

## Pitfalls

- Uploading executable payloads to production just to test a hypothesis.
- Treating MIME mismatch as exploitable without observing a security consequence.
- Assuming a public URL is unauthorized if public sharing is intended.
- Testing traversal by overwriting real files.
- Leaving test uploads or personal data behind.
- Reporting an extension-policy inconsistency without impact.

## Remediation guidance

Use server-side allowlists, file signature inspection, generated storage names, storage outside executable web roots, least-privilege permissions, safe archive extraction, malware scanning where appropriate, and authorization checks on every download/preview path.

## CyberStrike integration contract

Verify upload tooling, allowed test file fixtures, scope/state-change guards, cleanup behavior, and evidence redaction before automation. Do not enable exploit payloads or destructive tests by default.

## Attribution

Adapted from Claude-BugHunter hunt-file-upload: https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-file-upload/SKILL.md
