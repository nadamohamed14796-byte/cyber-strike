---
name: attack-file-upload
description: "Validate upload authorization, content validation, storage isolation, and unsafe processing using inert test files rather than web shells or active payloads."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - file-upload
  - content-type
  - storage
  - web
  - validation
tech_stack:
  - web
  - api
  - object-storage
  - php
  - dotnet
  - java
cwe_ids:
  - CWE-434
  - CWE-646
chains_with:
  - attack-xss
  - attack-rce
  - attack-idor-automation
  - attack-xxe
prerequisites: []
severity_boost:
  attack-xss: "Active content served from a trusted origin may create XSS only when browser execution and the affected origin are demonstrated."
  attack-rce: "An upload issue becomes RCE only if server-side processing executes controlled content in an explicitly authorized test."
---

# File Upload Security Assessment

## Objective

Determine whether upload workflows enforce authorization, size/type constraints, safe storage, and safe retrieval/processing. Use small inert files owned by the tester; never upload web shells, malware, or destructive parser samples.

## Testing Methodology

### Phase 1: Map upload and retrieval flows

Identify upload endpoints, presigned URLs, multipart forms, import jobs, thumbnail/PDF processors, and download routes. Confirm scope for both the application and backing storage; use a disposable test record.

### Phase 2: Establish a valid baseline

Upload a small benign text file and a valid image permitted by the feature. Record accepted types, size limits, generated key, response metadata, and retrieval behavior. Change one constraint at a time and respect quotas.

### Phase 3: Check validation and authorization

Compare filename extension, declared Content-Type, detected signature, and server-side parser result. Test with harmless mismatches and small inert files. Verify that unauthorized roles cannot upload or overwrite a test-owned object. Avoid executable formats and parser exploit files.

### Phase 4: Inspect storage and serving boundaries

Check whether content is outside executable web roots, served from a distinct origin, forced to attachment when appropriate, and returned with safe content headers. Test direct access only to test-owned objects; do not enumerate keys or open another user's files.

### Phase 5: Review processors and stop conditions

Inspect archive extraction, image conversion, document preview, antivirus, XML processing, and metadata tools in code/config. Do not submit decompression bombs, active SVG/HTML, macro documents, XXE files, or exploit samples to production. Request a sandboxed assessment for parser exploitation.

## What Constitutes a Finding

- **Candidate / lead:** client-side-only type checks, unusual file acceptance, exposed object URLs, or unsafe serving headers.
- **Confirmed finding:** an inert test file demonstrates a security boundary failure such as unauthorized upload/read, overwrite, or active content served in a sensitive origin with approved benign proof.
- **Not a finding:** harmless extension mismatch where content is safely isolated and served; an object URL existing by itself; or a scanner alert without reproduction.

## Evidence Requirements

- Exact request and metadata for a test-owned file, size, declared/detected type, and generated object identifier.
- Account role, timestamp, expected policy, actual result, origin, and response headers.
- Before/after access check using only tester-owned records.
- Sanitized screenshot/response and confirmation that test artifacts were removed.
- No active payloads, secrets, or unrelated users' content.

## Tools

- **Burp Suite:** inspect multipart requests and presigned-upload flows.
- **file/libmagic:** identify benign test-file signatures.
- **Browser DevTools / curl:** record serving headers and rendering behavior.
- **Scoped cloud console/API:** confirm test-object policy without listing unrelated objects.

## Upload Validation and Storage Matrix

| Control | Safe test | Risk signal |
|---|---|---|
| Extension/MIME/signature | Small benign file with declared/detected-type mismatch | Server trusts client header/extension alone |
| Authorization | Upload/retrieve a test-owned file under two controlled roles | Another test role can overwrite/read the fixture without authorization |
| Filename/key | Harmless Unicode and reserved-character names | Path normalization changes an object outside the intended prefix |
| Storage origin | Inspect DNS/origin and response headers for tester's file | Active content shares a privileged app origin or is served inline unsafely |
| Size/processing | Small files around documented limits | Limits are absent or mismatch creates an unexpected state; do not stress-test |
| Archive/document/image processor | Source/config review or benign sample | Unsafe extraction/parser configuration needs lab confirmation |

**Mitigation / regression:** validate type server-side, inspect signatures, rename objects, store outside executable roots, isolate origins, enforce quotas, scan/transform in sandboxed workers, and test authorization on retrieval.

## Verification and False Positives

- Client-supplied MIME type is not the server's verdict; inspect actual detection and serving headers.
- Public object access may be by design for an explicitly public upload feature; verify policy and sensitivity.
- A file returning HTTP 200 does not prove execution or unsafe parsing.
- Storage keys can be hard to guess but unguessability is not a substitute for authorization on private objects.
- Stop if testing would overwrite non-test content, stress a processor, access other tenants, or cross into cloud resources not explicitly in scope.

## References

- [uphiago/recon-skills — hunt-file-upload](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-file-upload)
- [elementalsouls/Claude-BugHunter — hunt-file-upload](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-file-upload)
- [OWASP — File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
