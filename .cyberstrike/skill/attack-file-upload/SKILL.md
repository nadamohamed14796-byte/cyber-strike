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


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue with materially different, authorized tests while the result can change the conclusion; deduplicate equivalent encodings/retries and stop when direct evidence resolves the hypothesis, relevant branches are exhausted, a prerequisite is unavailable, or scope/safety requires stopping. This does not override program rate limits or safe-production constraints.

Maintain an attempt ledger: hypothesis, single changed variable, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer controlled identities, synthetic resources and paired requests. Preserve sanitized evidence and minimize data collected.

### Skill-specific hypothesis order

1. Baseline upload behavior with an inert text or image canary: allowed extension, rejected extension, size boundary, and the server's final storage/retrieval path.
2. Change one file property at a time—extension, content type, signature, filename, path/name normalization, or archive structure—and observe whether validation is server-side and consistent.
3. Verify storage isolation and execution behavior with a harmless canary in a test-owned folder. Do not upload malware, web shells, oversized archives, or polyglot files to production.
4. Check authorization independently for upload, view, download, replace, and delete operations using two controlled identities; opaque filenames do not substitute for access checks.
5. Record the exact validation gap, final serving headers/origin, and a control rejected by the server; remediation should combine allowlisted types, content inspection, safe storage, randomized names, and authorization tests.


### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture and a relevant control.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause remains uncertain.
- **Unconfirmed:** response is ambiguous, cached, generic, or not linked to a security boundary.
- **Refuted / false positive:** an applicable negative control or valid policy explanation accounts for the signal. Record the attempt ledger rather than claiming every theoretical variant was exhausted.
- A 2xx status, error difference, header, schema/documentation exposure, scanner alert, or UI-only state is not proof by itself.

### Stop, cleanup, and handoff

Stop on scope ambiguity, unexpected real-user data, unexpected production state changes, service degradation, credential exposure, or a prohibited action. Restore disposable state and revoke temporary tokens/sessions where possible. Handoff target and scope proof, baseline, hypothesis, attempts used, impact, negative controls, verdict/confidence, sanitized evidence pointers, linked-skill signal, and cleanup status. Invoke a related skill only when its triggering signal is observed.

## References

- [uphiago/recon-skills — hunt-file-upload](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-file-upload)
- [elementalsouls/Claude-BugHunter — hunt-file-upload](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-file-upload)
- [OWASP — File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)


## Targeted quality-loop enrichment (2026-10-19)

### Upload lifecycle and retrieval proof
Trace the complete lifecycle: authorization to upload, content validation, filename normalization, storage key, processing/transformation, retrieval authorization, content type, and browser origin. Use a benign file with a unique marker and harmless declared/actual-type mismatch; do not upload executable malware, web shells, oversized files, or active content to production. Verify the stored object is isolated and cannot alter another user's content, then inspect whether retrieval runs through a safe download origin with expected Content-Disposition and X-Content-Type-Options. A filename/path anomaly is not code execution unless a distinct execution path is proven. Chain to SSRF only for a confirmed server-side URL fetch and to XSS only if retrieved content executes in a relevant browser origin.


## Practical inert-file verification and chain matrix

### Create and inspect a harmless fixture locally

```bash
umask 077
printf 'cyberstrike-upload-canary-%s\n' "$(date +%s)" > upload-canary.txt
file --mime-type upload-canary.txt
sha256sum upload-canary.txt
```

Upload only to an explicitly authorized feature. Record the local hash, reported server-side type (if available), object ID, and retrieval headers. Never use a real user's file as the test fixture.

### Lifecycle matrix

| Stage | Safe observation | Next branch only if this signal exists |
|---|---|---|
| Upload authorization | A controlled lower-privilege identity can upload a test-owned fixture contrary to policy | BFLA or object authorization, depending on the failed boundary |
| Type validation | Server accepts a benign mismatch but later interprets it unsafely | Content-type/browser behavior; not RCE without a proven execution path |
| Storage key/path | Normalization points outside the intended test-object prefix | Path traversal review only within the approved fixture/sandbox |
| Retrieval authorization | A second controlled identity can retrieve the private fixture | IDOR/BOLA with object-owner and access-policy evidence |
| Browser serving | The inert fixture is served inline from a privileged application origin with a risky type | XSS review only if browser interpretation/execution is demonstrated safely |
| Server-side processing | Source/config indicates a URL fetch, archive extraction, or parser invocation | SSRF/archive/parser skill only after that processor and input flow are established |
| Shared caching | Private fixture response is stored/replayed across contexts | Cache deception/poisoning review with cache-layer evidence |

### Evidence additions

Store upload_request_ref, fixture_hash, detected_type, generated_key, processing_path, retrieval_auth_context, response_content_type, content_disposition, nosniff_behavior, origin, before_after_access, cleanup_verified, and chain_basis. Keep the fixture and notes free of credentials. If the storage provider or processing stage is not observable, state that uncertainty instead of inferring it.
