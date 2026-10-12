---
name: attack-minio-s3
description: "Assess S3-compatible object storage response-header overrides, object permissions, and origin isolation with inert synthetic files and signed test requests."
category: "cloud"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - s3
  - minio
  - object-storage
  - content-type
  - xss
  - cloud
tech_stack:
  - aws-s3
  - minio
  - s3-compatible
  - cloudfront
  - cdn
  - web
cwe_ids:
  - CWE-434
  - CWE-942
  - CWE-200
chains_with:
  - attack-file-upload
  - attack-xss
  - attack-cloud-misconfig
prerequisites: []
severity_boost:
  attack-xss: "An object-header override can become XSS only if a safe test object is interpreted as active content in a security-relevant origin; never submit an active payload to production."
---

# S3 and MinIO Object Response Policy Assessment

## Objective

Check whether public or signed object-storage responses allow unexpected Content-Type/Content-Disposition/cache header overrides, and whether storage is isolated from the application's trusted origin. Use an inert test-owned object or lab bucket; do not upload script, HTML, SVG, polyglot, or executable content to a production bucket.

## Testing Methodology

### Phase 1: Confirm storage ownership and data boundary

Verify the bucket/MinIO endpoint and the application's storage domain are explicitly in scope. Identify whether the object is public, signed, CDN-served, or served through the application. A public URL may be intentional for a public asset.

### Phase 2: Choose an inert test object

Use a small text marker or benign image created by the tester in a disposable bucket/object prefix. Record the original URL, ownership, content type, cache policy, and expected public/private access.

### Phase 3: Compare response headers without mutation

Request the test object normally and with a harmless response-header override parameter, such as a different safe text content type, using the authorization mode required by the provider. Do not probe objects owned by other users or attempt to bypass a signature for private resources.

### Phase 4: Verify browser origin isolation

Compare the exact scheme/host/port serving the object with the authenticated application origin and inspect Content-Type, Content-Disposition, X-Content-Type-Options, CSP, and cache variation. Do not execute active content. A same-site subdomain is not necessarily the same origin.

### Phase 5: Review signed URL and CDN behavior

For AWS S3, response override parameters generally require a correctly signed request; use a test bucket and your own credentials where explicitly authorized. Check whether the CDN honors, ignores, or caches the parameter, and whether cache keys include it. Do not manipulate production cache entries.

### Phase 6: Validate permissions and clean up

Verify a private test object remains inaccessible anonymously and that the owner can delete the synthetic object. Capture only headers and a short marker; clean up and document the result.

## What Constitutes a Finding

- **Candidate / lead:** response content type changes with a query parameter, a bucket is publicly readable, or an uploaded asset shares a trusted application origin.
- **Confirmed finding:** storage policy permits a security-relevant header/permission change contrary to intended design, or a private synthetic object is readable by an unauthorized test context.
- **XSS distinction:** header override alone does not prove script execution; active execution should be isolated to a lab/test origin with harmless content and explicit authorization.
- **Not a finding:** public static assets, signed test URLs working as designed, or harmless override metadata without a security impact.

## Evidence Requirements

- Test object key/owner, timestamp, initial and modified request, and sanitized response headers.
- Authentication mode (anonymous or test-signed), origin host, content type/disposition, cache headers, and access policy.
- Browser origin analysis and a negative control for private-object access.
- Never record secrets, signed URL credentials beyond what's needed privately, customer files, or active payload output.

## Tools

- **curl:** compare object response headers with bounded GET/HEAD requests.
- **AWS CLI/SDK for a test bucket:** examine signed response parameters using tester-owned credentials.
- **Browser DevTools:** inspect origin and rendering headers without executing active content.
- **Cloud console / policy review:** check public access blocks, bucket policy, object ownership, and CDN cache keys.

## Object Response and Origin Isolation Matrix

| Control | Test | Confirmation bar |
|---|---|---|
| Public/private policy | Anonymous request for a known synthetic private object | Unauthorized access must fail for private object |
| Content-Type override | Request test object with safe text-type override | Header change is reproducible and within the provider's authorization model |
| Content-Disposition | Compare inline vs attachment on synthetic object | Browser handling differs contrary to intended content-serving policy |
| Origin boundary | Compare object host to app origin | Document exact origin; same-site is not identical to same-origin |
| CDN cache | Compare cache headers/key variation for test object | No cross-user cached response variation or poison path in production |
| Signed S3 URL | Verify response parameter signature in a test bucket | Only intended request parameters are authorized and URL expires per policy |
| XSS impact | Review policies or use lab-only active proof | No active payload delivery to production/shared users |

**Mitigation:** separate user content onto an untrusted origin, validate stored metadata, default to attachment for untrusted files, set safe content headers, block public access to private objects, constrain signed URL permissions/expiry, and vary cache keys safely.

## Verification and False Positives

- S3-compatible providers differ; verify documented behavior for the actual provider/version rather than assuming MinIO equals AWS S3.
- HTTP 200 for an object does not mean it is private or sensitive; confirm intended access policy.
- Query parameters may be ignored or stripped by a CDN; test only a disposable object.
- A same-site subdomain may still be a different origin, and cookie scope is a separate question.
- Do not upload active HTML/SVG/JavaScript, use an external victim-delivery PoC, expose real bucket names/secrets, or poison shared production caches.


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Treat the attempt budget as a ceiling for independent, evidence-producing hypotheses, not a payload quota. If the signal remains plausible, follow the next relevant branch up to 20 distinct hypotheses; stop earlier when impact is decisive, the branch is irrelevant, or scope/safety limits apply. Cosmetic variations of one request are not independent attempts.

Track each attempt as: hypothesis, one changed variable, baseline/control, observed signal, interpretation, confidence, and next branch. Use controlled identities or synthetic resources, preserve only minimal evidence, and redact secrets.

### Skill-specific hypothesis order

1. Confirm the authorized MinIO/S3 endpoint and test bucket, then baseline anonymous and authenticated metadata access without listing or downloading user data.
2. Check effective bucket/object policy, ACLs, anonymous access, signed URL expiry, and tenant boundaries with a purpose-built benign canary object.
3. Use one controlled read or write check only where explicitly authorized; do not enumerate all buckets, copy datasets, or alter/delete production objects.
4. Distinguish a publicly reachable endpoint from a publicly accessible object and a test bucket from a production bucket; correlate policy with effective response.
5. Record exact bucket/prefix, principal, action, and response; propose least-privilege policy, blocking public access where appropriate, and a read-only regression test.


### Verdict gates

- **Confirmed:** repeatable security impact is shown against an in-scope resource using a tester-controlled identity or fixture, with a meaningful control.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause is not yet established.
- **Unconfirmed:** observations are ambiguous, cached, generic, or not tied to a security boundary.
- **Refuted / false positive:** a relevant negative control or valid policy/implementation explanation accounts for the observation; document the attempts instead of claiming all imaginable variants were exhausted.
- Do not treat status codes, error text, response length, decoded tokens, static findings, or UI state alone as proof.

### Stop, cleanup, and handoff

Stop at scope uncertainty, unrelated sensitive data, unexpected production changes, service degradation, secret exposure, or prohibited actions. Restore disposable state and revoke test tokens/sessions where possible. Return the scope proof, baseline, hypothesis, attempt count, impact, controls, confidence/verdict, sanitized evidence pointers, relevant handoff signal and cleanup status. Chain into another skill only when its trigger is present.

## References

- [uphiago/recon-skills — S3/MinIO content-type XSS](https://github.com/uphiago/recon-skills/blob/main/recon/s3-minio-content-type-xss/SKILL.md) — merged storage and content-type source.

- [uphiago/recon-skills — s3-minio-content-type-xss](https://github.com/uphiago/recon-skills/tree/main/recon/s3-minio-content-type-xss)
- [AWS S3 — GetObject response header overrides](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html)
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
