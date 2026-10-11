---
name: attack-laravel
description: "Assess Laravel routes, middleware, Eloquent binding, validation, storage, debug settings, and signed workflow links using test-owned objects."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - laravel
  - php
  - eloquent
  - middleware
  - storage
  - web
tech_stack:
  - laravel
  - php
  - eloquent
  - sanctum
  - passport
  - mysql
  - redis
cwe_ids:
  - CWE-284
  - CWE-915
  - CWE-200
  - CWE-434
chains_with:
  - attack-bfla
  - attack-mass-assignment
  - attack-deserialization
  - attack-file-upload
  - attack-sqli
prerequisites: []
severity_boost:
  attack-mass-assignment: "A guarded-model failure becomes privilege escalation only when a protected test property is persisted and an authorization consequence is demonstrated."
---

# Laravel Application Security Assessment

## Objective

Review Laravel routes/middleware, policies, Eloquent mass assignment, validation, storage, signed URLs, and diagnostics. Use synthetic test records and avoid exposing APP_KEY, environment data, or real storage content.

## Testing Methodology

### Phase 1: Identify routes and version

Use composer.lock, route:list output provided by the owner, normal app traffic, and response assets to identify Laravel version and route groups. Correlate exact package versions to current advisories.

### Phase 2: Audit route middleware and policies

Check web/api route groups, middleware aliases, exclusions, implicit model binding, policies/gates, Sanctum/Passport guards, and custom action routes. Confirm each sensitive route checks both authenticated identity and object ownership.

### Phase 3: Review Eloquent mass assignment

Inspect fillable/guarded settings, nested relation binding, request->all usage, DTOs, and create/update hooks. Use a disposable test model to test one benign protected field and verify persisted state; never change real admin roles or ownership.

### Phase 4: Check validation, signed URLs, and state transitions

Review request validation, temporary download links, signed URL expiry, tenant binding, and password/reset/email-verification flows. Use test-owned links and synthetic objects; do not access another user's private exports.

### Phase 5: Inspect debug and storage exposure

Review APP_DEBUG configuration through source/owner-provided config rather than accessing environment dumps. Check storage link, upload serving origin, directory listing, backup/config routes, and response headers with inert test files only.

### Phase 6: Review query and job paths

Find raw queries, dynamic order fields, queued job IDs, export results, URL-fetch endpoints, and serialization. Validate with class-specific skills or an isolated lab; no DB dump, command execution, or production file writes.

### Phase 7: Confirm and remediate

Compare role/tenant behavior with test accounts, validate authoritative state and cleanup, then add route/policy regression coverage. Use minimal sanitized errors and requests.

## What Constitutes a Finding

- **Candidate / lead:** route lacks obvious middleware, uses request->all(), exposes debug-like errors, or signed URL behavior seems inconsistent.
- **Confirmed finding:** a synthetic protected field persists, a low-role test user accesses a restricted object/action, or a private diagnostic/storage resource is exposed contrary to policy.
- **Not a finding:** route:list/docs exposure alone, a debug setting mentioned in source but not active, or a field echoed without persistence.

## Evidence Requirements

- Laravel/framework and relevant package versions, route/method, role, timestamp.
- Sanitized request/response and synthetic object before/after state.
- Relevant route middleware, policy, model fillable/guarded, and storage config references.
- Redact APP_KEY, .env contents, passwords, signed URLs, cookies/tokens, and private objects.

## Tools

- **Source search / route:list in test or owner-provided environment:** map routes and middleware.
- **Burp Suite:** compare role and HTTP method variants.
- **Composer lockfile/advisories:** confirm affected package versions.
- **Test fixtures:** validate Eloquent write behavior and authorization without production data.

## Laravel Control Matrix

| Surface | Review | Confirmation |
|---|---|---|
| Routes/middleware | web/api groups, exclusions, custom routes | Unauthorized controlled request performs restricted operation |
| Policies/gates | per-object ownership and role checks | Non-owner test account reaches synthetic resource |
| Eloquent | fillable/guarded and request->all() | Protected test property persists |
| Sanctum/Passport | token ability, audience/scope and revocation | Token from a test context gains unintended access |
| Signed URLs | signature, expiry, tenant and resource binding | Altered/expired test link accesses private synthetic object |
| Debug/storage | APP_DEBUG, storage link, upload origin | Non-public diagnostics/object exposed with evidence |
| Query/jobs | raw SQL, dynamic order, export/job ID | Reachable input crosses a security boundary in a lab/test fixture |

**Mitigation:** apply per-route authorization policies, use explicit validated inputs, guard model fields, bind signed links to intended resource/expiry, disable debug output in production, and isolate uploads/exports.

## Verification and False Positives

- Laravel route definitions and missing local middleware can be protected by a group or policy; verify effective behavior.
- Signed URLs are bearer capabilities; possession is intentional but lifetime/resource scope must be checked.
- APP_DEBUG risk must be based on an active response, not merely source text.
- Do not retrieve .env/APP_KEY, access real exports, run artisan destructive operations, or write files in production.

## References

- [uphiago — hunt-laravel](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-laravel)
- [Claude-BugHunter — hunt-laravel](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-laravel)
- [Laravel Authentication](https://laravel.com/docs/authentication)
- [Laravel Authorization](https://laravel.com/docs/authorization)
