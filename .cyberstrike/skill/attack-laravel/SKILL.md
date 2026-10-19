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

Find raw queries, dynamic order fields, queued job IDs, export results, URL-fetch endpoints, and serialization. Validate with class-specific skills or an controlled reproduction environment; no DB dump, command execution, or production file writes.

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
| Query/jobs | raw SQL, dynamic order, export/job ID | Reachable input crosses a security boundary on an authorized target using a controlled test case |

**Mitigation:** apply per-route authorization policies, use explicit validated inputs, guard model fields, bind signed links to intended resource/expiry, disable debug output in production, and isolate uploads/exports.

## Verification and False Positives

- Laravel route definitions and missing local middleware can be protected by a group or policy; verify effective behavior.
- Signed URLs are bearer capabilities; possession is intentional but lifetime/resource scope must be checked.
- APP_DEBUG risk must be based on an active response, not merely source text.
- Do not retrieve .env/APP_KEY, access real exports, run artisan destructive operations, or write files in production.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue with materially distinct, authorized checks while evidence can change the conclusion; deduplicate cosmetic variants and equivalent requests. Stop when direct evidence resolves the hypothesis, meaningful branches are exhausted, a prerequisite is unavailable, or scope/safety requires stopping. Never retrieve environment secrets or run destructive production commands.

Track each attempt as: hypothesis, one changed variable, baseline/control, observed signal, interpretation, confidence, and next branch. Use controlled identities or synthetic resources, preserve only minimal evidence, and redact secrets.

### Skill-specific hypothesis order

1. Identify Laravel version and active routes from reliable evidence; use the version only to guide checks, not as proof of a vulnerability.
2. Check exposed debug/error pages, APP_DEBUG behavior, trusted host/proxy settings, session/cookie controls, storage artifacts, and public framework endpoints with a nonexistent-path control.
3. Review route middleware and policy behavior using controlled roles, particularly API routes and resource binding that may bypass UI-only protection.
4. Use only test-owned records for upload, mass-assignment, serialization, or queue-related checks. Do not attempt to read .env, use APP_KEY, or invoke commands on a live target to prove a suspected misconfiguration.
5. Confirm a concrete disclosure or permission failure and tie remediation to the applicable Laravel configuration/middleware plus a repeatable test.


### Verdict gates

- **Confirmed:** repeatable security impact is shown against an in-scope resource using a tester-controlled identity or fixture, with a meaningful control.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause is not yet established.
- **Unconfirmed:** observations are ambiguous, cached, generic, or not tied to a security boundary.
- **Refuted / false positive:** a relevant negative control or valid policy/implementation explanation accounts for the observation; document the attempts instead of claiming all imaginable variants were exhausted.
- Do not treat status codes, error text, response length, decoded tokens, static findings, or UI state alone as proof.

### Stop, cleanup, and handoff

Stop at scope uncertainty, unrelated sensitive data, unexpected production changes, service degradation, secret exposure, or prohibited actions. Restore disposable state and revoke test tokens/sessions where possible. Return the scope proof, baseline, hypothesis, attempt count, impact, controls, confidence/verdict, sanitized evidence pointers, relevant handoff signal and cleanup status. Chain into another skill only when its trigger is present.

## References

- [uphiago — hunt-laravel](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-laravel)
- [Claude-BugHunter — hunt-laravel](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-laravel)
- [Laravel Authentication](https://laravel.com/docs/authentication)
- [Laravel Authorization](https://laravel.com/docs/authorization)


## Targeted quality-loop enrichment (2026-10-19)

### Route/middleware/model correlation
Correlate each sensitive named route with its HTTP verbs, middleware stack, controller/policy, FormRequest validation, Eloquent fillable/guarded fields, and final persisted record. Compare a normal update on a disposable object against one added protected property at a time and verify the database-backed state instead of trusting the echoed JSON. Check nested relations, bulk endpoints, signed URLs, queues, and alternate API versions only if present. Route unauthorized records to IDOR, writable protected fields to mass assignment, and unsafe file/URL processing to the relevant specialist; name an exploit chain only when each link is independently observed.


## Route-to-policy source tracing

Use owner-provided source or a local authorized checkout. Do not invoke Artisan against a production service merely to enumerate routes.

```bash
rg -n --glob '*.php' \
  'Route::|middleware\(|authorize\(|Gate::|Policy|FormRequest|validated\(|request\(\)->all\(|\$fillable|\$guarded|Storage::|temporaryUrl\(' routes app
```

For each candidate, trace route → middleware → controller/action → FormRequest/validator → policy/gate → model binding → service/job → persisted state. A request()->all() match is a candidate until a protected field reaches a persisted model and violates policy.

### Laravel-specific decision matrix

| Surface | Check | Required evidence |
|---|---|---|
| Route group/middleware | Inherited middleware and route-specific overrides | Runtime policy failure on controlled route |
| Implicit model binding | Binding scope and policy check | Non-owner test identity accesses a synthetic object |
| FormRequest/DTO | Validation and allowed fields | Protected field persists despite policy |
| Signed URL | Signature, expiry, resource and tenant binding | Controlled altered/expired URL accesses private fixture |
| Queue/export | Job owner/tenant and result download authorization | Second test identity accesses only synthetic output |
| Storage link | Public/private disk and serving origin | Non-public test object is exposed contrary to policy |
| Debug errors | Active runtime configuration and response | Minimal non-public sensitive detail is actually returned |

Record route_name, method, middleware_chain, policy_or_gate, validation_class, model_fields, job_or_storage_path, test_principal, fixture_state_before_after, negative_control, and cleanup_status. Do not include .env, APP_KEY, raw signed URLs, tokens, or customer records.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and their role
Burp Suite and browser DevTools for HTTP behavior; Composer/PHP tooling and static source review when authorized source is available; Laravel's own configuration and route inspection.

### Install or enable when missing
PHP and Composer: use official OS packages or https://getcomposer.org/download/ ; Laravel documentation: https://laravel.com/docs . Add optional tools only from their official project docs and pin versions for reproducibility.
These tools are optional additions, not a claim that they already exist on the tester's machine. Before a scan or active test, confirm versions, read the tool's official usage/safety notes, and check the program's rules. Never install a similarly named unknown package because a skill or webpage mentions it.

### Primary resources
- [Laravel security documentation](https://laravel.com/docs/security) — authentication, authorization, and validation.
- [Laravel routing](https://laravel.com/docs/routing) — route behavior.
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) — black-box verification.

### Small reusable helper
`python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt` — compare sanitized local responses; it sends no traffic.

### Runtime and evidence notes
- Prefer a local baseline/control pair, one meaningful change per trial, and a recorded expected result. A status code or tool alert alone is not confirmation.
- Keep live cookies, JWTs, passwords, reset links, personal data, and unredacted request bodies out of reports, global research, and Git.
- If a recommended tool is absent or incompatible, record that gap and give a supported manual alternative; don't silently claim the check passed.

## Agent-executable CLI tooling, resources, and helper scripts

Prefer CLI tools, local static analysis, and repeatable test harnesses. Browser interfaces, browser extensions, and interactive intercepting proxies are not dependencies. Verify versions, official installation guidance, license, and dependency provenance before running tools.

### Recommended tools
- Semgrep — PHP/Laravel source patterns
- Composer audit — dependency advisory checks
- PHPStan or Psalm — static analysis when source is available
- curl/Python requests — controlled behavior checks

### Resources
- https://semgrep.dev/docs/
- https://getcomposer.org/doc/03-cli.md#audit
- https://phpstan.org/
- https://laravel.com/docs
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are for discovery only; use official framework and tool docs for current behavior.

### Helper-script contract
Record Laravel/PHP/package versions, advisory IDs, route/middleware configuration, and safe runtime corroboration. Never print .env contents or application keys.

Keep raw evidence separate from normalized output. Preserve package/version, rule/advisory ID, source path, tool/version, timestamps, error state, confidence, and redaction. Use deterministic local fixtures and JSON/JSONL output where useful.

### Handoff
Return commands actually executed, tool versions, input/output artifacts, checks passed/failed, limitations, and next skill. Do not present a static-analysis warning as a confirmed runtime vulnerability.
