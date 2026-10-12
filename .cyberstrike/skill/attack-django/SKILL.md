---
name: attack-django
description: "Assess Django views, middleware, ORM/query construction, serializers, admin surfaces, and deployment configuration for reachable security-boundary failures."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - django
  - python
  - orm
  - drf
  - middleware
  - web
tech_stack:
  - django
  - python
  - django-rest-framework
  - postgresql
  - mysql
cwe_ids:
  - CWE-89
  - CWE-285
  - CWE-200
  - CWE-915
chains_with:
  - attack-sqli
  - attack-bfla
  - attack-mass-assignment
  - attack-file-upload
prerequisites: []
severity_boost:
  attack-sqli: "Unsafe ORM raw fragments or identifier handling become SQL injection only when untrusted input reaches a query structure in the tested path."
---

# Django and Django REST Framework Security Assessment

## Objective

Review a scoped Django app's routing, middleware, ORM usage, DRF serializers/permissions, admin and operational settings. Validate with test accounts and synthetic objects; do not infer a vulnerability from framework defaults or version strings alone.

## Testing Methodology

### Phase 1: Identify app and deployment context

Use source manifests/lockfiles or owner-provided version metadata to determine Django/DRF versions, middleware, database backend, and deployment settings. Public banners are only hints; corroborate version and relevant patch/advisory.

### Phase 2: Check view and DRF permission coverage

Map URL patterns, class/function-based views, ViewSets, router actions, and custom permission classes. Verify list, retrieve, create, update, delete, and custom actions enforce object-level and function-level permissions, including nested routes.

### Phase 3: Review serializer and writable-field behavior

Inspect serializers' fields/read_only_fields, nested serializers, queryset restrictions, and create/update hooks. In a test fixture, add one harmless protected property and verify persisted state; never modify real role, billing, or tenant ownership.

### Phase 4: Inspect ORM and dynamic query construction

Search for raw(), extra(), cursor execution, dynamic order_by/field names, JSONField paths, and string concatenation. Confirm input reachability through source review or a non-destructive test fixture. Use the dedicated SQLi skill for bounded validation; do not dump production tables.

### Phase 5: Review settings, files, and diagnostics

Check DEBUG, ALLOWED_HOSTS, trusted proxy headers, secret/config exposure, file storage/serving, upload validation, and error pages. Capture only minimal sanitized evidence; do not request environment dumps, database backups, or secret-bearing settings.

### Phase 6: Test auth and workflow variants

Compare anonymous/owner/non-owner behavior for a synthetic object, including trailing slash, alternate methods, API versions, and custom DRF actions. A malformed body may be rejected before auth; send a minimal well-formed control before inferring missing authentication.

### Phase 7: Confirm and remediate

Tie the defect to a reachable view/serializer/query/configuration and write a regression test for the specific route and role. Clean up the fixture and retain only sanitized request/response evidence.

## What Constitutes a Finding

- **Candidate / lead:** DEBUG-like error page, public admin route, serializer accepting unknown properties, or unsafe ORM call in source.
- **Confirmed finding:** a controlled unauthorized request reads/changes a synthetic object contrary to policy, a protected property persists, or source plus safe test proves attacker-controlled query structure.
- **Not a finding:** framework presence, public Django admin login page, harmless validation error, or raw() usage that receives only trusted constants.

## Evidence Requirements

- Django/DRF version evidence, route/action, database backend, role, and timestamp.
- Matched request/response and before/after state for synthetic data.
- Source line/config relevant to middleware, permission class, serializer field, or query construction.
- Redact SECRET_KEY, cookies/tokens, environment values, private data and database content.

## Tools

- **Django URL/source search:** inventory views, routers, middleware and permission classes.
- **Burp Suite:** compare controlled roles and HTTP methods.
- **Semgrep / code review:** locate raw SQL and unsafe serializer/query patterns.
- **Official security releases:** verify affected version ranges and fixes.

## Django Control and Query Matrix

| Surface | Review | Confirmation |
|---|---|---|
| ViewSet/action | Global, view-level, and object permissions | Restricted action succeeds for low-role test user |
| Serializer | Writable fields, nested data, read-only fields | Protected synthetic property persists |
| ORM raw/dynamic field | Raw SQL, dynamic identifier, JSONField key | Untrusted input affects query structure in controlled test |
| Middleware/Host | DEBUG, ALLOWED_HOSTS, proxy trust, CSRF | Policy boundary is actually bypassed or private detail leaked |
| Admin/diagnostics | Admin login, debug toolbar, traceback | Non-public information/control exposed beyond intended design |
| Upload/storage | Validation, storage root/origin, serving headers | Test-owned file crosses authorization/origin boundary |
| API methods | List/detail/custom actions and trailing slash | Equivalent policy missing on specific route |

**Mitigation:** enforce object-level permissions, use explicit serializer allowlists, parameterize values and allowlist identifiers, disable DEBUG in production, protect diagnostics, and regression-test every custom action.

## Verification and False Positives

- A Django admin login page and public OpenAPI endpoint may be intentionally exposed.
- Serializers may discard unknown fields; response echo is not persistence proof.
- ORM raw APIs can be safe when query structure is constant and values are parameterized.
- Error messages and malformed bodies can come from middleware before authorization.
- Stop before reading settings/secrets, accessing real records, dumping databases, or writing production files.


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Treat the attempt budget as a ceiling for evidence-producing hypotheses, not a quota for payload variants. When a candidate remains plausible, branch to the next independent hypothesis up to a maximum of 20; stop earlier when evidence is decisive, the remaining hypotheses are not relevant, or safety/scope limits apply. Cosmetic variants of the same request do not count as independent attempts.

Keep a ledger per attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve evidence, redact secrets, and avoid unrelated data.

### Skill-specific hypothesis order

1. Establish the deployed Django version and application entry points from reliable response or approved source/config evidence; do not infer patch level from a banner alone.
2. Check deployment controls relevant to the observed stack: DEBUG leakage, ALLOWED_HOSTS handling, secure cookie/HTTPS settings, CSRF origin policy, admin exposure, and debug/static artifact publication.
3. Use controlled test identities to compare route authorization, object ownership, and form/API validation; verify that model-level policy holds when requests bypass the UI.
4. Exercise host-header and password-reset URL behavior only with an inbox and controlled domain you own; do not send reset flows to third-party addresses.
5. Confirm a concrete exposed setting or authorization failure with a harmless control, and pair it with the exact Django setting/code-level fix plus a regression test.


### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture, with a relevant control and a clear trust-boundary failure.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause is not established.
- **Unconfirmed:** the signal is ambiguous, cached, generic, or not tied to a security boundary.
- **Refuted / false positive:** a relevant negative control, valid authorization explanation, or repeatable contradictory evidence explains the signal. Record the attempts; do not claim every theoretical variant was exhausted.
- Status, banners, stack traces, response length, endpoint existence, tool alerts, or frontend state are not sufficient on their own.

### Stop, cleanup, and handoff

Stop at scope boundaries, unexpected real-user data, production side effects, rate-limit/availability degradation, secret exposure, or prohibited action. Clean up disposable state, revoke temporary sessions/tokens when possible, and record status. Return target/scope evidence, baseline, hypothesis, attempts used, impact, controls, verdict/confidence, sanitized evidence, handoff signal, and cleanup status. Trigger a chained skill only when its signal is observed.

## References

- [uphiago — hunt-django](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-django)
- [Claude-BugHunter — hunt-django](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-django)
- [Django Security](https://docs.djangoproject.com/en/stable/topics/security/)
- [Django REST Framework Permissions](https://www.django-rest-framework.org/api-guide/permissions/)
