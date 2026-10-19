---
name: attack-fastapi
description: "Assess FastAPI dependency-based auth, route authorization, Pydantic validation, OpenAPI exposure, and background task boundaries using controlled accounts."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - fastapi
  - python
  - pydantic
  - api
  - dependencies
  - authorization
tech_stack:
  - fastapi
  - python
  - pydantic
  - starlette
  - uvicorn
  - sqlalchemy
cwe_ids:
  - CWE-285
  - CWE-20
  - CWE-200
  - CWE-862
chains_with:
  - attack-bfla
  - attack-mass-assignment
  - attack-ssrf
  - attack-file-upload
prerequisites: []
severity_boost:
  attack-bfla: "A missing dependency/guard matters as BFLA only when a lower-role test identity invokes a restricted handler successfully."
---

# FastAPI Application Security Assessment

## Objective

Review FastAPI routes, dependency injection, Pydantic schemas, OAuth2 dependencies, background tasks and OpenAPI/docs surfaces. Use in-scope test accounts and synthetic records; source-code hints alone are not confirmed findings.

## Testing Methodology

### Phase 1: Map routes and dependency graphs

Inventory APIRouter prefixes, included routers, dependencies at app/router/route level, exception handlers, startup config, and background tasks. Determine whether each sensitive path receives authentication and authorization dependencies.

### Phase 2: Check dependency and role enforcement

Compare route dependencies with a normal allowed and denied baseline. Verify dependency overrides are limited to tests, router inclusion hasn't omitted guards, and object ownership is checked independently of login.

### Phase 3: Review Pydantic models and writable fields

Inspect request models, extra-field policy, aliases, nested models, validation, and response_model filtering. Use a synthetic object to test a harmless disallowed field and confirm persisted state rather than response serialization.

### Phase 4: Inspect OpenAPI, docs, and error handling

Determine whether /openapi.json, /docs, /redoc, tracebacks, and validation responses disclose non-public data or internal paths. Schema exposure by itself is not authorization bypass; avoid requesting config/env endpoints or full environment details.

### Phase 5: Review URL fetch, upload, and background jobs

Trace user-controlled URLs, file names, report generation, and queue/job IDs. Use a controlled callback or inert test object only if explicitly authorized; don't probe internal addresses, active parsers, or production file paths.

### Phase 6: Test tenant and alternate-path consistency

Compare anonymous, owner, and non-owner test accounts across alternate router prefixes, methods, async jobs, and result-download endpoints. Verify every operation and returned artifact remains tied to the requesting owner/tenant.

### Phase 7: Confirm root cause and regression

Trace the dependency and handler in source, keep a minimal sanitized request/response pair, and add a test showing the lower role is denied. Clean up synthetic records.

## What Constitutes a Finding

- **Candidate / lead:** missing Depends() call, publicly exposed docs, extra fields accepted, or a validation error reveals internals.
- **Confirmed finding:** an unauthorized test identity accesses a protected synthetic object or performs a restricted operation, a protected field persists, or a reachable input alters a sensitive backend sink.
- **Not a finding:** route documentation alone, exception formatting without sensitive disclosure, or code lacking an inline dependency but protected by a verified global dependency.

## Evidence Requirements

- Route/method, application version, role, dependency policy, and timestamp.
- Baseline and modified requests with test object ID and before/after state.
- Sanitized OpenAPI/error output and source trace for handler/dependency path.
- Redact tokens, secrets, customer data, and private configuration.

## Tools

- **OpenAPI / FastAPI docs:** inventory routes and schemas when in scope.
- **Burp Suite / curl:** compare auth roles and alternate endpoints.
- **Source review / Semgrep:** trace dependencies, response models, and background jobs.
- **Test fixtures:** confirm state and tenant binding without production data.

## FastAPI Route and Dependency Matrix

| Area | Review | Confirmation |
|---|---|---|
| App/router dependencies | Dependencies applied consistently to included routers | Protected handler reached by anonymous test session |
| OAuth2/current-user dependency | Signature, scopes, role and tenant logic | Server resolves unauthorized principal/action |
| Pydantic schema | Extra field handling, nested object, aliases | Protected test property persists or validation bypass has impact |
| Response model | Sensitive fields excluded from response | Non-public field leaks to unauthorized test user |
| OpenAPI/docs | Policy for schema visibility | Actual secret/private data exposure, not schema alone |
| Background task | Enqueue and result retrieval authorization | Another test identity can access synthetic job output |
| SSRF/upload sink | URL allowlist, file handling, parser | Controlled safe, minimal test case proves boundary crossed |

**Mitigation:** centralize dependencies, enforce object/tenant authorization in services, use strict request models, constrain response fields, protect diagnostics, and bind background job IDs to owners.

## Verification and False Positives

- Dependency inheritance and app-level dependencies can protect a route even without a local Depends declaration; verify runtime behavior.
- Public OpenAPI docs are often intentional and do not imply route access.
- Pydantic may ignore extra input or strip output fields; verify stored state.
- Background jobs may be eventually consistent; compare authoritative state and owner binding.
- Stop before internal SSRF, large uploads, queue flooding, or production file reads/writes.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue with materially distinct, authorized checks while evidence can change the conclusion; deduplicate equivalent requests and retries. Stop when direct evidence resolves the hypothesis, meaningful branches are exhausted, a prerequisite is unavailable, or scope/safety requires stopping.

Maintain an attempt ledger: hypothesis, single changed variable, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer controlled identities, synthetic resources and paired requests. Preserve sanitized evidence and minimize data collected.

### Skill-specific hypothesis order

1. Map the actual FastAPI routes and dependency declarations from permitted OpenAPI/docs or source evidence; do not assume that /docs or /openapi.json being available is itself a vulnerability.
2. Check each sensitive route with anonymous, least-privileged, and authorized test identities, including dependency overrides that may differ between route groups or API versions.
3. Test object/property authorization and request-model validation independently using test-owned records and benign marker fields; distinguish response filtering from the server's effective authorization.
4. Review trusted-host, proxy-header, CORS, debug/error response, and cookie/session settings only where deployed configuration suggests they are relevant.
5. Confirm the boundary with a protected canary and negative control; report the route, effective dependency/role, data/action impacted, and framework-specific remediation plus a regression test.


### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture and a relevant control.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause remains uncertain.
- **Unconfirmed:** response is ambiguous, cached, generic, or not linked to a security boundary.
- **Refuted / false positive:** an applicable negative control or valid policy explanation accounts for the signal. Record the attempt ledger rather than claiming every theoretical variant was exhausted.
- A 2xx status, error difference, header, schema/documentation exposure, scanner alert, or UI-only state is not proof by itself.

### Stop, cleanup, and handoff

Stop on scope ambiguity, unexpected real-user data, unexpected production state changes, service degradation, credential exposure, or a prohibited action. Restore disposable state and revoke temporary tokens/sessions where possible. Handoff target and scope proof, baseline, hypothesis, attempts used, impact, negative controls, verdict/confidence, sanitized evidence pointers, linked-skill signal, and cleanup status. Invoke a related skill only when its triggering signal is observed.

## References

- [uphiago — hunt-fastapi](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-fastapi)
- [Claude-BugHunter — hunt-fastapi](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-fastapi)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)
- [FastAPI Bigger Applications](https://fastapi.tiangolo.com/tutorial/bigger-applications/)


## Targeted quality-loop enrichment (2026-10-19)

### Dependency and schema differential
For each router operation, map path/method, dependency injection chain, authentication and authorization dependencies, Pydantic request/response models, and any background task or URL-fetch feature. Compare a high-role and low-role test account using the same disposable object; do not assume a dependency attached to the router covers every mounted path or transport. Check whether response models filter internal fields, whether nested writable fields alter persisted state, and whether generated OpenAPI security matches actual enforcement. Route object-specific read/write gaps to IDOR/property authorization and URL-consuming features to SSRF only after confirming server-side fetching.


## FastAPI dependency and model source tracing

Use an authorized local source tree. Static matches are a route map, not proof that a dependency is missing at runtime.

```bash
rg -n --glob '*.py' \
  'FastAPI\(|APIRouter\(|include_router|Depends\(|Security\(|OAuth2PasswordBearer|current_user|response_model|extra=|model_config|BackgroundTasks|add_task|File\(|UploadFile|httpx\.|requests\.' .
```

For each route, trace app-level dependencies → router dependencies → endpoint dependencies → service authorization → object lookup → response model/state change. Check whether tests override dependencies only in test setup; never assume a test override affects production.

### Decision matrix

| Surface | Gap hypothesis | Evidence required |
|---|---|---|
| Router inclusion | A mounted router lacks a global dependency | Actual unauthorized request reaches a protected handler |
| Dependency override | Runtime/test configuration changes auth behavior | Production-equivalent test shows the weaker dependency is active |
| Pydantic extra/nested fields | Protected property accepted by input model | Server-side persisted field and policy violation |
| Response model | Internal fields returned beyond intended schema | Controlled unauthorized response contains a genuinely private field |
| Background task | Job creation/result ID not owner-bound | Second test identity accesses synthetic job output |
| URL fetch/upload | Input reaches a server-side network/parser sink | Controlled benign fixture confirms the data flow without internal targets |

Record router_prefix, route_method, dependency_chain, principal, request_model, response_model, object_owner, synthetic_fixture, persisted_change, negative_control, and cleanup_status. Do not fetch environment files or internal URLs to validate a suspected issue.


## Practical tooling, references, and helper scripts (2026-10-19)

### Tools that fit this skill
- Burp Proxy/Repeater/Comparer, observed client requests, OpenAPI/GraphQL schema when available, and jq; use controlled principals and avoid destructive mutations or load tests.
- Treat CLIs as optional until locally verified. Prefer read-only checks; state-changing tests require permission and a disposable fixture.

### Primary resources
- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x00-header/) — risk taxonomy.
- [PortSwigger API testing](https://portswigger.net/web-security/api-testing) — practical methodology.
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) — access control.
- - [Official platform documentation](https://fastapi.tiangolo.com/tutorial/security/) — verify actual defaults.

### Small reusable helper
    python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt
Compares local artifacts offline with heuristic redaction; no requests are sent and sanitization is not guaranteed.

### Evidence and hand-off
- Keep cookies, tokens, reset links, private user data, and secret values out of notes, global research storage, and Git commits. Keep private originals local; share only reviewed derivatives.
- Mark outcomes confirmed, disproven, or still hypothetical. Record tool errors and coverage gaps rather than inventing results.

Compare baseline and control, vary one meaningful property, and record alternative explanations before confirming a lead.
