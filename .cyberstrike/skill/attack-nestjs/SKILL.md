---
name: attack-nestjs
description: "Assess NestJS controllers, guards, interceptors, DTO validation, GraphQL resolvers, and Swagger exposure for authorization and input-validation gaps."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - nestjs
  - nodejs
  - typescript
  - guards
  - dto
  - graphql
tech_stack:
  - nestjs
  - nodejs
  - typescript
  - express
  - fastify
  - graphql
cwe_ids:
  - CWE-285
  - CWE-20
  - CWE-915
  - CWE-862
chains_with:
  - attack-bfla
  - attack-mass-assignment
  - attack-graphql
  - attack-auth-bypass
prerequisites: []
severity_boost:
  attack-bfla: "A controller/resolver guard omission is a function-level flaw when a low-role test identity reaches a restricted function."
---

# NestJS Framework Security Assessment

## Objective

Review NestJS guard/interceptor/pipe patterns and route-level security consistency. Use controlled roles and synthetic records; don't assume decorators, Swagger annotations, or a globally configured guard protect every controller or resolver.

## Testing Methodology

### Phase 1: Map modules, controllers, and transports

Identify REST controllers, GraphQL resolvers, WebSocket gateways, microservice handlers, and global/module-scoped guards. Use source manifests and public docs to understand the current architecture.

### Phase 2: Check guard coverage and execution order

Compare class-level versus method-level guards, public-route decorators, inheritance, custom metadata, and global guard registration. Confirm each sensitive handler checks the caller's role and object ownership on the server.

### Phase 3: Review DTO validation and mass assignment

Inspect ValidationPipe settings, whitelist/forbidNonWhitelisted behavior, transform options, nested DTOs, and entity binding. In a staging fixture, submit one harmless protected field and verify authoritative state; never change a real role or tenant.

### Phase 4: Audit GraphQL and alternate transports

Check whether REST guards are mirrored in GraphQL resolver, subscription, WebSocket, and microservice paths. Test only a specific documented test operation and a synthetic object. Schema visibility is not proof of access.

### Phase 5: Review Swagger and exception filters

Determine whether Swagger/docs are intentionally public and whether errors leak internal paths, stack traces, tokens, or environment values. Capture only the minimal sanitized evidence.

### Phase 6: Verify through a controlled role matrix

Compare anonymous, user, and admin test identities on read-only methods first. Use disposable records for permitted mutations, and verify persisted state. Trace any gap to controller/resolver guard, DTO, or provider configuration.

## What Constitutes a Finding

- **Candidate / lead:** missing guard decorator, weak DTO validation, publicly accessible Swagger, or unexpected error output.
- **Confirmed finding:** an unauthorized test role executes a restricted handler or persists a protected model property despite policy forbidding it.
- **Not a finding:** Swagger exposure by itself, decorator absence where equivalent global guard is effective, or an echoed field not persisted.

## Evidence Requirements

- Controller/resolver/handler route, HTTP or transport method, role, timestamp, and test setup.
- Matched allowed/denied requests and authoritative state for a disposable record.
- Sanitized validation/error output and relevant guard/pipe/DTO source references.
- Redact secrets, private response fields, and production customer data.

## Tools

- `rg`: inventory controllers, guards, custom decorators, pipes, and resolvers in an authorized source checkout.
- `semgrep`: scan local TypeScript source with relevant rules.
- OpenAPI/GraphQL parser: map operations and request schemas where available.
- Python `httpx` or `curl`: compare observed routes using controlled identities when a live check is required.
- Project test runner: validate DTO/write behavior with synthetic fixtures.

Verify `node --version`, `npm --version`, `semgrep --version`, and `curl --version`. Official docs: https://docs.nestjs.com/, https://semgrep.dev/docs/getting-started/, https://curl.se/docs/.

## NestJS Security Control Matrix

| Layer | Common gap | Proof standard |
|---|---|---|
| Controller method | Guard exists on some methods but not the target | Low-role test account performs restricted operation |
| Global/class guard | Public decorator or override bypasses expected protection | Effective runtime guard chain confirmed |
| DTO / ValidationPipe | Extra properties are accepted or transformed unsafely | Protected field persists in synthetic object |
| GraphQL resolver | REST authorization not mirrored | Unauthorized resolver access to a synthetic fixture |
| WebSocket/microservice | Different transport misses normal auth context | Controlled test request crosses access boundary |
| Swagger/exception | Internal detail leakage | Non-public sensitive detail is actually returned |

**Mitigation:** centralize guards, default-deny sensitive handlers, use explicit DTOs and strict validation, authorize object ownership in services, and test each transport separately.

## Verification and False Positives

- A decorator may delegate to a global guard or policy service; inspect effective runtime behavior.
- Swagger is often intentionally available to developers or authenticated users; sensitivity and program policy matter.
- DTO transform behavior can remove or ignore fields; verify persisted state rather than echo.
- Stop before privileged changes, broad resolver enumeration, or mutations without a disposable fixture.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue with materially distinct, authorized checks while evidence can change the conclusion; deduplicate cosmetic variants and equivalent requests. Stop when direct evidence resolves the hypothesis, meaningful branches are exhausted, a prerequisite is unavailable, or scope/safety requires stopping.

Track each attempt as: hypothesis, one changed variable, baseline/control, observed signal, interpretation, confidence, and next branch. Use controlled identities or synthetic resources, preserve only minimal evidence, and redact secrets.

### Skill-specific hypothesis order

1. Map NestJS controllers, routes, guards, interceptors, and validation behavior from permitted traffic/source evidence; check whether guard application differs across controller and method levels.
2. Compare anonymous, low-privilege, and authorized test identities on one route in each relevant controller, including nested resource ownership.
3. Test validation and property-level authorization on test-owned records using benign marker fields; compare DTO allowlisting and validation pipe behavior between create/update routes.
4. Check deployment-specific debug, CORS, trusted proxy, and exception-filter behavior with safe negative controls rather than assuming defaults from the framework name.
5. Confirm one server-side policy failure or unintended disclosure, then identify the missing guard/policy/DTO validation and provide a regression case.


### Verdict gates

- **Confirmed:** repeatable security impact is shown against an in-scope resource using a tester-controlled identity or fixture, with a meaningful control.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause is not yet established.
- **Unconfirmed:** observations are ambiguous, cached, generic, or not tied to a security boundary.
- **Refuted / false positive:** a relevant negative control or valid policy/implementation explanation accounts for the observation; document the attempts instead of claiming all imaginable variants were exhausted.
- Do not treat status codes, error text, response length, decoded tokens, static findings, or UI state alone as proof.

### Stop, cleanup, and handoff

Stop at scope uncertainty, unrelated sensitive data, unexpected production changes, service degradation, secret exposure, or prohibited actions. Restore disposable state and revoke test tokens/sessions where possible. Return the scope proof, baseline, hypothesis, attempt count, impact, controls, confidence/verdict, sanitized evidence pointers, relevant handoff signal and cleanup status. Chain into another skill only when its trigger is present.

## References

- [uphiago — hunt-nestjs](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-nestjs)
- [Claude-BugHunter — hunt-nestjs](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-nestjs)
- [NestJS Guards](https://docs.nestjs.com/guards)
- [NestJS Validation](https://docs.nestjs.com/techniques/validation)


## Targeted quality-loop enrichment (2026-10-19)

### Guard/pipe/interceptor coverage
For every controller/transport, map module, guard order, route-level overrides, parameter decorators, DTO validation, serializer/interceptor, and object lookup policy. Compare the same read-only operation as authorized and low-privilege test principals and verify the actual response fields and server-side state. Pay special attention to custom decorators and routes where controller-level guards differ from method-level behavior, plus GraphQL/resolver and websocket gateways. A DTO rejecting malformed input does not demonstrate authorization, and a swagger declaration does not prove enforcement. Route writable security-sensitive properties to mass-assignment review and field disclosure to API property authorization.


## Source inventory helper

Run this against the authorized local repository. Use matches to map coverage, then inspect the effective guard and route path; decorators alone do not establish runtime protection.

```bash
rg -n --glob '*.{ts,js}' \
  '@(Controller|Resolver|UseGuards|Public|Roles|SetMetadata|Mutation|Query|Subscription)|ValidationPipe|forbidNonWhitelisted|whitelist|APP_GUARD|CanActivate|ExecutionContext' src .
```

### Guard/DTO evidence fields

Record module_name, controller_or_resolver, route_or_operation, transport, guard_chain, public_override, dto_class, validation_options, principal_role, object_owner, persisted_field_change, effective_permission, negative_control, and cleanup_status.

### Chain rules

- Guard missing on one operation → BFLA only after a low-role controlled request reaches the protected function.
- Extra DTO field persists → mass-assignment/property authorization, not merely weak validation.
- Nested object belongs to another test account → BOLA/IDOR if object policy fails.
- GraphQL/WS path differs from REST → validate each transport independently; do not assume shared middleware.
- Swagger or error stack visible → information disclosure only if non-public sensitive details are exposed contrary to policy.


## Agent-executable CLI tooling, resources, and helper scripts

- `rg`: inventory controllers, guards, decorators, pipes, and resolvers in an authorized source checkout.
- `semgrep`: scan local TypeScript source with relevant rules.
- `npm` / project test runner: reproduce DTO and authorization behavior with synthetic fixtures.
- Python `httpx` or `curl`: compare observed routes using controlled identities when a live check is required.
- `python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt`: compare saved responses offline.

Verify `node --version`, `npm --version`, `semgrep --version`, and `curl --version`. Official docs: https://docs.nestjs.com/security, https://docs.nestjs.com/guards, https://semgrep.dev/docs/getting-started/, https://curl.se/docs/.

Pair source-level concerns with a relevant test where feasible. Code findings alone may not be reachable; use a disposable clone/test environment and preserve the lockfile.
