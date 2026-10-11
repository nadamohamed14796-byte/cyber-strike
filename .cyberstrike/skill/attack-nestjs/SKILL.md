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

- **Nest CLI/source search:** inventory controllers, guards, custom decorators, pipes, and resolvers.
- **Burp Suite:** compare routes with controlled identities.
- **OpenAPI/GraphQL tooling:** map operations and request schemas.
- **Test fixture:** verify DTO/write behavior without production data.

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

## References

- [uphiago — hunt-nestjs](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-nestjs)
- [Claude-BugHunter — hunt-nestjs](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-nestjs)
- [NestJS Guards](https://docs.nestjs.com/guards)
- [NestJS Validation](https://docs.nestjs.com/techniques/validation)
