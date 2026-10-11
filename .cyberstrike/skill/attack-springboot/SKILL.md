---
name: attack-springboot
description: "Assess Spring Boot controllers, Spring Security filter chains, Actuator endpoints, method authorization, and binding behavior with test identities and non-sensitive probes."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - spring-boot
  - java
  - actuator
  - spring-security
  - api
tech_stack:
  - spring-boot
  - spring-security
  - java
  - spring-mvc
  - webflux
  - actuator
cwe_ids:
  - CWE-284
  - CWE-200
  - CWE-862
  - CWE-915
chains_with:
  - attack-bfla
  - attack-mass-assignment
  - attack-deserialization
  - attack-sqli
prerequisites: []
severity_boost:
  attack-bfla: "A missing Spring Security matcher or method annotation is a privilege flaw only when a restricted operation succeeds for a lower-role test identity."
---

# Spring Boot Security Assessment

## Objective

Review Spring Boot request routing, Spring Security matcher/filter ordering, method-level authorization, Actuator exposure and object binding. Use safe read-only endpoints and test accounts; do not dump environment or configuration secrets from Actuator.

## Testing Methodology

### Phase 1: Identify deployed components and profiles

Use build files, dependency manifests, safe headers, and owner-provided configuration to identify Spring Boot/Security versions, servlet versus reactive stack, and active profiles. Correlate against current vendor advisories rather than relying on a generic banner.

### Phase 2: Inventory Spring Security chains

Review SecurityFilterChain order, requestMatchers, ignored/static paths, CSRF settings, authentication entry points, and method-security annotations. Compare the route to the intended role policy; a path excluded from one chain may be covered by another.

### Phase 3: Check Actuator exposure conservatively

Start with /actuator/health or an explicitly permitted metadata endpoint. Inventory configured exposure from source/config rather than requesting env, configprops, heapdump, logfile, mappings, beans, or startup data that may contain secrets. Treat health information separately from sensitive management disclosure.

### Phase 4: Review controller binding and authorization

Inspect DTO/entity binding, Jackson polymorphism, @ModelAttribute, validation annotations, repository finders, and ownership checks. Use synthetic objects and harmless fields to test mass assignment/property-level access.

### Phase 5: Check error and expression surfaces

Review verbose errors, SpEL/templating usage, file upload, URL fetch, deserialization, and raw SQL separately with class-specific skills. Do not submit expression commands, serialized gadgets, or destructive payloads to production.

### Phase 6: Compare role and method variants

Use test accounts to compare GET and permitted method variants, versioned endpoints, trailing slash, and reactive/servlet route differences. Verify authoritative state for any authorized disposable mutation.

### Phase 7: Confirm the fix path

Trace the exact filter/handler/service configuration and patch. Add a regression test for the affected URL/method/role and redact tokens, Actuator values, and environment data.

## What Constitutes a Finding

- **Candidate / lead:** Actuator route is reachable, a version matches an advisory, matcher ordering looks inconsistent, or entity binding exposes a protected field.
- **Confirmed finding:** a protected non-sensitive operation is available to an unauthorized test role, private diagnostic data is exposed beyond policy, or a protected synthetic property persists.
- **Not a finding:** /actuator/health alone, public info endpoint with intended contents, a security annotation missing where equivalent central policy applies, or a version match without reachable preconditions.

## Evidence Requirements

- Boot/Security version and servlet/reactive profile evidence, endpoint/method, role, and timestamp.
- Sanitized response with only minimal diagnostic marker; never attach heap dumps, environment values, tokens, or secrets.
- Matched request/control and synthetic before/after state.
- Relevant filter-chain, method-security, DTO, and Actuator-exposure configuration.

## Tools

- **curl / Burp Suite:** bounded request comparison under test roles.
- **Source/config review:** inspect filter chains, method annotations and management exposure.
- **Dependency/SBOM scanner:** identify version candidates and vendor patch range.
- **Official Spring docs/security advisories:** confirm configuration and supported fixes.

## Spring Boot Exposure and Authorization Matrix

| Surface | Review | Safe confirmation |
|---|---|---|
| Filter chain | Matchers, order, ignored routes, CSRF | Controlled low-role request reaches protected operation |
| Method security | @PreAuthorize/roles/object ownership | Test-owned object access denied/allowed as expected |
| Actuator | Exposed management endpoints and network policy | Minimal health/metadata check; secrets never fetched |
| Binding/DTO | Entity binding, Jackson types, protected properties | Synthetic property persists contrary to policy |
| Error handling | Stack traces and sensitive diagnostics | Minimal non-public detail reproduced |
| Expression/deserialization | User input into SpEL or unsafe type resolver | Source review/lab only; no production command payload |
| Reactive/servlet parity | Separate filters/router config | Actual route has missing auth policy |

**Mitigation:** restrict Actuator by network/auth, order filter chains explicitly, use method-level and object-level checks, bind to DTO allowlists, and add security regression tests per route.

## Verification and False Positives

- Actuator health/info behavior depends on configuration and may be intentionally public.
- A missing annotation does not prove missing authorization if global rules apply.
- Version strings can be backported or hidden behind a proxy; verify dependency and patch state.
- Never request heap dumps, full environment/config properties, logfiles or other secret-bearing diagnostics on production unless explicitly authorized and carefully scoped.

## References

- [uphiago — hunt-springboot](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-springboot)
- [Claude-BugHunter — hunt-springboot](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-springboot)
- [Spring Boot Actuator Endpoints](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html)
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
