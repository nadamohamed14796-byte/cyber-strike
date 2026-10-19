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


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue with materially distinct, authorized checks while evidence can change the conclusion; deduplicate cosmetic variants and equivalent requests. Stop when direct evidence resolves the hypothesis, meaningful branches are exhausted, a prerequisite is unavailable, or scope/safety requires stopping. Never retrieve sensitive Actuator data or trigger state-changing management operations on production.

Keep an attempt ledger: hypothesis, one variable changed, baseline/control, signal, interpretation, confidence and next branch. Use controlled identities/fixtures, independent corroboration, low-impact requests and minimum sanitized evidence.

### Skill-specific hypothesis order

1. Identify the exact Spring Boot deployment/version and context path using confirmed evidence, then map read-only health/info/config endpoints against a random-path control.
2. Check which Actuator endpoints are actually exposed and whether their detail level is appropriate; distinguish a minimal health check from environment, beans, mappings, heap, or log data disclosure.
3. Compare anonymous and authorized test-role responses and inspect network-level restrictions; do not invoke shutdown, refresh, heap dumps, loggers, or other state-changing/high-volume endpoints.
4. Redact environment values, credentials, internal topology, and filesystem paths as soon as observed. A 200 status or endpoint name without sensitive content is not proof of impact.
5. Recommend disabling unnecessary endpoints, securing required endpoints through Spring Security/network controls, and testing exposure again with a random-path and authorized-role control.


### Verdict gates

- **Confirmed:** repeatable impact at an explicit in-scope boundary is demonstrated with a controlled fixture/identity and relevant control.
- **Likely / needs corroboration:** multiple independent signals support the candidate but the effect or cause remains uncertain.
- **Unconfirmed:** signal is generic, timing/cache-dependent, or not tied to a security property.
- **Refuted / false positive:** a relevant control or valid product/security behavior explains the observation; preserve the test ledger rather than claiming all theoretical vectors were attempted.
- A status code, banner, parser error, timing fluctuation, version string, or scanner alert alone is not proof.

### Safety, cleanup, and handoff

Stop on scope ambiguity, unexpected state changes, sensitive data, service degradation, secret exposure or prohibited actions. Restore synthetic state and revoke temporary credentials/sessions where possible. Report scope proof, baseline, hypothesis, attempt count, impact, controls, verdict/confidence, sanitized evidence and cleanup status. Chain into another skill only after observing its required signal.

## References

- [uphiago — hunt-springboot](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-springboot)
- [Claude-BugHunter — hunt-springboot](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-springboot)
- [Spring Boot Actuator Endpoints](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html)
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)


## Targeted quality-loop enrichment (2026-10-19)

### Spring security-chain and actuator review
Identify the deployed product/profile, reverse-proxy path, ordered SecurityFilterChain matchers, controller mappings, method-level annotations, Actuator exposure/configuration, and serialization settings. Test one read-only endpoint as anonymous and controlled roles; compare the actual resolved data and policy across management/application ports only when in scope. An Actuator endpoint name, Spring banner, or OpenAPI listing is a lead rather than a vulnerability. Confirm that exposed environment/heap/health details are sensitive and not intentionally public, and never download heap dumps or secrets to prove access. Route expression/deserialization findings to the corresponding input specialists and route role/object gaps to BFLA/IDOR.


## Local source-review helper

Use this only on an authorized local repository. Search hits need contextual review; a missing annotation may be covered by a global filter chain.

```bash
rg -n --glob '*.{java,kt,yml,yaml,properties}' \
  'SecurityFilterChain|authorizeHttpRequests|requestMatchers|@PreAuthorize|@Secured|@RolesAllowed|management\.endpoints|include:|exclude:|@RequestMapping|@RestController' .
```

### Evidence fields

Record application_port_vs_management_port, context_path, active_profile_source, filter_chain_order, matched_route, method_security, actuator_exposure_config, principal, data_classification, random_path_control, and cleanup_status. Do not fetch secret-bearing endpoints to fill unknown fields; use source/config evidence or mark the fact unverified.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Use Burp for HTTP behavior, Maven or Gradle for dependency/configuration analysis on an authorized source checkout, and Semgrep for targeted static checks when the source is available.

### Installation and setup
- [Spring Security documentation](https://spring.io/projects/spring-security) — version-specific integration.
- [Maven installation](https://maven.apache.org/install.html) or [Gradle installation](https://gradle.org/install/) — follow the project's existing wrapper when available rather than replacing build versions.
- [Semgrep getting started](https://semgrep.dev/docs/getting-started/) — optional source review.
Run dependency checks on a disposable copy and preserve lock/build files. A default actuator path or static rule match is a lead; verify actual exposure/access control.

### Primary resources
- [Spring Boot security](https://docs.spring.io/spring-boot/reference/web/spring-security.html) — official behavior/configuration.
- [Spring Actuator reference](https://docs.spring.io/spring-boot/reference/actuator/index.html) — management endpoints.
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) — black-box evidence.

### Reusable helper
`python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt` compares sanitized responses saved locally.

### Result handling
Record exact app/version, route, authentication context, and the sensitive operation/data actually exposed. Redact actuator environment/config output before storing evidence.
