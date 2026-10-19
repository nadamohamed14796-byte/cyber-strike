---
name: attack-api-noauth-hunt
description: "Discover and validate API endpoints that expose data or privileged operations without the required authentication or object-level authorization."
category: "api-security"
version: "1.0.0"
author: "cyberstrike-official"
tags: [api, authentication, authorization, openapi, graphql, access-control]
tech_stack: [REST, OpenAPI, GraphQL, HTTP]
cwe_ids: [CWE-306, CWE-862, CWE-863]
chains_with: [attack-graphql, attack-grpc, attack-idor-automation, attack-auth-bypass, attack-information-disclosure]
prerequisites:
  - "A confirmed in-scope API host or endpoint"
  - "A baseline request and controlled test identity when applicable"
severity_boost:
  high: "Sensitive tenant data or privileged operations are reachable without the intended identity or permission check."
---

# Unauthenticated API Exposure Hunting

## Objective

Find API routes where authentication, authorization, or operation-level controls are absent or inconsistently applied. Distinguish intentionally public endpoints from data or actions whose business context requires an authenticated principal.

## Testing Methodology

### 1. Build the endpoint inventory

Collect API hosts and paths from first-party JavaScript, mobile clients, documented routes, OpenAPI/Swagger documents, GraphQL schemas, traffic captures, and observed version prefixes. Record method, content type, authentication mechanism, object identifiers, tenant context, and expected role. Documentation exposure is an inventory source, not a vulnerability by itself.

### 2. Establish a request matrix

For each representative endpoint, compare anonymous, invalid/expired credentials, a low-privilege controlled account, and an authorized account for the same test object. Keep headers, body, object, and method identical except for the identity dimension being tested. Verify whether cookies, bearer tokens, API keys, mTLS, or gateway identity headers are required.

### 3. Classify the endpoint

Separate public read endpoints, private read endpoints, object-level operations, administrative functions, and state-changing operations. Inspect methods independently: a protected GET does not prove POST/PUT/PATCH/DELETE are protected, and a successful OPTIONS request does not prove data exposure.

### 4. Inspect schemas and error behavior

Review OpenAPI operation security declarations and inherited security requirements, per-operation overrides, deprecated versions, alternate routes, and inconsistent auth middleware. Compare schema declarations with observed behavior. Use bounded, non-sensitive requests; avoid broad enumeration of customer records.

### 5. Validate data exposure minimally

A finding needs a meaningful field or record that should not be public, not simply JSON output. Prefer a synthetic test object or a single controlled sample. Redact values and preserve only enough evidence to establish sensitivity and missing access control.

### 6. Validate writes only when expressly permitted

Use a disposable synthetic record in a test collection. Verify the intended authorization failure first, perform the minimum state change, then remove the synthetic record if cleanup is supported. Never create, modify, or delete real user data to prove impact.

### 7. Trace the control gap

Determine whether the root cause is missing authentication middleware, route-specific middleware omission, an unprotected legacy version, object-level authorization failure, tenant context derived from client input, or inconsistent gateway/backend policy.

## What Constitutes a Finding

- A private API returns sensitive data without required authentication, or a controlled low-privilege identity crosses a defined authorization boundary.
- A restricted operation succeeds without the required role or object ownership check.
- The endpoint's intended privacy is supported by product behavior, schema, UI flow, or access requirements.
- Public health checks, public catalog data, generic API documentation, and empty responses are not automatically vulnerabilities.

## Evidence Requirements

- Sanitized requests for anonymous and authenticated controls.
- Endpoint, method, status, response schema, and one minimal sensitive-field example.
- Clear explanation of the expected permission and the observed missing check.
- For writes, proof using only a disposable synthetic object plus cleanup status.
- Avoid storing raw customer data, full tokens, or secrets in reports.

## Tools

- `curl` or Python `httpx` for replaying captured, authorized requests with controlled inputs; no interactive proxy is required.
- curl/httpie for low-volume endpoint checks.
- jq/Python for schema comparison and response shape analysis.
- OpenAPI parsers for route inventory.
- GraphQL introspection tooling where supported; use the dedicated GraphQL skill for resolver-level checks.

## API Authentication Coverage Matrix

| Surface | Test dimension | Evidence of a defect | Not enough by itself |
|---|---|---|---|
| REST read route | Anonymous vs authenticated | Private fields/records returned anonymously | HTTP 200 with empty JSON |
| REST write route | Required role vs controlled low privilege | Synthetic state change succeeds without required permission | OPTIONS or validation error |
| Object endpoint | Same test object across two controlled identities | Unauthorized identity reads/changes object | Different IDs without known ownership |
| Multi-tenant route | Tenant A identity vs tenant B synthetic object | Cross-tenant object accessible despite policy | Tenant ID echoed in response |
| API versions | Current vs legacy route | Legacy version omits a required control | Deprecated endpoint exists |
| OpenAPI | Declared security vs runtime | Declared private operation is reachable anonymously | Public schema is exposed |
| GraphQL | Resolver/field access under identity matrix | Sensitive resolver/field bypasses expected auth | Introspection enabled alone |
| Gateway/backend | Edge policy vs alternate documented route | Alternate path reaches protected operation | An unverified direct origin |

## Verification and False Positives

- Compare response bodies to an unauthenticated control and a random nonexistent path.
- Confirm the data is genuinely private and not a public fixture, demo record, or cached response.
- Check whether authentication is carried in a cookie or alternate header before concluding it is absent.
- Distinguish missing authentication from IDOR/BOLA and role-based access-control issues.
- Re-test with fresh sessions and inspect cache directives when safe.
- A schema, stack trace, server version, or endpoint name is supporting context, not proof of impact.

## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Continue testing materially distinct, evidence-producing hypotheses while the candidate remains plausible and a meaningful next branch exists. Do not impose a fixed attempt ceiling or count cosmetic retries as new hypotheses. Stop when direct evidence confirms or disproves this hypothesis, no meaningful new branch remains, a valid prerequisite is unavailable, or program/safety rules require stopping; unresolved cases remain inconclusive.

Keep a compact ledger for every attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve raw evidence locally, redact secrets, and avoid collecting unrelated user data.

### Skill-specific hypothesis order

1. Inventory a small set of in-scope API routes from first-party traffic or documentation, then record unauthenticated and authenticated baselines for the same request shape.
2. Prioritize private read-only resources first; compare no credential, expired credential, and a least-privileged test token without widening the route list into guessed endpoints.
3. Test resource ownership and role context separately from authentication: an endpoint may accept anonymous requests yet return only public data, or authenticate correctly while missing object-level authorization.
4. Check alternate API versions, content types, and documented transport patterns only when evidence shows they reach the same handler; vary one factor and preserve a known-public or known-denied control.
5. Confirm exposure with a synthetic canary or a test-owned object's non-public field. Redact all secrets and stop before reading unrelated user records or attempting a write.

### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture, with a relevant control and a clear trust-boundary failure.
- **Likely / needs corroboration:** multiple independent signals support the hypothesis, but the security consequence or root cause is not yet established.
- **Unconfirmed:** evidence is incomplete, ambiguous, cached, or indistinguishable from a generic response.
- **Refuted / false positive:** a relevant negative control, valid authorization explanation, or repeatable contradictory evidence explains the signal. Record what was tested; do not claim that every theoretical variant was exhausted.
- A status code, banner, stack trace, response-length difference, endpoint existence, tool alert, or visible frontend state is never sufficient on its own.

### Stop and cleanup rules

Stop immediately on an out-of-scope boundary, unexpected real-user data, production side effects, rate-limit/availability degradation, credential exposure, or a request to perform a prohibited action. Do not continue merely to spend the budget. Restore disposable test state, revoke temporary sessions/tokens where possible, and record cleanup status.

### Agent handoff record

Return: skill, target asset, in-scope evidence, baseline, candidate hypothesis, attempts used, observed impact, negative controls, confidence/verdict, related-skill signal, sanitized evidence references, and cleanup status. Invoke a chained skill only when the stated signal is independently observed; do not chain from name similarity alone.

## References

- Source merged: [uphiago/recon-skills — recon/api-noauth-hunt/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/api-noauth-hunt/SKILL.md)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP API Security — Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [OWASP API Security — Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)

## Hands-on field pattern: anonymous-to-authenticated differential
Choose a documented/observed endpoint and a synthetic object. First capture the anonymous baseline, then compare the response from an authorized account that should be allowed to access that fixture:

```bash
: "Use a read-only in-scope endpoint; TOKEN is supplied outside shell history"
curl -sS -D anon.headers -o anon.body "$API_URL"
curl -sS -D auth.headers -o auth.body -H "Authorization: Bearer $TOKEN" "$API_URL"
sha256sum anon.body auth.body
```

A body-hash difference is only a triage signal; inspect redacted schemas and protected marker fields. Check alternate API versions and methods only when they are observed and authorized. Chain to `attack-shadow-api` for version drift, `attack-idor-automation` for object-boundary signals, or `attack-bfla` for function-level exposure.

## Targeted quality-loop enrichment (2026-10-19)

### Anonymous-to-authenticated differential
For every candidate API route, compare the same method, content type, object fixture, and request body as anonymous, invalid/expired, low-privilege, and authorized test identities. First classify whether the operation is intended to be public; OpenAPI documentation, a 200 status, OPTIONS, schema visibility, and a login-free health response are not proof of sensitive exposure. For JSON, compare field-level data and object ownership rather than raw response length. For writes, use a disposable fixture and verify server-side state; do not test irreversible actions. Route object-boundary failures to IDOR/BOLA, role-operation failures to BFLA, property differences to API property authorization, and undocumented/version drift to shadow-API review.

## Expanded auth-state matrix and cache controls

Use the same captured read-only request for each identity state. Avoid using a guessed direct origin or changing several headers at once.

```bash
# All URLs and credentials must belong to an explicitly in-scope test.
curl -sS -D anonymous.headers -o anonymous.json "$API_URL"
curl -sS -D invalid.headers -o invalid.json -H 'Authorization: Bearer invalid-test-token' "$API_URL"
curl -sS -D low.headers -o low.json -H "Authorization: Bearer $LOW_ROLE_TOKEN" "$API_URL"
curl -sS -D authorized.headers -o authorized.json -H "Authorization: Bearer $AUTHORIZED_TEST_TOKEN" "$API_URL"
```

Do not compare response hashes alone. Compare field paths and the minimum synthetic marker, and confirm whether the endpoint is meant to be public. Use a test-owned object; never copy production customer responses into the workspace.

```bash
# Optional shape comparison for redacted/synthetic JSON responses.
for f in anonymous.json invalid.json low.json authorized.json; do
  printf '\n### %s\n' "$f"
  jq -r 'paths(scalars) | map(tostring) | join(".")' "$f" | sort -u
done
```

### False-positive branches to rule out

- Cache returns a previously authenticated response to an anonymous request: inspect cache status, Cache-Control, Vary, and repeat with a clean controlled session before assigning root cause.
- API gateway requires a different observed credential mechanism (cookie, API key, mTLS, or signed request): inspect normal client traffic before concluding no auth.
- A 200 response contains only public metadata, empty results, or a generic schema: not sensitive exposure.
- A deprecated/versioned route differs: compare actual policy and output using the same controlled object; route to shadow-API review only when the security control differs.
- An anonymous write returns success but no state change: not confirmed; do not repeat on non-disposable objects.

### Structured evidence additions

Record route_source, intended_visibility, auth_mode, anonymous_result, invalid_credential_result, low_role_result, authorized_control_result, protected_field_paths, synthetic_marker, cache_status, object_owner, state_changed, and cleanup_verified. Every chain to BOLA, BFLA, property authorization, or shadow API must cite the specific observed condition that triggered it.

## Agent-executable CLI tooling, resources, and helper scripts

Agent-invokable CLI tools and local libraries only. Browser interfaces, browser extensions, and interactive intercepting proxies are not required dependencies. Verify tool availability/version, official documentation, license, and target-specific impact before use.

### Recommended tools
- curl/Python requests — unauthenticated baseline checks
- jq — parse structured API responses
- OpenAPI parser/validator such as swagger-cli or Python openapi-spec-validator where schemas exist
- http_response_diff.py — compare anonymous and authenticated controls

### Resources
- https://owasp.org/API-Security/editions/2023/en/0xa7-security-misconfiguration/
- https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- https://github.com/OAI/OpenAPI-Specification
- https://github.com/vavkamil/awesome-bugbounty-tools

Use community lists to discover candidates, then verify their current maintenance and CLI behavior from official sources.

### Helper-script contract
For each route, preserve method, auth context, response classification, harmless test object, and anonymous/authenticated control pair. Do not enumerate or retain exposed personal data.

Keep raw evidence separate from normalized results. Record source, timestamp, tool/version, auth context, control result, errors, confidence, and redaction. Helpers should use explicit input/output paths, structured output, and local fixtures.

### Handoff
Report commands actually run, tool versions, input/output artifact paths, control/variant outcomes, failures, confidence, limitations, and next skill. Missing tools and blocked tests must be explicit.
