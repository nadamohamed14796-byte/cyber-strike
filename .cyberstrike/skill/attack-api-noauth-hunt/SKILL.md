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

- Burp Suite or mitmproxy for replaying controlled requests.
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


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Treat the attempt budget as a ceiling for evidence-producing hypotheses, not a quota for payload variants. When a candidate remains plausible, branch to the next independent hypothesis up to a maximum of 20; stop earlier when evidence is decisive, the remaining hypotheses are not relevant, or safety/scope limits apply. Never count the same request with cosmetic encoding changes as separate attempts.

Keep a compact ledger for every attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve raw evidence locally, redact secrets, and avoid collecting unrelated user data.

### Skill-specific hypothesis order

Use the matrix and acceptance criteria already defined in this skill to choose the next distinct, low-impact hypothesis; do not repeat equivalent probes.

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
