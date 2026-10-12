---
name: attack-graphql
description: "Test GraphQL schema exposure, object-level authorization, batching, and query-cost controls with bounded requests"
category: "web-application"
version: "1.1.0"
author: "cyberstrike-official"
tags:
  - graphql
  - api
  - web
  - dos
  - attack
tech_stack:
  - web
  - graphql
cwe_ids:
  - CWE-200
  - CWE-284
  - CWE-770
chains_with:
  - attack-idor-automation
prerequisites: []
severity_boost:
  attack-idor-automation: "GraphQL introspection reveals IDOR-vulnerable queries"
---

# GraphQL Vulnerability Testing

## Objective

Exploit GraphQL-specific vulnerabilities including schema exposure, query complexity abuse, and authorization bypass.

## Testing Methodology

### Phase 1: Automated Testing

```bash
# Full GraphQL test suite
attack_script graphql_tester "https://TARGET/graphql" \
  -H "Authorization:Bearer TOKEN" \
  --json-output

# Custom depth/batch
attack_script graphql_tester "https://TARGET/graphql" \
  --depth 15 --batch-count 100
```

### Phase 2: Introspection Query

```bash
# Full schema extraction
curl --max-time 15 --connect-timeout 5 -s -X POST https://TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } mutationType { fields { name args { name type { name } } } } queryType { fields { name } } } }"}'
```

If introspection is enabled, map all types, queries, mutations, and subscriptions.

### Phase 3: Authorization Bypass

```graphql
# Access admin queries without auth
{ adminUsers { id email role } }

# Mutation without auth
mutation { deleteUser(id: "123") { success } }

# Access other user's data
{ user(id: "OTHER_USER_ID") { email ssn creditCard } }
```

### Phase 4: Complexity / DoS

```graphql
# Deeply nested query
{ users { posts { comments { author { posts { comments { author { id } } } } } } } }

# Alias multiplication
{ a1: __typename a2: __typename ... a100: __typename }

# Batch queries (array)
[{"query":"{ __typename }"}, {"query":"{ __typename }"}, ... x50]
```

### Phase 5: Directive Abuse

```graphql
# Skip/include directive for info leakage
{ user(id: "1") { name email @skip(if: false) secretField @include(if: true) } }

# Field suggestions (error-based enum)
{ user { nonExistentField } }
# Error may suggest: "Did you mean: password, secret_key?"
```

## What Constitutes a Finding

| Finding | Severity |
|---------|----------|
| Introspection enabled (schema exposed) | Medium (P3) |
| Admin mutations accessible without auth | Critical (P1) |
| Other user data accessible (IDOR) | High (P2) |
| DoS via complexity (server timeout/crash) | Medium (P3) |
| Batch queries bypass rate limiting | Medium (P3) |

## Evidence Requirements

- GraphQL endpoint URL
- Query/mutation sent
- Response showing unauthorized data
- For introspection: schema dump (types, mutations, queries)
- For DoS: response timing proving server overload

## Tools

- `attack_script graphql_tester` — automated introspection + DoS + batch testing

## Coverage Matrix: Object, Field, Mutation, and Batching

Test GraphQL authorization at more than one layer. Use two controlled accounts with different roles and compare: direct object lookup (`node`/global ID where supported), nested object relationships, sensitive fields, and mutations that change a test-owned record.

- Compare GraphQL operations with the equivalent REST action where one exists. If REST denies an action but a GraphQL mutation permits it, preserve both sanitized request/response pairs.
- Try a small number of aliases in one request to determine whether throttling is applied per HTTP request or per operation. Do not scale into OTP guessing, broad enumeration, or resource exhaustion; stop once the enforcement gap is demonstrated.
- Introspection being enabled is a discovery signal, not an impact claim. Likewise, a large query, deep nesting, or a `200 OK` response is not proof of denial-of-service or authorization bypass.
- For query-cost/depth checks, begin with a baseline and increase one dimension at a time using bounded requests. Record latency and response shape; stop on degradation and do not perform load testing unless explicitly allowed.

## Verification and False Positives

- Introspection being enabled is not automatically a vulnerability. Determine whether the schema exposes sensitive implementation details that create a concrete risk under the program's policy.
- Test object- and field-level authorization with two accounts you control. Compare the same query using each account and verify whether unauthorized fields or objects are returned; do not enumerate real users' identifiers.
- Test mutations with a harmless record owned by your test account. A successful HTTP status does not prove the mutation executed; inspect the GraphQL `errors` array and the resulting test record.
- Probe depth, aliases, batching, and complexity with small, bounded requests first. Stop if latency, errors, or resource use rises materially; do not perform load or denial-of-service testing unless explicitly permitted.
- GraphQL commonly returns HTTP 200 for both successful and failed operations. Validate the JSON `data` and `errors` fields, returned object ownership, and actual state change.
- Use request timeouts and low request rates. Preserve sanitized query/response pairs and the account role used for each test.
- [uphiago/recon-skills — GraphQL hunting](https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-graphql/SKILL.md) (external research reference; not a local Cyber Strike skill path).
- [elementalsouls/Claude-BugHunter — GraphQL hunting](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-graphql/SKILL.md) (external research reference; not a local Cyber Strike skill path).

## GraphQL Coverage and Triage Matrix

Track coverage by schema surface rather than by payload count:

| Surface | Compare | Validate |
|---|---|---|
| Queries | same object as anonymous, owner, and other test user | object-level authorization |
| Nested fields | parent allowed but sensitive child field requested | field-level authorization |
| Mutations | valid owner vs non-owner; allowed vs disallowed state transition | authorization and server-side invariants |
| Node/global IDs | IDs belonging to two controlled accounts | whether changing an identifier crosses ownership |
| Aliases/batching | small bounded batch vs single operation | whether controls are applied per operation and per object |
| Introspection/errors | enabled/disabled behavior and sanitized errors | information disclosure with actionable impact |
| Pagination/filtering | boundary values and alternate filters | tenant isolation and unintended data expansion |

Use only controlled accounts and synthetic records. Keep batch size small and stop if latency, error rate, or resource consumption rises unexpectedly. Do not use introspection output alone as proof of a vulnerability.

A strong report contains the operation, variables, role/tenant context, expected authorization rule, observed result, and a redacted before/after response showing the exact unauthorized field or state change.


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Treat the attempt budget as a ceiling for independent, evidence-producing hypotheses, not a payload quota. If the candidate remains plausible, follow the next signal-led branch up to 20 distinct hypotheses; stop sooner when impact is decisive, no relevant branch remains, or scope/safety limits apply. Cosmetic encodings of the same request do not count as separate attempts.

Maintain an attempt ledger: hypothesis, single changed variable, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer controlled identities, synthetic resources and paired requests. Preserve sanitized evidence and minimize data collected.

### Skill-specific hypothesis order

1. Identify the GraphQL endpoint and capture one valid query, one invalid-field query, and one unauthenticated response; bound query size/depth and preserve request IDs.
2. Use schema introspection only within program rules and only to map attack surface; check field-level auth, node/global-ID access, aliases, batching, and nested relationships with test-owned records.
3. Change one variable per request: principal, object ID, requested property, operation type, or API version. Compare behavior to the schema's expected access policy rather than relying on hidden UI controls.
4. Test mutations only on disposable records with reversible, nonfinancial effects; avoid expensive recursive queries or broad enumeration that could affect availability.
5. Confirm unauthorized data/action using a canary and compare with a denied principal/control. Report field/path, role, object ownership, and actual impact; introspection exposure alone is context, not proof.


### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture and a relevant control.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause remains uncertain.
- **Unconfirmed:** response is ambiguous, cached, generic, or not linked to a security boundary.
- **Refuted / false positive:** an applicable negative control or valid policy explanation accounts for the signal. Record the attempt ledger rather than claiming every theoretical variant was exhausted.
- A 2xx status, error difference, header, schema/documentation exposure, scanner alert, or UI-only state is not proof by itself.

### Stop, cleanup, and handoff

Stop on scope ambiguity, unexpected real-user data, unexpected production state changes, service degradation, credential exposure, or a prohibited action. Restore disposable state and revoke temporary tokens/sessions where possible. Handoff target and scope proof, baseline, hypothesis, attempts used, impact, negative controls, verdict/confidence, sanitized evidence pointers, linked-skill signal, and cleanup status. Invoke a related skill only when its triggering signal is observed.

## References

- [PortSwigger: GraphQL](https://portswigger.net/web-security/graphql)
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [HackerOne: GraphQL Bugs](https://www.hackerone.com/vulnerability-management/graphql-security-guide)
