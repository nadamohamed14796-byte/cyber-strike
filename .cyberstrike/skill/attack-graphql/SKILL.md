---
name: attack-graphql
description: "Assess GraphQL schema exposure, object and field authorization, mutation controls, batching, and query resource limits"
category: "web-application"
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [graphql, api, authorization, introspection, query-cost]
tech_stack: [http, graphql, json, browser]
cwe_ids: [CWE-200, CWE-284, CWE-770]
chains_with: [attack-idor-automation, attack-cors, attack-race-condition, attack-triage-validation]
prerequisites:
  - "Authorized GraphQL endpoint and permitted operation types"
  - "Controlled accounts and a low-impact query plan"
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-graphql/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
  - "https://portswigger.net/web-security/graphql"
---

# GraphQL Security Assessment

## Objective

Find authorization, validation, information exposure, and resource-control defects in GraphQL APIs. Schema visibility is a discovery signal; a reportable issue requires a policy violation or meaningful demonstrated impact.

## Scope and safety

Confirm the endpoint, permitted query/mutation/subscription behavior, rate limits, and test account. Begin with low-cost read-only operations. Do not invoke destructive mutations, enumerate real user records, or run resource-exhaustion tests against production. Any load/complexity testing must stay within an explicitly approved low threshold.

## Procedure

### 1. Discover and fingerprint

Look for GraphQL endpoints from in-scope browser traffic, application code, API documentation, and known paths. Confirm protocol and content type rather than assuming every JSON endpoint is GraphQL. Check whether the application uses one endpoint for multiple roles or versions.

### 2. Inspect schema safely

Where permitted, test introspection with a minimal query and record whether type and field metadata are exposed. If introspection is disabled, use documented schema, client operations, and validation errors as discovery aids. Do not treat enabled introspection by itself as a vulnerability; determine whether sensitive operations or data are exposed to an unauthorized principal.

### 3. Build an operation inventory

For each query, mutation, and subscription, record:
- operation and arguments;
- object identifiers and nested relationships;
- expected roles and tenant boundary;
- read/write effect and sensitivity;
- pagination, batching, and cost controls;
- corresponding REST or alternate API operation, if one exists.

### 4. Validate object- and field-level authorization

Use two controlled accounts or tenants only when explicitly allowed. Establish a baseline for an object owned by account A, then compare a single identifier or nested reference with account B. Check both object-level authorization and field-level authorization. Treat `node`, `nodes`, global IDs, nested resolvers, bulk inputs, and indirect references as leads—not proof. Verify semantic data access or state change, not merely a successful HTTP status.

### 5. Validate mutation controls

For controlled test objects, check whether mutations enforce role, ownership, state-transition, and tenant constraints. Compare mutation behavior with the corresponding REST API if both exist. Pay special attention to stale membership or role state that differs between APIs. Do not delete, transfer, purchase, invite real users, or modify production privileges as proof.

### 6. Check alternate authorization paths

Where observed in the schema or client, compare aliases, fragments, nested fields, batch requests, persisted queries, subscriptions, and alternate API versions. Keep requests small. Check whether rate limits apply consistently to aliases/batches, but do not deliberately overload the service.

### 7. Review complexity and resource limits safely

Look for depth, pagination, cost, alias, batch, and recursion limits. Use a small, bounded query in a permitted environment and observe server-side rejection or predictable cost behavior. Do not attempt to crash, saturate, or degrade a live service. A timeout alone is not proof of a vulnerability.

### 8. Validate cross-API state and race hypotheses

If the same object is managed by GraphQL and REST, compare authorization and state consistency. Race-condition claims belong in `attack-race-condition`; only test with disposable objects and explicit permission.

## Common false positives

- Introspection enabled without sensitive impact.
- A field suggestion or schema name that is not actually accessible.
- A 200 response containing errors or null data.
- A role-specific field that is intentionally public.
- Query timeout caused by network conditions rather than server-side cost.
- A mutation rejected by business rules but misread as successful.

## Evidence and output

Record the operation, redacted variables, caller role, expected authorization rule, baseline and test responses, data sensitivity, observed state, and minimal reproducible proof. Return `endpoint`, `operation_type`, `operation_name`, `auth_context`, `object_boundary`, `field_boundary`, `mutation_effect`, `cost_controls`, `impact`, `confidence`, and evidence references.

## Related skills

- `attack-idor-automation` — object ownership and tenant isolation.
- `attack-cors` — browser cross-origin response exposure.
- `attack-race-condition` — concurrent state transitions.
- `attack-triage-validation` — false-positive and impact review.
