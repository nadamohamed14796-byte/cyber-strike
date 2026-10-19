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


## Targeted quality-loop enrichment (2026-10-19)

### GraphQL depth: operation, object, property, and cost
Keep a canonical inventory of query/mutation/subscription operation, variables, aliases, fragments, nested fields, principal, and object fixture. Compare the same operation under anonymous and test roles, then inspect whether every returned sensitive field and every mutation target has its own authorization decision. Introspection visibility is not proof of exposure; a field may be documented but intentionally public. Use only small, benign queries and measure cost through response/latency metadata rather than load testing production. Route cross-owner object access to IDOR/BOLA, unauthorized property selection to API property authorization, and unbounded query cost to API resource-consumption review.


## Operation-shape matrix: aliases, fragments, batching, subscriptions

| Feature | Safe comparison | Security question |
|---|---|---|
| Aliases | Two small, independent aliases for the same benign field in a test environment | Does authorization apply per resolver/field, and is cost accounted for consistently? |
| Fragments | Reuse an observed fragment under two controlled roles | Does field authorization follow the resolved field rather than only the top-level query? |
| Global IDs / nodes | Query a test-owned ID, then a second controlled fixture's ID as the lower-privilege account | Does the resolver verify object ownership/tenant independently? |
| Batch operations | Small batch containing only known test fixtures | Is each operation/object authorized independently, or does one permitted item mask a denied one? |
| Persisted queries | Compare registered/known query with an unregistered harmless query where the client uses persisted operations | Are authorization and cost controls applied after query lookup as well as during registration? |
| Subscriptions | Use a test-only channel with synthetic events and explicitly approved subscription testing | Are subscribe authorization and per-event authorization both enforced after role/tenant changes? |
| Nested resolver | Query one allowed parent and one controlled child reference | Can a parent permission accidentally grant access to an unauthorized child? |

Do not infer an exploitable cost bypass from alias support alone. Keep each query small, and stop if the service shows instability or a program threshold is reached.

### Minimal response normalization

Save the GraphQL request as a redacted artifact and record operationName, query hash, variable keys (not sensitive values), errors[].extensions.code, data field paths, and test principal. A GraphQL HTTP 200 often carries application errors; inspect both errors and data. Do not store full returned records if a synthetic marker or field path is sufficient.

### Chain routing

- Node/global-ID resolver crosses ownership boundary → IDOR/BOLA.
- Query exposes restricted fields on an otherwise permitted object → API property authorization.
- Mutation can invoke a restricted function regardless of object owner → BFLA.
- Aliases/batches cause excessive server cost → API resource-consumption, with a safe staging cost trace.
- Subscription continues delivering private events after access is revoked → session/authorization review using synthetic events only.
