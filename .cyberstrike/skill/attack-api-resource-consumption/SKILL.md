---
name: attack-api-resource-consumption
description: "Assess API resource-consumption controls, pagination and query-cost boundaries without generating load or affecting real users."
category: "api-security"
version: "1.0.0"
author: "cyberstrike-official"
tags: [api, resource-consumption, pagination, query-complexity, rate-limit, denial-of-service]
tech_stack: [REST, GraphQL, gRPC, HTTP]
cwe_ids: [CWE-400, CWE-770, CWE-799]
chains_with: [attack-rate-limit-bypass, attack-graphql, attack-business-logic, attack-triage-validation, attack-evidence-hygiene]
prerequisites:
  - "Written permission for the tested endpoint and test window"
  - "A staging/sandbox environment or a low-impact, program-approved read-only operation"
---
# API Resource-Consumption Assessment

## Objective
Identify whether a supported API operation lacks effective bounds on response size, query cost, pagination, file processing, or repeated expensive actions. This skill does not authorize load testing. Use static/configuration review, a sandbox, or the smallest permitted differential that can prove a missing control.

## Testing workflow
1. Inventory expensive operations actually exposed by the app: search/filter, pagination, GraphQL nesting/aliases, report/export generation, image/document conversion, bulk actions, and long-running jobs.
2. Record a normal baseline: response time range, status, result count, documented maximum, rate-limit headers, and any server-provided operation/job identifier.
3. Test one boundary at a time with a synthetic small dataset: default page size, documented maximum, just-out-of-range value, empty/negative/incorrect type, or a duplicate submit. Do not create large datasets or unbounded nested queries.
4. Compare server behavior with the expected contract. A rejected oversized value or documented cap is a protective control; a UI-hidden field does not establish that the server enforces it.
5. Confirm the cost/control gap using provider metrics, staging telemetry, a test job queue, or a small number of approved samples. Never saturate production or benchmark a third-party service.
6. Check how the control is scoped: user, tenant, endpoint, operation class, cost unit, and time window. A per-IP limit alone is not automatically a vulnerability without a plausible consequence.

## Safe boundary matrix
- Pagination: normal page, documented maximum, one value beyond maximum.
- GraphQL/API query cost: a shallow allowed query and one mildly deeper permitted query in a lab; no recursive or high-complexity production requests.
- Export/processing: one synthetic small artifact, then compare with a documented maximum in staging.
- Repeat submission: one controlled duplicate of a reversible test action; verify idempotency and job creation.
- Rate limit: observe documented headers and behavior with test-owned identities; never brute force, rotate proxies, or evade detection.

## What constitutes a finding
A confirmed finding needs a missing/ineffective server-side bound plus measurable, relevant impact or a reproducible path to consume a protected quota/resource under the stated rules. An absent 429, a slow request once, or a high response time without a baseline is only a lead. Infrastructure instability or a prohibited test window means stop and mark inconclusive.

## Chaining
Route per-account throttling to rate-limit review, expensive GraphQL operations to GraphQL query-cost review, repeated workflow actions to business-logic/idempotency review, and output overexposure to property authorization. Each chain link needs its own observed condition. Avoid describing denial-of-service impact if no production-safe evidence exists.

## Evidence, remediation, cleanup
Record endpoint, method, test identity, controlled input boundary, expected maximum, request timestamps, bounded result count/latency, control behavior, and stop/cleanup status. Recommend server-side per-operation quotas, pagination caps, query-cost accounting, execution deadlines, concurrency controls, streaming limits, idempotency, and monitoring. Add a regression test proving oversized/expensive inputs are rejected before costly work begins.

## References
- https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- https://portswigger.net/web-security/api-testing
- https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html
