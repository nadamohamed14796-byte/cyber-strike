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


## Per-operation cost model and test ledger

For each operation, record the resource consumed and the control expected to bound it. Do not use a single generic “rate limit” label for unrelated controls.

| Resource | Useful signal | Safe confirmation path |
|---|---|---|
| Response size | item count, serialized bytes, pagination metadata | Synthetic dataset and documented page boundary |
| Query execution | query complexity/depth/aliases, DB plan or staging trace | Approved sandbox telemetry; compare a normal query with one small, valid complexity increase |
| Async queue | accepted jobs, duplicate job IDs, queue age, worker duration | One disposable job and an authoritative job-state read |
| File/image/document processing | input size, decoded dimensions/pages, worker timeout | Benign small fixtures and code/config review; no bombs or oversized production files |
| Per-user/tenant quota | quota headers/state and principal binding | Two controlled test identities; prove quota isolation or cross-tenant accounting safely |
| Expensive workflow | cost per operation, retries, idempotency | One controlled duplicate/retry and persisted side-effect check |

### Minimal response inventory

For a saved API response, extract metadata without dumping response values:

```bash
jq '{count:(.items|length), nextCursor:(.nextCursor != null), hasMore, total}' response.json
```

Adapt field names to the actual response schema. A wrong jq field or absent property is not evidence of an API flaw. Keep response samples small and synthetic.

### Differential test record

Persist operation_class, resource_type, normal_input, documented_bound, test_input, server_enforced_bound, request_count, response_bytes, item_count, elapsed_range, test_identity, tenant, queue_or_job_id, control_result, telemetry_source, and stop_reason. Keep raw timing as supporting evidence, not a standalone verdict.

### Chaining rules

- Per-identity quota bypass → rate-limit review only if the same actor can exceed the documented policy in a controlled test.
- Query depth/alias complexity → GraphQL only when the expensive operation is a GraphQL query or resolver path.
- Repeated job creation → business logic/idempotency only when duplicate side effects persist.
- Excessive fields returned at normal cost → property authorization, not resource consumption.
- If impact cannot be established without stress/load testing that the program does not permit, record the control gap and mark impact unconfirmed; do not perform the prohibited test.


## Practical tooling, references, and helper scripts (2026-10-19)

### Tools that fit this skill
- Burp Proxy/Repeater/Comparer, the observed client request, an available OpenAPI schema or GraphQL operation document, and jq for local JSON comparison. Prefer two controlled principals and a harmless fixture; do not load-test or send undocumented destructive mutations.
- Before treating an optional CLI command as runnable, verify its presence and version locally. Do not claim integrations or tools that the current runtime has not exposed.
- Start with passive/read-only observation. Only active tests against authorized assets; state-changing tests require an approved disposable fixture and explicit program permission.

### Primary resources
- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x00-header/) — API risk taxonomy.
- [PortSwigger API testing](https://portswigger.net/web-security/api-testing) — hands-on test reasoning.
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) — authorization design.

### Small, reusable helper
    python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt
This compares local artifacts offline and heuristically redacts common secrets before displaying differences. It sends no requests and does not prove complete sanitization.

### Evidence and hand-off
- Save a sanitized artifact reference and the exact claim it supports. Keep credentials, full cookies, reset links, private user data, and raw secrets out of notes, global research storage, and commits.
- Mark the result confirmed, disproven, or still a hypothesis. If the key check cannot be run safely or the expected control is missing, record the gap rather than inventing a conclusion.

Validation note: use a known-good baseline and a control case, change one meaningful variable at a time, record the alternative explanation, and route a lead onward only when the evidence meets this skill's proof criteria.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Use Burp Repeater and application telemetry to check per-user/resource limits safely. A load-testing tool is usually unnecessary for a bug bounty proof; if required, k6 is for an explicitly approved staging/lab capacity test, not for stress-testing public production systems.

### Installation and setup
- [Burp Suite](https://portswigger.net/burp) — official install.
- [k6 installation](https://grafana.com/docs/k6/latest/set-up/install-k6/) — official installer and supported environments.
- jq on Kali/Debian: sudo apt update && sudo apt install jq.
Do not run load tests, large batches, or resource-exhaustion payloads against a live target unless the written program rules explicitly authorize them. Prefer a minimal test of a disposable resource and stop on service degradation or rate limiting.

### Primary resources
- [OWASP API Security Top 10 — API4](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/) — risk and controls.
- [Grafana k6 docs](https://grafana.com/docs/k6/latest/) — test design and thresholds.
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) — defensive context.

### Reusable helper
Run python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt to compare saved responses offline.

### Result handling
Record the documented limit, safe request count/spacing, resource ownership, observed control behavior, and stop condition. Don't claim unbounded impact from a single slow response.

## Agent-executable CLI tooling, resources, and helper scripts

Use CLI tools and local scripts directly. Browser UI, browser extensions, and interactive intercepting proxies are not dependencies. Check availability/version and official documentation before use; active tests require explicit authorization and low-impact settings.

### Recommended tools
- OpenAPI parser — inventory request and response schemas
- Python requests/httpx — low-volume controlled usage tests
- jq — inspect response metadata and server limits
- A local load-test harness only for staging or explicit agreed test windows

### Resources
- https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- https://github.com/OAI/OpenAPI-Specification
- https://github.com/vavkamil/awesome-bugbounty-tools

Treat community lists as discovery aids and verify current maintenance and behavior from official sources.

### Helper-script contract
Model normal request cost and rate policy before testing. Use test-owned resources and an agreed low request budget; record limit headers, response behavior, cost signals, and server-side impact. Never stress production systems.

Preserve raw evidence separately from normalized results; record tool/version, timestamps, identity/context, errors, confidence, redaction, and output paths. Use structured output and deterministic local fixtures.

### Handoff
Return actual command/version, input/output paths, request counts, controls, errors, confidence, limitations, and next skill. Blocked or unexecuted tests must remain inconclusive.
