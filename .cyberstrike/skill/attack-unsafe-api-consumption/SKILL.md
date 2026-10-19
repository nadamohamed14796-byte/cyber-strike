---
name: attack-unsafe-api-consumption
description: "Assess unsafe trust of third-party APIs, webhook payloads and downstream responses at application integration boundaries."
category: "api-security"
version: "1.0.0"
author: "cyberstrike-official"
tags: [api, third-party, webhook, supply-chain, response-validation, ssrf]
tech_stack: [REST, webhooks, JSON, HTTP]
cwe_ids: [CWE-20, CWE-345, CWE-918]
chains_with: [attack-ssrf, attack-deserialization, attack-api-property-authorization, attack-source-leak, attack-triage-validation]
prerequisites:
  - "An observable integration or authorized staging fixture for the external API/webhook"
  - "A documented expected schema, signature policy, or trust boundary"
---
# Unsafe API Consumption Assessment

## Objective
Check whether the application trusts a downstream API response, webhook, callback, or partner-controlled field without validating origin, integrity, schema, size, or semantic constraints. Focus on the consuming application's trust boundary; an external API being reachable is not a vulnerability by itself.

## Workflow
1. Inventory the integration source, authentication/signature method, callback route, expected schema, allowed hosts, redirect behavior, retry policy, and where the response is stored or used.
2. Capture one valid integration event in a test tenant and one invalid signature/schema fixture in an approved staging or vendor test mode.
3. Change one property at a time: signature validity, issuer/source binding, unexpected field/type, missing required field, duplicate event/idempotency key, response status/content type, or redirect/URL field.
4. Verify whether the consumer rejects invalid input before persistence or privileged action. Compare authoritative state and logs, not just a 200 response to the webhook.
5. Trace downstream use of any accepted field: authorization decision, template/output render, query construction, file path, URL fetch, deserializer, or workflow state. Use synthetic markers and source/code review where possible.
6. Stop before triggering financial, account, deployment, or irreversible business actions; use disposable fixtures and vendor test credentials only.

## Safe validation matrix
- Valid signed event versus invalid/missing signature.
- Expected schema/type versus a harmless unexpected property.
- Duplicate event with the same idempotency key versus a new test event.
- Approved URL/host versus a controlled disallowed test host in staging.
- Normal downstream response versus a synthetic malformed response from a controlled stub.

Never forge callbacks to a production business operation or submit real vendor credentials/secret values to third-party services.

## What constitutes a finding
Confirmed only when an unauthorized or untrusted response is accepted across a defined trust boundary and causes a protected state, data, or processing outcome. Missing schema validation or overly broad allowlists may be a security design issue, but severity must reflect the reachable consequence. Invalid requests accepted without any meaningful effect remain leads.

## Chaining
- SSRF: only when a URL from the external response is fetched server-side and the controlled destination receives the request.
- Deserialization: only when downstream data is interpreted through a vulnerable serialized format.
- Property authorization: only when trusted partner fields leak or alter protected API model properties.
- Source/CI review: when integration credentials or workflow configuration are exposed; never use leaked credentials to prove impact.

## Evidence and remediation
Retain the sanitized fixture/event ID, signature/schema result, consumer response, authoritative state before/after, trust source, and cleanup status. Recommend signature verification with replay protection, strict schema and semantic validation, allowlisted destinations, redirect/size/time limits, idempotency, isolated parsing, and explicit authorization checks after integration data is consumed.

## References
- https://owasp.org/API-Security/editions/2023/en/0xa10-unsafe-consumption-of-apis/
- https://owasp.org/www-project-web-security-testing-guide/


## Integration contract and trust-boundary ledger

For each integration, record the producer, consumer, authentication principal, signature/transport protection, schema version, idempotency contract, retry behavior, and final side effect. Keep transport authentication, payload integrity, schema validation, and business authorization as separate controls.

| Check | Controlled comparison | Evidence required |
|---|---|---|
| Webhook signature | Valid test signature vs invalid/missing signature | Consumer decision and unchanged authoritative state on invalid input |
| Freshness/replay | Fresh test event vs same event ID/timestamp replay | Duplicate is rejected or safely deduplicated according to contract |
| Source binding | Correct test tenant/provider vs mismatched controlled issuer/tenant | Consumer binds event to the intended account/tenant |
| Schema | Valid fixture vs one unknown/wrong-type field | Strict handling before persistence or action |
| Semantics | In-range synthetic value vs invalid business-state transition | Server enforces invariant independent of producer claims |
| Response handling | Expected status/content type/schema vs malformed response from a controlled stub | Consumer fails safely without exposing raw downstream body |
| Redirect/destination | Expected provider endpoint vs controlled disallowed destination in staging | Destination allowlist and redirect policy enforced |
| Size/timeouts | Small normal response vs bounded staging fixture | Explicit response size and timeout handling without production load |
| Retry/partial failure | Controlled transient failure followed by retry | Idempotency and compensation prevent duplicate side effects |
| Error handling | Downstream error with sensitive synthetic marker | Client-facing response/logs do not leak secrets or private payloads |

## Source-to-effect trace

Follow one field from the external response or webhook through parsing, validation, persistence, and use. Mark whether each stage is verified by code, approved logs, or behavior. A response accepted by the parser is not necessarily trusted by the business logic; conversely, an invalid field that is stored but never used may have a different risk from a field that controls identity, URL, permissions, or workflow state.

## Evidence record

Persist integration_name, provider_identity, tenant_binding, signature_policy, schema_version, event_id_fingerprint, freshness_result, idempotency_key_fingerprint, field_path, validation_result, downstream_use, state_before_after, negative_control, log_redaction, and cleanup_status. Never retain webhook signing secrets, full authorization headers, or production payloads in the global knowledge store.

## Regression handoff

Add tests for invalid signature, replay, wrong tenant/provider, unknown field, wrong type, missing required field, malformed downstream response, disallowed redirect, and retry after partial failure. Keep tests synthetic and verify authoritative state rather than the HTTP acknowledgement alone.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Use Burp Repeater/Comparer to trace how the application consumes third-party API data, jq/schema validators for local response samples, and an authorized mock/staging upstream to reproduce trust-boundary issues. Never assume a partner API response is safe because it is syntactically valid JSON.

### Installation and setup
- [Burp Suite](https://portswigger.net/burp) — official installation.
- jq on Kali/Debian: `sudo apt update && sudo apt install jq`.
- For an owned service, use its existing OpenAPI/JSON Schema validator or the official library for its language; pin dependencies and test using sanitized synthetic fixtures.
Do not alter third-party services, replay other users' webhooks, or inject real downstream actions during a production test.

### Primary resources
- [OWASP API Security Top 10 — API10: Unsafe Consumption of APIs](https://owasp.org/API-Security/editions/2023/en/0xa10-unsafe-consumption-of-apis/) — risk description.
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) — validation boundaries.
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) — if upstream URLs are controllable.

### Reusable helper
`python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt` compares two already-collected sanitized responses offline.

### Result handling
Trace the untrusted upstream field to the security-sensitive sink, record the downstream effect using synthetic data, and keep partner keys and customer payloads out of evidence.
