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
