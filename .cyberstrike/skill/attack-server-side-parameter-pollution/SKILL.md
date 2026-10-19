---
name: attack-server-side-parameter-pollution
description: "Assess ambiguity in how backend routers and downstream services parse duplicate, encoded or nested parameters using synthetic test inputs."
category: "api-security"
version: "1.0.0"
author: "cyberstrike-official"
tags: [api, parameter-pollution, parser-differential, routing, request-validation]
tech_stack: [HTTP, REST, Node.js, Java, reverse-proxy]
cwe_ids: [CWE-20, CWE-444]
chains_with: [attack-api-noauth-hunt, attack-graphql, attack-401-403-bypass, attack-request-smuggling, attack-triage-validation]
prerequisites:
  - "An observed endpoint that consumes or forwards user-controlled parameters"
  - "A harmless synthetic object/value pair and known-good baseline"
---
# Server-Side Parameter Pollution Assessment

## Objective
Determine whether different layers interpret a request's parameters differently, allowing an input to change the downstream operation or authorization context. This is distinct from SQL injection and HTTP request smuggling: the core signal is inconsistent parameter parsing or construction between application components.

## Workflow
1. Identify a route that forwards parameters to an internal API, search service, identity provider, or downstream controller. Establish that forwarding from observed behavior, source review, or permitted trace evidence.
2. Capture a normal request and a known-invalid control with tester-owned identifiers. Record which parameters are accepted, duplicated, decoded, normalized, or reserialized.
3. Change one parsing dimension at a time: duplicate key order, array/object shape, encoded delimiter, empty value, conflicting query/body value, or case/whitespace where the contract allows it.
4. Compare the application result with the documented API contract and, where safely available, a staging trace of the downstream request. Do not probe undocumented internal endpoints or attempt to escape into adjacent APIs.
5. Confirm only when the parser differential changes a protected object, function, tenant, or data boundary and a controlled negative control shows the intended policy.
6. Stop if testing could trigger a privileged operation, access non-test data, desynchronize a shared connection, or materially affect service availability.

## Controlled request pair
Use a synthetic ID such as item-A and item-B that both belong to the test account. Submit the documented single-value form, then a duplicate-parameter variant with the same two test-owned values. Compare the resolved object and downstream audit/request record if available. Do not use another tenant's real ID or chain to unrelated injection payloads.

## Findings and false positives
A framework choosing the first or last duplicate value is not by itself a vulnerability; it matters only when the security policy and downstream interpretation diverge. A 400, 404, or different response size is only a signal. Confirm the exact parser/layer responsible and the security consequence. If the application consistently rejects ambiguity or normalizes it before authorization, record the control as effective.

## Chaining
- API no-auth/BOLA: only when the downstream resolution crosses object or authentication boundaries.
- GraphQL: only when a gateway transforms user input into GraphQL and the field/operation boundary is affected.
- 401/403 analysis: only when parsing changes the authorization decision for an observed protected route.
- Request smuggling: only if separate raw HTTP message-framing evidence establishes cross-layer request-boundary disagreement.

## Evidence and remediation
Preserve the canonical request, one-variable variant, response/state comparison, role context, and sanitized downstream trace. Recommend rejecting duplicate security-sensitive parameters, parsing once into a typed schema, canonicalizing before authorization, and passing structured arguments rather than concatenating downstream query strings. Add regression cases for order, duplication, encoding, and conflicting parameter sources.

## References
- https://portswigger.net/web-security/api-testing/server-side-parameter-pollution
- https://owasp.org/API-Security/editions/2023/en/0x00-header/
