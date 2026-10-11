---
name: wstg-apit-00
description: "API Testing Overview"
category: api-testing
owasp_id: WSTG-APIT-00
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [api, rest, graphql, soap, grpc, authorization, wstg]
tech_stack: [http, rest, graphql, soap, grpc, json]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-api-misconfig/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/recon/api-noauth-hunt/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-mass-assignment/SKILL.md"
  - "https://owasp.org/www-project-web-security-testing-guide/"
---

# WSTG-APIT-00: API Testing Overview

## Objective

Build a structured, authorization-aware test plan for API surfaces. This overview routes specific hypotheses to the relevant WSTG/API skill rather than duplicating all detailed procedures in one place.

## Scope and safety

Confirm host, API versions, documented methods, allowed test intensity, test accounts, and exclusions. Start with read-only requests and synthetic records. Do not access other users' data, invoke destructive methods, or test production rate limits beyond the approved budget.

## Procedure

1. **Inventory the API surface.** Use in-scope traffic, documentation, OpenAPI/GraphQL schemas, mobile client traffic, and permitted JavaScript analysis. Record host, route, method, content type, auth requirement, expected role, and data sensitivity.
2. **Capture baselines.** For each important operation, save a redacted authenticated request/response and expected business rule. Use controlled accounts with different roles/tenants where permitted.
3. **Check authentication.** Compare anonymous and authenticated behavior on a read-only route. Route unexpected access to the relevant authentication/session skill; do not infer a finding from status code alone.
4. **Check object authorization.** Test ownership and tenant boundaries with test-owned objects; use `attack-idor-automation` and WSTG authorization skills.
5. **Check property authorization and mass assignment.** Compare client-writable properties with server-controlled fields. Use a harmless marker and a disposable object; route to WSTG mass-assignment testing.
6. **Check function-level authorization.** Compare expected roles and permissions for each operation, including alternate methods and API versions. Do not invoke administrative or destructive operations on real data.
7. **Check input validation.** Route SQL/NoSQL injection, file inclusion, SSRF, XXE, SSTI, and request-smuggling hypotheses to their dedicated WSTG/attack skills. Do not combine unrelated payloads in one request.
8. **Check API-specific controls.** Review pagination, filtering, export endpoints, batch requests, GraphQL complexity, content-type parsing, idempotency, CORS, and rate limits where relevant.
9. **Validate impact and stop.** Confirm semantic unauthorized data access or state change with minimal evidence. Stop on real personal data, service instability, or scope ambiguity.

## Related existing skills

- `wstg-apit-01` — API reconnaissance.
- `wstg-apit-02` — BOLA.
- `wstg-apit-99` — GraphQL.
- `wstg-authz-02` and `wstg-authz-03` — authorization bypass and privilege escalation.
- `wstg-inpv-20` — mass assignment.
- `attack-cors`, `attack-graphql`, and `attack-idor-automation` — focused procedures.

## Output contract

Return endpoint inventory, expected auth/role policy, baseline references, hypothesis-to-skill routing, safe validation status, confidence, and redacted evidence.
