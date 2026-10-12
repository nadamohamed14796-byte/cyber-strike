---
name: wstg-apit-00
description: "API Testing Overview"
category: api-testing
owasp_id: WSTG-APIT-00
version: "1.2.0"
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

Build an authorization-aware, evidence-driven test plan for API surfaces. This is an overview and routing skill: inventory endpoints, establish baselines, form one hypothesis at a time, and hand focused testing to the relevant API/WSTG skill rather than duplicating every procedure here.

## Scope and safety gate

Before sending requests:
- Confirm exact in-scope hosts, API versions, methods, account roles, tenants, and permitted request volume.
- Read program exclusions and rules for automated scanning, destructive actions, file uploads, and test data.
- Start with read-only requests and synthetic objects. Use test-owned accounts for authorization comparisons.
- Do not access real third-party records, invoke destructive/admin methods on real data, or test rate limits beyond the approved budget.
- Stop on service instability, unexpected sensitive data, scope ambiguity, or any signal that the test is affecting another user.

## 1. Inventory the API surface

Collect routes from in-scope traffic, published documentation, OpenAPI/Swagger descriptions, GraphQL schema/introspection when allowed, mobile-client traffic, and permitted JavaScript analysis. For each endpoint record:
- Host and API version.
- Method, path template, content type, and expected response type.
- Authentication mechanism and expected role/tenant.
- Object identifiers and sensitive properties.
- Read/write/destructive classification and rate-limit notes.
- Source of discovery and a redacted baseline request.

Do not infer authorization requirements from route names alone. Verify expected policy from documentation, UI behavior, or a known-good request.

## 2. Establish baselines and map identities

1. Capture one valid request/response for each important operation.
2. Where authorized, use two test-owned accounts or tenants with distinguishable synthetic objects.
3. Record expected outcomes for anonymous, ordinary-user, elevated-role, and cross-tenant cases only when those identities are explicitly available to the tester.
4. Preserve request IDs and relevant response headers, but redact cookies, bearer tokens, API keys, personal data, and secret fields.
5. Keep observed behavior, inferred policy, and confirmed security impact clearly separated.

## 3. Authentication and session handling

- Compare anonymous and authenticated behavior on a harmless read-only route.
- Check token expiry, logout, refresh behavior, and credential/session binding using tester-owned sessions.
- Treat a status code alone as insufficient; verify returned data and resulting permissions.
- Route detailed authentication/session issues to the applicable wstg-athn skill.

## 4. Object-level authorization (BOLA/IDOR)

- Create or identify synthetic objects owned by each controlled account.
- Test read and update boundaries using only IDs belonging to the tester's own accounts.
- Compare expected owner access with a controlled unauthorized request and verify whether data or state actually changes.
- Check secondary routes such as export, attachment, history, nested resource, and batch operations only when in scope.
- Route detailed testing to wstg-apit-02, authorization skills, or attack-idor-automation. Stop immediately if a request returns real third-party data.

## 5. Property-level authorization and mass assignment

- Identify server-controlled fields such as role, tenant, owner, approval state, billing status, or entitlement.
- On a disposable object, change one candidate property to a harmless marker and verify persisted state.
- Do not attempt to grant privileged access to a real account or alter real billing/financial state.
- Route confirmed hypotheses to the mass-assignment skill and include a before/after state diff.

## 6. Function-level authorization

- Build a role-to-operation matrix from documented expectations.
- Compare roles only using test accounts and harmless read-only or reversible operations.
- Include alternate HTTP methods, API versions, and secondary routes when permitted.
- Never invoke destructive administrative actions against real records merely to prove a missing role check.

## 7. Input parsing and validation

- Test one input class at a time and use benign boundary values.
- Check required fields, type coercion, enum validation, content-type handling, duplicate keys, pagination, sorting, filtering, and error consistency.
- Route specialized injection hypotheses (SQL/NoSQL injection, SSRF, XXE, SSTI, path traversal, request smuggling) to their dedicated skills. Do not combine unrelated payload families into one request.
- Avoid oversized bodies, resource-exhaustion payloads, or exploit chains without explicit approval.

## 8. API-specific controls

- Pagination/filtering: verify tenant and authorization filters apply on every page and export path.
- Batching: verify each item is independently authorized; use only synthetic records and small batches.
- GraphQL: review field authorization, introspection policy, depth/complexity controls, and resolver-level object checks without sending expensive queries.
- CORS: compare allowed origins and credential behavior against documented requirements; a permissive header alone is not automatically exploitable.
- Idempotency: use one controlled retry to check duplicate state changes where permitted.
- Rate limits: inspect headers and documented policy; do not flood endpoints or continue after throttling.
- Errors: check whether stack traces, internal IDs, secrets, or personal data are exposed; retain only redacted evidence.
- Version drift: compare authorization and validation behavior across versions only when each version is in scope.

## 9. Validate impact and stop conditions

A finding should demonstrate a violated security invariant and a meaningful effect. Verify final state with an independent read-only request when possible. Stop immediately if the result exposes another user's data, changes an unintended record, triggers a real-world side effect, or destabilizes the service. Do not broaden the test after a clear proof.

## Related skills

Use the repository's existing focused skills when present:
- wstg-apit-01 — API reconnaissance.
- wstg-apit-02 — object-level authorization / BOLA.
- wstg-apit-99 — GraphQL API testing.
- wstg-authz-02 and wstg-authz-03 — authorization bypass and privilege escalation.
- wstg-inpv-20 — mass assignment.
- attack-cors, attack-graphql, and attack-idor-automation — focused test procedures.

If a referenced skill is absent from the current catalog, retain the hypothesis in the report and use the nearest existing skill rather than inventing a path.

## Output contract

Return endpoint_inventory with source, method, auth/role expectation, and sensitivity; baseline_refs with secrets and personal data redacted; hypothesis_to_skill routing and rationale; validation_status (untested, blocked, not reproducible, or confirmed); observed_effect, impact, confidence, stop_reason, and cleanup_status.

## Remediation guidance

Centralize authorization checks at object, property, and function level; validate inputs server-side; scope queries by tenant and owner; enforce safe pagination and request limits; use consistent error handling; and add regression tests for each confirmed invariant.
