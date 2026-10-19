---
name: attack-api-property-authorization
description: "Assess API object-property authorization for excessive read exposure and unauthorized writes using controlled identities and synthetic fixtures."
category: "api-security"
version: "1.0.0"
author: "cyberstrike-official"
tags: [api, property-authorization, excessive-data-exposure, mass-assignment, graphql, multi-tenant]
tech_stack: [REST, GraphQL, gRPC, JSON]
cwe_ids: [CWE-200, CWE-213, CWE-915]
chains_with: [attack-idor-automation, attack-mass-assignment, attack-bfla, attack-graphql, attack-triage-validation, attack-evidence-hygiene]
prerequisites:
  - "An in-scope API operation and a tester-owned object or synthetic fixture"
  - "At least one permitted identity for the relevant role/tenant comparison"
---
# API Property-Level Authorization Assessment

## Objective
Determine whether an API returns or accepts a property that the current principal is not allowed to read or modify. Keep read-side excessive data exposure separate from write-side mass assignment: they can share a model/schema weakness, but the proof and impact differ.

## Testing workflow
1. Inventory response/request schemas from OpenAPI, GraphQL types, observed traffic, and first-party client code. Do not assume an undocumented field is sensitive by its name alone.
2. Classify fields as public/user-editable, internal, tenant-bound, security-sensitive, derived, or unknown. Record the expected policy and source of that expectation.
3. Capture an owner/authorized baseline for one synthetic object, then repeat the same request with a second tester-controlled role/tenant. Keep method, object, body, and content type unchanged while changing only the principal.
4. For read exposure, compare exact fields and values against the allowed projection. For writes, add one harmless synthetic candidate property per request and verify persisted state through an independent read. An echoed value is not proof of persistence.
5. Check nested objects, arrays, bulk updates, export endpoints, GraphQL fragments/aliases, and alternate API versions only when they exist in the observed surface.
6. Confirm whether the field is genuinely protected by product semantics, then preserve a redacted minimal request/response pair and a relevant negative control.

## Request comparison template
- Owner baseline: GET the synthetic object as its owning test account.
- Cross-role read: request the same object with the lower-role test identity.
- Write candidate: update the tester-owned object with one non-sensitive marker property, then read it back.
- Negative control: query a known-public property and a known-denied object to verify normal endpoint behavior.

Do not use real customer records, secrets, payment attributes, role escalation fields, or irreversible actions as test fixtures.

## What constitutes a finding
- **Candidate:** a property appears in output or is accepted in a request but its sensitivity/policy is not yet established.
- **Confirmed read issue:** a controlled lower-authority identity receives a property whose confidentiality boundary is defined and demonstrably violated.
- **Confirmed write issue:** a protected property is persisted and changes behavior beyond the principal's intended authority.
- **False positive:** the field is documented as public/editable, the response is a mock/echo, or independent state does not change.
- **Inconclusive:** test identity, object, expected policy, or persistence evidence is missing.

## Chaining and impact
- Chain with IDOR only when the object ownership boundary is separately crossed.
- Chain with BFLA when the operation itself requires a higher role.
- Chain with mass-assignment when untrusted input is bound to protected model fields; report separate roots only if independently actionable.
- For GraphQL, validate field authorization in the resolver and mutation path rather than inferring risk from introspection.
- Do not add severity just because multiple property names are exposed. State the actual data/action revealed and the actor who can reach it.

## Evidence and remediation
Save the exact endpoint/method, role and tenant, synthetic object ID, expected property policy, sanitized request/response, independently observed persisted state, negative control, and cleanup status. Recommend server-side allowlisted projections and writable-field allowlists, per-property authorization for sensitive fields, schema/resolver regression tests, and a cross-role test that fails if unauthorized fields are returned or changed.

## References
- https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- https://portswigger.net/web-security/api-testing


## Field-level review matrix

| Property class | Read-side question | Write-side question | Evidence bar |
|---|---|---|---|
| Identity/ownership | Is owner, tenant, or membership metadata exposed beyond policy? | Can caller reassign owner/tenant on a test object? | Server-authoritative owner/tenant after read-back |
| Role/privilege | Is role/permission metadata private to admins? | Can caller set role, scopes, or approval state? | Never promote a real account; use an isolated fixture and explicit authorization |
| Billing/entitlement | Are internal price, billing, or entitlement fields returned? | Can a client-supplied amount/status override server calculation? | Synthetic transaction and documented invariant; no real financial actions |
| Security/session | Are recovery state, MFA state, API-key metadata, or internal security flags exposed? | Can caller change security controls without required proof? | Safe test account and state comparison; do not retrieve live secrets |
| Internal/derived | Are internal IDs, debug fields, or computed fields returned unnecessarily? | Are server-derived values accepted from client input? | Field is shown to be trusted/used, not merely echoed |
| Nested/bulk | Are child fields filtered per object and role? | Does each item/field get validated individually? | Controlled fixtures and per-item/per-field result |

### JSON response key inventory (keys only)

Use this on a saved, redacted response from an authorized test fixture. It lists property paths without printing values.

```bash
jq -r 'paths(scalars) | map(tostring) | join(".")' response.json | sort -u
```

For large/nested responses, compare key paths and values separately; a key-name difference is a lead, while the sensitivity policy and actual value matter for confirmation. Do not run this against a bulk dump of real customer data.

### Minimal write validation

1. Save the normal request and current server-side value for one synthetic object.
2. Submit exactly one harmless candidate property using the normal method/content type.
3. Re-read the object through an independent request or UI; do not trust the update response echo.
4. Compare the stored value and any derived behavior with the documented field policy.
5. Restore the fixture and record cleanup.

### Chaining rules

- Unauthorized object itself is reachable → BOLA/IDOR; property issue remains separate only if a distinct field-level control also fails.
- Operation is admin-only regardless of object → BFLA.
- Protected field is accepted through generic model binding → mass-assignment review; do not assume all writable properties are vulnerable.
- Sensitive data is cached across identities → cache review only after cross-context replay is demonstrated.
- A GraphQL schema exposes a field name → not a finding until resolver output or mutation behavior violates field policy.

Add property_path, expected_read_policy, expected_write_policy, principal_role, tenant, owner_fixture, request_field_present, response_field_present, persisted_value_changed, independent_readback, negative_control, and cleanup_verified to the evidence record.
