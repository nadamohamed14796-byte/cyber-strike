---
name: attack-mass-assignment
description: "Assess mass assignment by testing whether untrusted fields alter protected model properties using disposable records and server-side state verification."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - mass-assignment
  - api
  - model-binding
  - authorization
  - input-validation
tech_stack:
  - web
  - rest-api
  - graphql
  - nodejs
  - rails
  - django
  - springboot
cwe_ids:
  - CWE-915
chains_with:
  - attack-bfla
  - attack-idor-automation
  - attack-auth-bypass
prerequisites: []
severity_boost:
  attack-bfla: "Changing a protected role or status may produce privilege escalation if restricted operations then become available."
---

# Mass Assignment Assessment

## Objective

Determine whether automatic request binding accepts security-sensitive model fields the caller should not control. Use disposable test-owned objects and verify persisted state instead of response reflection.

## Testing Methodology

### Phase 1: Identify model-binding surfaces

Inspect create/update endpoints, JSON bodies, GraphQL mutations, profile/settings forms, and framework binding code. Compare documented writable fields with role, owner, tenant, approval, billing, verification, and status properties.

### Phase 2: Capture normal update

Create a disposable object and change an ordinary field through the supported interface. Record stored state and which fields the role is permitted to edit.

### Phase 3: Add one protected field

Add one suspected protected field at a time with a harmless test value in staging. Do not assign admin privileges, transfer ownership of shared records, or alter real billing/verification state.

### Phase 4: Verify persistence

Check authoritative object state and test only a minimal benign consequence. Distinguish response echo from persisted property. Restore/delete the fixture.

### Phase 5: Trace allowlist and nested models

Review DTOs, serializer schemas, writable-field lists, nested relation binding, and authorization at parent/child levels.

## What Constitutes a Finding

- **Candidate / lead:** server accepts or reflects unknown fields.
- **Confirmed finding:** a protected property is persisted from caller input despite policy forbidding the caller from setting it.
- **Impact-qualified:** a test-only privilege/ownership/workflow boundary demonstrably changes.
- **Not a finding:** ignored/stripped fields or echoes that do not persist.

## Evidence Requirements

- Baseline request and modified request adding exactly one field.
- Disposable object ID, role, timestamp, expected writable fields, authoritative before/after state.
- Sanitized permission consequence and cleanup confirmation.

## Tools

- Python `httpx` or `curl`: compare observed update requests using test-owned records and reversible changes.
- OpenAPI/schema parser: inventory documented writable fields when a schema exists.
- `rg`: inspect local DTOs, serializers, allowlists, and nested binding.
- `jq`: compare saved request/response fields after redaction.
- `python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt`: compare saved responses offline.

Verify the chosen request client and `jq --version`; official docs: https://curl.se/docs/, https://www.python-httpx.org/, https://jqlang.org/. Use local fixtures or source review when live validation is unsafe.

## Writable Field Classification Matrix

| Field | Expected authority | Test approach |
|---|---|---|
| Display name/description | Usually caller-editable | Baseline ordinary update |
| Role/permissions | Server/admin-controlled | Review policy; do not elevate production role |
| Owner/tenant ID | Bound to ownership policy | Two test tenants with synthetic objects |
| Email verified/MFA enabled | Trusted workflow-controlled | Inspect state machine or staging fixture |
| Price/balance/quota | Server-derived | Confirm server recomputes value |
| Approval/internal flags | Workflow-controlled | Test benign fixture field |
| Nested relation ID | Object-level policy required | Ensure relation stays in allowed test scope |

**Mitigation:** bind to explicit DTOs, allowlist writable properties, validate nested objects, enforce property-level authorization, and reject protected fields in regressions.

## Verification and False Positives

- Unknown fields may be ignored; response echo does not establish persistence.
- Properties may be writable only in an audited admin workflow; validate policy.
- ORM defaults may overwrite input; inspect authoritative state.
- Stop before changing real roles, billing, verification, or shared objects.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue with materially distinct, authorized branches while evidence can change the conclusion; deduplicate cosmetic variants and exact retries. Stop when direct evidence resolves the hypothesis, meaningful branches are exhausted, a prerequisite is unavailable, or scope/safety requires stopping. Program limits and production-safety constraints remain mandatory.

Track each attempt as: hypothesis, one changed variable, baseline/control, observed signal, interpretation, confidence, and next branch. Use controlled identities or synthetic resources, preserve only minimal evidence, and redact secrets.

### Skill-specific hypothesis order

1. Record the normal allowed fields and server response for a test-owned object, including the expected role/tenant/owner values.
2. Probe only plausible extra fields supported by the application's data model (for example, status, owner, tenant, or role) one at a time with harmless marker values.
3. Compare fields accepted by create, update, bulk, and nested operations; server-side allowlists may differ by operation and version.
4. Use a disposable record and an inert canary field to verify whether a forbidden property truly persists or changes an authorization boundary; do not promote your own account to admin in a shared production tenant.
5. Capture before/after state, valid-field control, and the denied policy. Recommend explicit DTO/field allowlists and separate create/update schemas.


### Verdict gates

- **Confirmed:** repeatable security impact is shown against an in-scope resource using a tester-controlled identity or fixture, with a meaningful control.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause is not yet established.
- **Unconfirmed:** observations are ambiguous, cached, generic, or not tied to a security boundary.
- **Refuted / false positive:** a relevant negative control or valid policy/implementation explanation accounts for the observation; document the attempts instead of claiming all imaginable variants were exhausted.
- Do not treat status codes, error text, response length, decoded tokens, static findings, or UI state alone as proof.

### Stop, cleanup, and handoff

Stop at scope uncertainty, unrelated sensitive data, unexpected production changes, service degradation, secret exposure, or prohibited actions. Restore disposable state and revoke test tokens/sessions where possible. Return the scope proof, baseline, hypothesis, attempt count, impact, controls, confidence/verdict, sanitized evidence pointers, relevant handoff signal and cleanup status. Chain into another skill only when its trigger is present.

## References

- [uphiago — hunt-mass-assignment](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-mass-assignment)
- [Claude-BugHunter — hunt-misc related coverage](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-misc)
- [OWASP Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)


## Targeted quality-loop enrichment (2026-10-19)

### Writable-property verification contract
Derive candidate properties from API schemas, normal frontend traffic, source/model definitions, and controlled response differences; classify each as user-editable, server-managed, role/tenant/security-sensitive, or unknown. Add one property to a normal update for a tester-owned object, then verify authoritative state and re-read through the allowed UI/API. Do not treat an echoed field or ignored property as success. Compare nested objects and alternate update endpoints where supported, but avoid any field that triggers money movement, role assignment, or irreversible actions unless explicit program rules permit a disposable fixture. Chain to BFLA or property-level authorization only when the actual principal/property boundary is distinct and demonstrated.


## Writable-field discovery and safe differential

Generate candidate field names from observed request schemas and model definitions rather than guessing a huge field list. Keep one test per property and use inert values on a disposable object.

```bash
# List property paths in a saved synthetic JSON response without printing values.
jq -r 'paths(scalars) | map(tostring) | join(".")' before.json | sort -u > before.keys
jq -r 'paths(scalars) | map(tostring) | join(".")' after.json  | sort -u > after.keys
diff -u before.keys after.keys
```

A new key in the response only shows a shape difference. For a write-side finding, confirm the value persisted through an independent read and that the caller was not allowed to set it.

### Field-operation coverage

| Operation | Specific check | Required evidence |
|---|---|---|
| Create | Is a server-managed property accepted at creation? | Persisted test object violates its expected policy |
| Update | Does the same field become writable after creation? | Independent read-back and normal-field control |
| Nested relation | Can caller bind a child object from another owner/tenant? | Relation access violates policy, not just a malformed reference |
| Bulk update | Is each item/field filtered individually? | Controlled fixture proves one unauthorized field change |
| GraphQL mutation | Are input object types broader than caller's writable schema? | Resolver persists the prohibited field |
| Alternate API version | Does a legacy handler skip the current allowlist? | Same test principal and fixture show policy inconsistency |

### Chain routing

- A protected field is readable but not writable → property-level read exposure.
- A protected field persists but no privilege boundary changes → report the precise data-integrity impact; do not call it privilege escalation.
- A role/permission property changes a controlled fixture's effective capability → chain to BFLA only after a safe, isolated test confirms the operation.
- An owner/tenant property crosses object boundary → chain to BOLA only when the cross-owner access is independently confirmed.

Persist allowed_field_control, candidate_property, expected_authority, request_field_present, server_persisted_value, independent_readback, effective_permission_delta, cleanup_verified, and root_cause_confidence. Never commit secrets or raw production records.


## Agent-executable CLI tooling, resources, and helper scripts

Agent-invokable CLI tools and local libraries only; browser UI, extensions, and interactive intercepting proxies are not required dependencies. Verify official installation docs, version, license, platform support, and impact before use.

### Recommended tools
- Python requests/httpx — controlled identity/session comparisons
- jq — parse structured responses
- http_response_diff.py — compare baseline and test variants
- Local JSONL matrix for account, role, token lifecycle, and operation

### Resources
- https://portswigger.net/web-security/access-control
- https://owasp.org/API-Security/
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids; confirm tool maintenance and CLI behavior from official sources.

### Helper-script contract
Use tester-owned accounts and synthetic resources. Change one trust dimension at a time and preserve baseline/control, auth context, result, and redacted evidence. Never retain live bearer tokens or modify real user data.

Preserve raw evidence and normalize a separate copy. Record source, timestamp, tool/version, auth context, errors, confidence, redaction state, and artifact references. Use explicit paths, structured output, and local fixtures.

### Handoff
Report actual commands and versions, input/output paths, control results, failures, confidence, limitations, and next skill. Missing tools and blocked tests are explicit.
