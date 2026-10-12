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

- **Burp Repeater:** compare allowed/disallowed properties.
- **OpenAPI/schema:** enumerate documented writable fields.
- **Source review:** inspect DTOs, allowlists, and nested binding.
- **Test UI/database:** verify persistence rather than response-only output.

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


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Treat the attempt budget as a ceiling for independent, evidence-producing hypotheses, not a payload quota. If the signal remains plausible, follow the next relevant branch up to 20 distinct hypotheses; stop earlier when impact is decisive, the branch is irrelevant, or scope/safety limits apply. Cosmetic variations of one request are not independent attempts.

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
