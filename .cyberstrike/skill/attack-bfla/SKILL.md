---
name: attack-bfla
description: "Assess broken function-level authorization by comparing role-to-operation permissions with controlled accounts and non-destructive actions."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - bfla
  - authorization
  - rbac
  - api
  - privilege-escalation
tech_stack:
  - web
  - rest-api
  - graphql
  - grpc
  - multi-tenant-saas
cwe_ids:
  - CWE-285
  - CWE-862
chains_with:
  - attack-idor-automation
  - attack-business-logic
  - attack-auth-bypass
prerequisites: []
severity_boost:
  attack-idor-automation: "Function-level access gaps can combine with object-level flaws to expose test-owned objects across roles."
---

# Broken Function-Level Authorization Assessment

## Objective

Determine whether the server enforces role and privilege checks for each operation independently of frontend visibility. Use accounts and records controlled by the tester; prefer read-only or reversible actions.

## Testing Methodology

### Phase 1: Build role-operation inventory

Create a role and operation matrix from UI traffic, OpenAPI docs, GraphQL schema, and route definitions. Record expected allow/deny behavior; hidden buttons alone do not define authorization.

### Phase 2: Capture role baselines

For each role, send one known permitted request and one known denied operation. Keep tenant and object IDs within your test environment and record server behavior and state.

### Phase 3: Compare operations across roles

Replay the same harmless request under a lower-privileged test account. Test relevant methods and API versions one at a time. Use a disposable synthetic object for mutations only when explicitly allowed.

### Phase 4: Verify server enforcement

Confirm backend denies the operation and does not return protected fields or change state. A 403 from a proxy is insufficient if the action still runs; verify state in the test environment.

### Phase 5: Trace policy coverage

Review role claims, policy evaluators, middleware, service-to-service authorization, and default-deny behavior. Ensure every route receives the required check.

## What Constitutes a Finding

- **Candidate / lead:** a function is discoverable by a low-role user or returns an unusual status.
- **Confirmed finding:** lower-privileged test identity performs a higher-privilege function or obtains protected output against a controlled fixture.
- **Not a finding:** hidden button, route-name disclosure, expected shared operation, or changed status with no permission difference.

## Evidence Requirements

- Role/operation matrix with expected and observed decisions.
- Matched requests, endpoint/method, timestamp, and test tenant.
- Resulting state for disposable object or sanitized harmless output.
- Redact privileged data and credentials.

## Tools

- **Burp Suite:** replay identical requests under different controlled sessions.
- **OpenAPI/GraphQL tools:** inventory operations and declared roles.
- **Route/source review:** map handlers to policy checks.
- **Synthetic fixtures:** reproduce mutations without business impact.

## Role-to-Function Coverage Matrix

| Function | Low-role check | Evidence |
|---|---|---|
| Admin read | Request test-only configuration | Protected fields are denied or redacted |
| Admin mutation | Dry-run or disposable object, if allowed | Backend denies; state remains unchanged |
| Export/report | Generate synthetic report only | Export honors UI permissions |
| Role/tenant admin | Inspect policy in a disposable tenant | Caller cannot grant roles or cross tenant |
| Legacy/API version | Compare route variants | Each variant enforces equivalent policy |
| Background job | Review enqueue/status APIs | Low-role caller cannot invoke restricted job |

**Mitigation:** default-deny, authorize every function server-side, centralize policy checks, and test role matrices in CI.

## Verification and False Positives

- A proxy 403 can mask backend state changes; verify in a controlled test.
- Some operations are intentionally shared; use policy and documentation.
- Admin schema exposure is not itself BFLA.
- Avoid production deletes, exports, grants, or mutations without disposable fixtures.

## References

- [uphiago — hunt-broken-function-level-auth](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-broken-function-level-auth)
- [OWASP API Security — BFLA](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
