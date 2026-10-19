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


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Continue testing materially distinct, evidence-producing hypotheses while the candidate remains plausible and a meaningful next branch exists. Do not impose a fixed attempt ceiling or count cosmetic retries as new hypotheses. Stop when direct evidence confirms or disproves this hypothesis, no meaningful new branch remains, a valid prerequisite is unavailable, or program/safety rules require stopping; unresolved cases remain inconclusive.

Keep a compact ledger for every attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve raw evidence locally, redact secrets, and avoid collecting unrelated user data.

### Skill-specific hypothesis order

1. Build a role-to-function matrix from application routes and normal user flows. Mark each operation as allowed, denied, or not yet known for each controlled role.
2. Invoke one directly observed function as a low-privilege test account even when the UI hides it; compare with the administrator test account and a nonexistent-function control.
3. Separate endpoint authorization from object authorization: hold the object constant while changing role, then hold role constant while changing only a test-owned object.
4. Use harmless or reversible administrative actions on a disposable fixture to prove the impact; avoid user, billing, permission, or tenant changes that cannot be safely rolled back.
5. Confirm the denied baseline is genuinely policy-denied rather than merely unsupported. Report the exact role/function pair and demonstrated capability, not a general claim of administrator access.


### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture, with a relevant control and a clear trust-boundary failure.
- **Likely / needs corroboration:** multiple independent signals support the hypothesis, but the security consequence or root cause is not yet established.
- **Unconfirmed:** evidence is incomplete, ambiguous, cached, or indistinguishable from a generic response.
- **Refuted / false positive:** a relevant negative control, valid authorization explanation, or repeatable contradictory evidence explains the signal. Record what was tested; do not claim that every theoretical variant was exhausted.
- A status code, banner, stack trace, response-length difference, endpoint existence, tool alert, or visible frontend state is never sufficient on its own.

### Stop and cleanup rules

Stop immediately on an out-of-scope boundary, unexpected real-user data, production side effects, rate-limit/availability degradation, credential exposure, or a request to perform a prohibited action. Do not continue merely to spend the budget. Restore disposable test state, revoke temporary sessions/tokens where possible, and record cleanup status.

### Agent handoff record

Return: skill, target asset, in-scope evidence, baseline, candidate hypothesis, attempts used, observed impact, negative controls, confidence/verdict, related-skill signal, sanitized evidence references, and cleanup status. Invoke a chained skill only when the stated signal is independently observed; do not chain from name similarity alone.

## References

- [uphiago — hunt-broken-function-level-auth](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-broken-function-level-auth)
- [OWASP API Security — BFLA](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)


## Hands-on field pattern: same function, different roles
Choose a non-destructive function already observed in the application. Use the same method and payload with two controlled roles; retain the expected permission matrix from documentation or product behavior.

```bash
curl -sS -D low.headers -o low.body -H "Authorization: Bearer $LOW_ROLE_TOKEN" "$FUNCTION_URL"
curl -sS -D high.headers -o high.body -H "Authorization: Bearer $HIGH_ROLE_TOKEN" "$FUNCTION_URL"
sha256sum low.body high.body
```

A route reachable to a low role is not enough: establish that the protected function actually ran or returned a privileged result, while ruling out client-side-only differences and generic error pages. Continue through materially different role/function combinations rather than stopping at a fixed attempt count. Chain to `attack-idor-automation` for object-level checks, `attack-mass-assignment` for field-level writes, and `attack-business-logic` when a sensitive workflow is implicated.


## Targeted quality-loop enrichment (2026-10-19)

### Role-to-operation differential
Build the matrix from observed requests and documented roles, not from hidden buttons alone. For every sensitive operation compare (a) known-allowed action by a high-role test account, (b) the same action by a low-role account, and (c) an operation that should be denied to both as a negative control. Preserve the operation, object, tenant, and content type while changing only the principal. Confirm that server-side state or protected output changed; if only a status differs, investigate gateway behavior first. Route object-specific failures to IDOR/BOLA, sensitive-field-only differences to API property authorization, and workflow invariants to business-logic testing. Never use real customer records or non-reversible actions to prove privilege impact.


## Coverage expansion: alternate operation surfaces

After the normal role matrix, add only operation surfaces actually observed in the application or its schema. Keep each row linked to the same role pair and expected policy.

| Surface | Compare | Confirmation requirement |
|---|---|---|
| HTTP methods | Supported GET/POST/PATCH/DELETE methods for the same function | A lower role performs a prohibited operation; state change is verified on a disposable object |
| API versions | Current and legacy routes for the same function | Legacy route bypasses the same documented server-side policy |
| GraphQL | Query, mutation, nested resolver, bulk operation | Resolver performs a privileged function under the low-role test identity |
| Async/background | Job creation, job status, job result/download | Low role can enqueue or retrieve a restricted operation/result |
| Service-to-service | User-controlled request that triggers a backend integration | Downstream action lacks caller authorization; confirm through approved logs or a synthetic fixture |
| Tenant admin | Cross-tenant configuration/role operation in a disposable tenant | Server grants or exposes a privileged function outside the test principal's tenant |
| Field update | Role may edit object but not a sensitive property | Route to property-level authorization; do not misclassify as generic BFLA |

### Evidence contract

For every confirmed row, preserve expected_role, observed_role, function_id, route_and_method, tenant, test_fixture, allowed_control, denied_control, server_state_change, evidence_ref, cleanup_verified, and root_cause_confidence. If the route is merely visible but does not execute, classify it as discovery exposure, not BFLA.

### Chain gates

Only chain to object-level authorization if the same function's permission varies by object ownership; to business logic if a permitted function is used in an invalid sequence; to auth bypass if the operation is callable without a valid identity. Keep these as separate hypotheses with independent controls.


## Practical tooling, references, and helper scripts (2026-10-19)

### Tools that fit this skill
- Browser DevTools Network/Application, Burp Proxy/Repeater/Comparer, and curl for replaying one observed request. Use only tool integrations that the current CyberStrike runtime actually exposes; optional CLI programs must be verified with command -v first.
- Before treating an optional CLI command as runnable, verify its presence and version locally. Do not claim integrations or tools that the current runtime has not exposed.
- Start with passive/read-only observation. Only active tests against authorized assets; state-changing tests require an approved disposable fixture and explicit program permission.

### Primary resources
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — test procedures and evidence criteria.
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — controlled labs and differential testing.
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/) — remediation-oriented guidance.

### Small, reusable helper
    python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt
This compares local artifacts offline and heuristically redacts common secrets before displaying differences. It sends no requests and does not prove complete sanitization.

### Evidence and hand-off
- Save a sanitized artifact reference and the exact claim it supports. Keep credentials, full cookies, reset links, private user data, and raw secrets out of notes, global research storage, and commits.
- Mark the result confirmed, disproven, or still a hypothesis. If the key check cannot be run safely or the expected control is missing, record the gap rather than inventing a conclusion.

Validation note: use a known-good baseline and a control case, change one meaningful variable at a time, record the alternative explanation, and route a lead onward only when the evidence meets this skill's proof criteria.
