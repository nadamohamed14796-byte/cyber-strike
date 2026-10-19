---
name: attack-exceptional-conditions
description: "Review error, timeout, retry, partial-failure, cancellation, and fallback paths for inconsistent security controls."
category: "web-application"
version: "1.0.0"
tags: [error-handling, fail-safe, retry, timeout, queues, authorization]
tech_stack: [web, api, distributed-systems, queues]
prerequisites: ["Prefer code/config review and controlled test environments", "Avoid causing production instability"]
---

# Exceptional Conditions and Fail-Safe Review

## Goal
Check whether normal-path controls remain enforced during exceptions, dependency failures, retries, fallback behavior, cancellation, and partial completion. A 5xx response or timeout alone is not a security finding.

## Review workflow
1. Identify one security invariant and its normal successful path.
2. Trace authorization, validation, audit, and state changes across every stage.
3. Prefer source review, unit/integration tests, dependency stubs, and staging fault injection.
4. Use synthetic fixtures and a known-good baseline. Change one failure condition at a time.
5. Verify authoritative final state, not only response status or error text.
6. Record rollback/compensation and cleanup behavior.
7. Stop if the test risks production instability, real financial effects, notifications, or irreversible state changes.

## Coverage matrix

| Failure boundary | Controlled review | Expected safe behavior |
|---|---|---|
| Identity/policy service unavailable | Staging stub returns a controlled error | No silent grant or privileged default identity |
| Validation/parser failure | Harmless malformed fixture | Reject before protected state changes |
| Dependency timeout | Simulated staging timeout | Required authorization and tenant checks remain enforced |
| Retry/idempotency | Disposable synthetic job or record | No duplicate protected side effect beyond the documented contract |
| Partial transaction | Controlled failure between test stages | Rollback or compensation leaves no orphaned authority/resource |
| Cache fallback | Synthetic private response with two controlled identities | No cross-identity reuse |
| Async queue/dead letter | Test-owned job with known tenant context | Owner/tenant authorization persists through retry and replay |
| Cancellation | Cancel a disposable workflow at a supported stage | Final state and compensation are consistent |
| Audit/logging failure | Staging-only simulated sink failure | Critical operation follows documented fail-safe policy |
| Error output | Synthetic sensitive marker in a test error | No secrets or unrelated private data in client response/logs |

## Test design
For each case, record the invariant, expected failure behavior, controlled fault, observed decision, authoritative state, negative control, and cleanup. Do not stress production to provoke timeouts. If the path cannot be safely reproduced, mark it inconclusive and provide the owner with a specific regression test.

## Finding criteria
Confirm only when a failure path reproducibly violates a security invariant and the impact is demonstrated. Distinguish reliability defects from authorization, confidentiality, integrity, or business-logic defects.

## Chain routing
- Duplicate effect after retry/concurrency: business-logic or race-condition review, only if the invariant is violated.
- Policy failure allows access: authentication/authorization review.
- Error exposes sensitive data: information-disclosure review with minimal redacted proof.
- Stale cached private response crosses identities: cache review using controlled contexts.

## Evidence contract
Record operation, invariant, fault condition, principal/tenant, expected result, observed result, side-effect state, rollback result, negative control, evidence reference, and cleanup status. A stack trace, timeout, retry, or 5xx alone is not confirmation.

## References
- https://owasp.org/www-project-web-security-testing-guide/
- https://cwe.mitre.org/data/definitions/703.html
- https://cwe.mitre.org/data/definitions/636.html
- https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/
