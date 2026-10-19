---
name: attack-business-logic
description: "Validate business-rule and workflow flaws using documented invariants, controlled test records, and before/after state comparisons."
category: "business-logic"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - business-logic
  - workflow
  - payments
  - state-machine
  - authorization
tech_stack:
  - web
  - rest-api
  - ecommerce
  - saas
  - fintech
cwe_ids:
  - CWE-840
  - CWE-841
chains_with:
  - attack-idor-automation
  - attack-bfla
  - attack-race-condition
prerequisites: []
severity_boost:
  attack-race-condition: "Concurrency can violate a business invariant such as one-time redemption; test only disposable items."
---

# Business Logic and Workflow Assessment

## Objective

Identify workflows that accept an invalid sequence, violate a documented invariant, or trust client-controlled business values. Use synthetic accounts and reversible transactions in an authorized environment.

## Testing Methodology

### Phase 1: Model intended workflow

Document normal states, prerequisites, transitions, quantities, ownership, expiry, and final state. Identify invariants such as single redemption, non-negative balance, inventory bounds, or approval before release.

### Phase 2: Capture valid baseline

Complete the legitimate workflow once using a disposable test record. Record request order, server-side state, values, and idempotency/reference identifiers. Do not use real funds, customer data, or irreversible actions.

### Phase 3: Change one rule input

Test skipped/reordered steps, stale state, client-supplied totals, and boundary values one at a time. Prefer staging/dry-run endpoints. Never manipulate real payments, shipment, credits, or entitlements.

### Phase 4: Verify authoritative state

Compare backend state and audit trail before/after. Check whether server recomputes price, permissions, balance, eligibility, expiry, and ownership. Repeat only enough to establish stable evidence.

### Phase 5: Assess concurrency if authorized

Use a lab or disposable item with a small agreed request budget. Do not issue high-volume parallel requests or compete for a real benefit/payment.

## What Constitutes a Finding

- **Candidate / lead:** unusual sequence returns success or client value differs from display.
- **Confirmed finding:** authoritative server state violates a documented invariant in a reproducible test transaction.
- **Not a finding:** UI-only inconsistency, expected rounding, cache staleness, or a response that does not alter server state.

## Evidence Requirements

- Intended workflow and violated invariant.
- Baseline and modified request sequence, test transaction IDs, role, timestamps.
- Before/after authoritative state from approved logs or test UI.
- Use synthetic values and omit customer/payment records.

## Tools

- **Burp Suite / DevTools:** capture normal workflow requests.
- **API schema and product rules:** define valid state transitions.
- **Staging fixtures:** isolate financial and entitlement logic.
- **Audit logs:** distinguish success-shaped responses from persisted state.

## Business Invariant Decision Matrix

| Invariant | Test question | Confirmation |
|---|---|---|
| Transaction state | Can a step occur without its prerequisite? | Persisted state shows disallowed transition |
| Price/quantity | Does server recompute totals and bounds? | Synthetic transaction accepts unauthorized value |
| One-time benefit | Can a test coupon/reward be redeemed twice? | Test ledger records extra redemption |
| Ownership/eligibility | Is eligibility recalculated server-side? | Controlled account receives an invalid entitlement |
| Approval workflow | Can requester approve their own restricted action? | Audit trail shows disallowed transition |
| Replay/idempotency | Does duplicate submission repeat a side effect? | Test ledger proves duplicate persisted effect |

**Mitigation:** enforce invariants server-side, use explicit state machines, recompute sensitive values, enforce idempotency/transactions, and automate negative-transition tests.

## Verification and False Positives

- Optimistic UI may show completion before server commit; inspect authoritative state.
- Rounding, eventual consistency, or queued jobs can explain temporary mismatch.
- Define business policy before calling alternate sequence invalid.
- Stop before real financial transfers, purchases, benefit redemption, or high-volume concurrency.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Continue testing materially distinct, evidence-producing hypotheses while the candidate remains plausible and a meaningful next branch exists. Do not impose a fixed attempt ceiling or count cosmetic retries as new hypotheses. Stop when direct evidence confirms or disproves this hypothesis, no meaningful new branch remains, a valid prerequisite is unavailable, or program/safety rules require stopping; unresolved cases remain inconclusive.

Keep a compact ledger for every attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve raw evidence locally, redact secrets, and avoid collecting unrelated user data.

### Skill-specific hypothesis order

1. Write the business invariant before testing (for example, a workflow step may happen once, a discount cannot exceed a defined limit, or a refund cannot exceed the captured amount) and capture the normal valid transaction.
2. Test one boundary at a time using test-owned fixtures: minimum/maximum values, repeated submission, omitted optional fields, changed ownership, and permitted versus forbidden workflow ordering.
3. Check whether the server enforces the invariant across UI, API, and asynchronous/background routes; client-side validation is context, not proof of server-side enforcement.
4. Use idempotency/replay checks and concurrency only when explicitly allowed, at low bounded volume, with a disposable transaction and an agreed cleanup path.
5. Measure the business outcome in server-side state or the authoritative response, compare with a valid control, and stop immediately if real money, real users, external notifications, or production inventory may be affected.


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

- [uphiago — hunt-business-logic](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-business-logic)
- [Claude-BugHunter — hunt-business-logic](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-business-logic)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)


## Hands-on field pattern: state transition and invariant checks
Map the workflow before testing: current state → allowed actor → expected transition → invariant that must remain true. Use an owned disposable record or staging fixture; avoid real payments, refunds, transfers, invitations, or destructive actions.

```text
Fixture: TEST_ORDER_001 (owned by controlled account A)
Baseline: GET /api/orders/TEST_ORDER_001 -> status=Pending, owner=A
Probe: replay the observed transition request as the same authorized actor; change one workflow variable only
Verify: read the controlled object again and compare persisted state, audit event, and downstream side effects
```

The strongest chain is input/state inconsistency → missing server-side invariant → unauthorized or duplicate transition → measurable business consequence. Chain into attack-race-condition, attack-rate-limit-bypass, attack-bfla, or attack-idor-automation only when the relevant concurrency, abuse-control, function, or object signal is observed.


## Enrichment: state transitions and impact
Build a state model before testing: current state, authorized actor, expected transition, invariant, and postcondition. Test only owned disposable records or staging fixtures; do not run real money movement or destructive operations.

```text
Fixture: TEST_ORDER_001
Baseline observation: order is pending and owned by controlled account A
Test: replay the observed safe transition with one changed variable
Verify: re-read the same fixture and compare persisted state and audit event
```

A strong chain is an inconsistent input/state transition causing a violated business invariant and a measurable unauthorized consequence. Link to race-condition, rate-limit, function-level authorization, or object-level authorization skills only when their trigger is observed.


## Targeted quality-loop enrichment (2026-10-19)

### Invariant and state-transition ledger
Represent each important workflow as allowed states, prerequisites, ownership, expiry, and transitions. State one invariant explicitly (for example, a one-time benefit is consumed once or an approval precedes release), then test one transition boundary using a disposable record and verify authoritative server state before and after. Include retries, stale state, alternate routes, duplicated submission, and concurrent execution only when each branch tests a distinct invariant and the program permits it. A success-shaped response is not proof if state is unchanged; a surprising final state needs a control and repeatable evidence. Chain to IDOR/BFLA when identity or role authorization is missing, or race-condition review when the violation depends on interleaving.


## Workflow coverage extension: synchronous, asynchronous, and cross-channel paths

For each business invariant, record where it is enforced and where the state is read back. The same operation may pass through browser validation, API validation, a queue/worker, and a downstream provider; do not assume that identical UI behavior means identical server-side enforcement.

| Workflow surface | Test idea using a disposable fixture | Required proof |
|---|---|---|
| Client/API disagreement | Compare UI-calculated values with the normal API request; change one client-supplied field only | Server-authoritative total/eligibility and persisted result |
| Duplicate/retry | Repeat the same documented idempotent request with the same idempotency key, then a new key only if the contract allows it | Duplicate side effect in the test ledger, not just duplicate 2xx responses |
| Async job | Submit one test job and compare accepted, queued, completed, and failed states | Final persisted outcome and any duplicate downstream side effect |
| Cross-channel workflow | Compare web UI and documented mobile/API operation for the same test fixture | One channel skips an invariant enforced by the other |
| Stale authorization | Change test fixture ownership/membership, then retry an already captured operation | Server policy after the change, not just stale frontend display |
| Numeric boundaries | Test documented min/max, zero, negative, rounding, currency/units, and integer overflow boundaries where applicable | A persisted value violates a documented invariant; no real monetary movement |
| Multi-step approval | Compare requester, approver, and low-privilege test roles | Audit trail shows an unauthorized transition or separation-of-duty violation |

### Side-effect inventory

Before an experiment, list possible side effects: email/webhook, billing provider, inventory, entitlement, queue job, audit log, notification, and external integration. Use staging or explicit program-provided safe fixtures when an action can trigger external effects. Do not perform a production test simply because the first request is low impact.

### Report and chain quality gate

A business-logic report should include the expected invariant, normal state transition, altered transition, server-authoritative before/after evidence, the minimum consequence, and cleanup. Route a role-only violation to BFLA; an object ownership violation to BOLA; a duplicate effect caused by request interleaving to race-condition; and a pure abuse-volume control failure to rate-limit analysis. Avoid multiple reports for the same root cause unless each has a distinct, independently evidenced impact.
