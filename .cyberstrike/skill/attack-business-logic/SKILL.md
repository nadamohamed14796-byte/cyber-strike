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

## References

- [uphiago — hunt-business-logic](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-business-logic)
- [Claude-BugHunter — hunt-business-logic](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-business-logic)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
