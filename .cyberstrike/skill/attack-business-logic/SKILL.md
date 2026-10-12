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


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Treat the attempt budget as a ceiling for evidence-producing hypotheses, not a quota for payload variants. When a candidate remains plausible, branch to the next independent hypothesis up to a maximum of 20; stop earlier when evidence is decisive, the remaining hypotheses are not relevant, or safety/scope limits apply. Never count the same request with cosmetic encoding changes as separate attempts.

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
