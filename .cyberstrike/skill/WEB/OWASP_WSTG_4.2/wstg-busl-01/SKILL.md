---
name: wstg-busl-01
description: "Test Business Logic Data Validation"
category: business-logic
owasp_id: WSTG-BUSL-01
version: "1.2.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [business-logic, validation, workflow, wstg]
tech_stack: [web, http, api]
cwe_ids: [CWE-840]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-business-logic/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
  - "https://owasp.org/www-project-web-security-testing-guide/"
---

# WSTG-BUSL-01: Business Logic Data Validation

## Objective

Determine whether server-side business rules remain correct when requests contain unexpected but safe values, omit fields, repeat valid actions, or arrive out of the expected workflow order. Focus on security boundaries and meaningful business impact rather than UI differences alone.

## Preconditions and safety

- Confirm written authorization, in-scope hosts, allowed methods, and test intensity.
- Use a dedicated test account, synthetic records, and reversible low-impact actions.
- Do not create real purchases/refunds, transfer funds, trigger fulfillment, send customer communications, or alter production entitlements.
- Test concurrency/race hypotheses only when explicitly allowed and route them to the dedicated race-condition skill.
- Avoid extreme numeric values, oversized payloads, and actions that could affect availability or other users.

## Build a rule model

For each workflow, document:
- Actor: expected role, account, tenant, and authentication state.
- Preconditions: state, ownership, eligibility, required approvals, and required prior steps.
- Inputs: fields accepted from the client versus values that must be calculated by the server.
- Invariant: the rule that must always remain true, such as positive quantity, tenant ownership, or required approval.
- Postconditions: expected persisted state, audit events, and notifications.
- Rollback: how the test record can be safely restored.

Write the invariant before testing. Without a clear invariant, an unexpected response may not establish a vulnerability.

## Procedure

### 1. Establish a valid baseline

1. Complete one normal workflow with a test account and disposable record.
2. Capture the minimal request/response sequence and expected server-side state.
3. Verify the final state using an independent read-only view where available.
4. Identify which fields are server-generated, immutable, role-controlled, or derived from other values.

### 2. Validate types, ranges, and required fields

- For a disposable record, test one representative case at a time: omitted optional field, omitted required field, empty value, wrong primitive type, unexpected enum value, and a reasonable boundary value.
- Confirm validation is enforced by the server, not only by the UI or client library.
- Check whether normalization or defaulting changes the meaning of a request unexpectedly.
- Do not send unbounded arrays, huge integers, deeply nested payloads, or malformed input intended to exhaust resources.

### 3. Test workflow order and state transitions

- Map allowed transitions, such as draft → submitted → approved, and identify transitions that require a prior step or separate authority.
- Using a synthetic record, try one out-of-order transition at a time and verify persisted state.
- Confirm rejected transitions do not partially mutate data, create duplicate records, or emit misleading success notifications.
- Test cancellation, retry, and resubmission only when the action is reversible and explicitly permitted.

### 4. Check server-authoritative values

- Compare client-supplied totals, quantities, discounts, ownership identifiers, roles, approval flags, and status fields with values the server should derive or authorize.
- Use harmless marker values on disposable records; never modify a real user's role, balance, or entitlement.
- Verify both the immediate response and final persisted state. A reflected input or HTTP success code is not proof of an accepted state change.
- Check whether the server recalculates dependent values after any allowed update.

### 5. Check ownership and tenant boundaries

- Create two controlled accounts or tenants only if the program permits it, and create synthetic records in each.
- Test whether a record identifier or tenant field can be changed to reference the other test-owned record.
- Confirm authorization is checked on every relevant operation, including read, update, delete, export, and secondary actions.
- Stop if the response exposes real third-party data; do not explore further or retain it.

### 6. Check idempotency, duplicates, and retries

- Identify actions expected to be idempotent, such as retrying a draft save, and those that intentionally create a new object.
- Submit a normal action once, then perform at most one controlled retry using the same idempotency context when permitted.
- Verify whether the server creates duplicate records or applies the business effect twice.
- Do not use parallel requests; concurrent execution is a separate test class and requires explicit approval.

### 7. Check limits and eligibility

- Review documented minimums, maximums, quotas, eligibility rules, time windows, and per-account limits.
- Use only values near a reasonable documented boundary and a synthetic record.
- Check whether the same invariant is enforced through UI, API, bulk endpoint, and alternate API version when those routes are in scope.
- Avoid testing real financial transfers, purchase completion, refunds, messaging, or fulfillment without a dedicated sandbox.

### 8. Verify outcome and cleanup

- Inspect final persisted state and relevant audit history; compare it with the pre-test baseline.
- Record rejected requests as well as accepted ones so the expected invariant is clear.
- Restore the synthetic record, remove test artifacts, and document any cleanup that requires the program owner.
- Repeat only if necessary to rule out a transient or eventual-consistency effect.

## Common false positives

- The UI shows a changed value but the server ignores it.
- A response echoes client input without persisting it.
- A role or workflow exception is intentional and documented.
- Eventual consistency briefly shows an intermediate state that later converges correctly.
- A duplicate HTTP response represents an idempotent replay rather than a second business effect.
- A product-rule disagreement has no security boundary or measurable impact.

## Evidence contract

Return business_rule and expected_invariant; actor_role and synthetic record identifiers; valid_baseline and minimal redacted request sequence; single_variable_change and server response; persisted_state_diff and audit/event observations; impact, reproduction, cleanup_status, and confidence.

Do not include real customer data, session tokens, payment details, or unrelated secrets.

## Remediation guidance

Enforce invariants server-side; allowlist state transitions; derive sensitive totals and ownership from trusted state; validate type/range/enum constraints centrally; make retries idempotent where appropriate; apply authorization on every operation; and use transactions for multi-step state changes.
