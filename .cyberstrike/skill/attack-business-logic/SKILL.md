---
name: attack-business-logic
description: "Test application workflows for broken business rules and trust-boundary assumptions"
category: "web-application"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [business-logic, workflow, authorization, state-machine, race-condition]
tech_stack: [web, api, http]
prerequisites:
  - "Written authorization and a clear test boundary"
  - "Dedicated test tenant, disposable records, and known expected workflow"
chains_with: [attack-idor-automation, attack-race-condition, attack-api-misconfig, attack-triage-validation, attack-report-writing]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-business-logic/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
---

# Business Logic Testing

## When to use

Use when security depends on a sequence of steps, limits, eligibility rules, approvals, quotas, pricing, ownership, or state transitions rather than a single input validation rule.

## Preconditions and safety

- Define the expected business rule with evidence from product behavior or documentation.
- Use a test tenant and disposable records. Avoid real purchases, refunds, payouts, messages to customers, or irreversible changes.
- Do not assume unusual behavior is a vulnerability until the security or business invariant is clear.
- Keep request volume low; race testing is owned by `attack-race-condition`.

## Procedure

1. **Model the workflow.** Write the states and allowed transitions, such as draft → submitted → approved. Identify who may perform each transition.
2. **Write invariants.** Examples: a discount is applied once; a user cannot approve their own request; a quota cannot be exceeded; a cancelled object cannot be fulfilled; ownership remains tied to the creator.
3. **Capture the valid path.** Perform the workflow with your test account and record required fields, server-side state, and expected outcome.
4. **Change one condition at a time.** Try skipping a step, repeating a step, changing order, replaying an idempotent request, using a stale state, or changing a client-supplied price/quantity in a disposable transaction.
5. **Check actor boundaries.** Where two controlled accounts are permitted, verify that roles and ownership are enforced at every transition, not only at object creation.
6. **Check server-side calculation.** Compare client-displayed totals with server-confirmed totals in a test transaction. Never manipulate real billing or trigger actual fulfillment.
7. **Check replay and duplicate submissions.** Use a small number of requests against a disposable action and confirm idempotency and state consistency.
8. **Observe final state.** Use a separate read-only query or UI view to confirm whether the business invariant was violated. A success message alone is insufficient.
9. **Assess impact and cleanup.** Explain the rule violated, who can exploit it, and the bounded impact. Restore disposable state if permitted.

## Pitfalls

- UI inconsistency may be cosmetic or eventually corrected server-side.
- A feature behaving differently for admins may be intentional.
- A test must not create real financial loss, send real communications, or affect other tenants.
- Do not combine multiple changes in one request until each individual hypothesis is understood.

## Verification

A valid finding includes the expected rule, baseline valid sequence, minimal violating sequence, observed persisted state, actor/role context, and impact. If the rule cannot be established, document an observation rather than claiming a vulnerability.

## Output contract

Return: `rule`, `baseline_sequence`, `test_sequence`, `observed_state`, `affected_role`, `impact`, `cleanup_status`, `confidence`, and redacted evidence references.
