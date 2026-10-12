---
name: wstg-busl-01
description: "Test Business Logic Data Validation"
category: business-logic
owasp_id: WSTG-BUSL-01
version: "1.1.0"
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

Determine whether the application enforces business invariants on the server rather than trusting client-supplied values, request order, or UI restrictions.

## Preconditions and safety

Use a dedicated test account, disposable records, and reversible low-impact actions. Do not create real purchases/refunds, transfer funds, send messages to customers, or trigger fulfillment. Race/concurrency hypotheses belong in `attack-race-condition` and require separate permission.

## Procedure

1. Identify the business rule from documentation, UI behavior, or a valid baseline workflow.
2. Write the invariant explicitly: allowed state transitions, limits, ownership, pricing, quantity, eligibility, uniqueness, or approval requirements.
3. Capture a normal successful request and verify the persisted state using a read-only view.
4. Change one field or step at a time. Test omitted fields, unexpected types, stale values, reordered workflow steps, repeated submissions, and client-side-only restrictions using disposable data.
5. Compare client-supplied totals, role flags, ownership fields, and status values with server-calculated or server-authoritative values. Do not submit privilege-bearing changes to a real account.
6. Test boundary values only within reasonable limits; avoid huge numeric values or payloads that could affect availability.
7. Verify final server-side state independently. A success message or reflected value does not prove the invariant was violated.
8. Check whether the behavior is intentional, role-dependent, eventually consistent, or corrected by a later server-side step.
9. Restore the test record and document cleanup.

## Common false positives

- UI-only difference with no server-side state change.
- A value is echoed but ignored by the business logic.
- A special role is intentionally allowed to perform the action.
- Eventual consistency converges to the correct state.
- The report describes a product rule without showing a security boundary or meaningful impact.

## Evidence and output

Return `business_rule`, `valid_baseline`, `minimal_test_sequence`, `persisted_state_diff`, `actor_role`, `impact`, `cleanup_status`, `confidence`, and redacted evidence. Recommend server-side invariant enforcement, allowlisted state transitions, server-calculated values, and transactional consistency.
