---
name: wstg-authz-03
description: "Testing for Privilege Escalation"
category: authorization
owasp_id: WSTG-AUTHZ-03
version: "1.0.0"
author: cyberstrike-official
tags: [authorization, access-control, privilege, wstg, authz]
tech_stack: []
cwe_ids: [CWE-269]
chains_with: [wstg-authz-02, wstg-athn-05]
prerequisites: [wstg-athn-01, wstg-idnt-01]
severity_boost: {}
---
# WSTG-AUTHZ-03 — Privilege Escalation (Evidence-Led)

## Objective

Determine whether a test identity can perform an action or access a resource beyond its documented role/ownership permissions. A path containing `admin`, a role field, or a successful response alone is not proof.

## Safety and scope

- Confirm the exact URL and canonical target workspace with persisted scope before active requests.
- Use only explicitly authorized test accounts and test-owned resources. Never access another person's records, guess/enumerate IDs, use real admin credentials unless explicitly provided for this engagement, or modify/delete production resources.
- Do not inject privileged role values into live accounts. If testing a server-controlled role property requires an active change, request an isolated fixture or stop as blocked.
- Do not brute-force paths, tamper with tokens for other identities, or use raw requests to bypass scope/normalization.

## Test method

1. **Map the expected policy.** Use application docs, captured traffic, and `web_get_session_context` to identify roles, resource ownership, and the action expected to be restricted.
2. **Establish a baseline.** Capture a successful request made by an authorized test identity against a harmless test-owned resource.
3. **Choose one relevant control.** Compare with a lower-privilege test identity or unauthenticated request only if the policy requires denial. Preserve CSRF/session context and change one factor at a time.
4. **Check the meaningful result.** Verify the actual protected data/action, not just status code. Rule out public resources, cached responses, stale sessions, and role-appropriate differences.
5. **Avoid speculative bypass lists.** Do not automatically try case variants, path traversal, method overrides, or `admin=true` parameters. Test these only if captured routing/authorization evidence supports a specific hypothesis and the approved test path is safe.

## Recording and validation

Use `verification_attempt` for each meaningful executed test. Record the request ID, test identity label (not token), resource owner, expected policy, baseline/control, observed response, and valid preconditions. Duplicate variants, planned tests, and invalid scope/setup do not count.

Use `validate_finding` for the ten-check assessment. A decisive confirmation may stop early. A final false-positive/disproven verdict requires 20 distinct valid evidence-backed attempts and matching contradictory checks. If safety or prerequisites prevent this, keep `INCONCLUSIVE / NEEDS REVIEW`.

## Reporting

Use `report_vulnerability` only when unauthorized access or action is demonstrated. Include minimal redacted request/control evidence and remediation such as server-side checks at every function/object boundary. Never include tokens, cookies, personal data, or unrelated users' records.
