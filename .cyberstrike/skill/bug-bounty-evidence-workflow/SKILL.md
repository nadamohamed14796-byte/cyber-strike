---
name: bug-bounty-evidence-workflow
description: "Orchestrate evidence-led bug bounty work from inventory through hypotheses, verification, deduplication, triage, and reporting."
category: "bug-bounty-methodology"
version: "1.0.0"
tags: [bug-bounty, evidence, triage, reporting, deduplication, source-review]
prerequisites: ["Operate only on authorized targets", "Treat public writeups as hypotheses, not proof"]
---

# Evidence-Led Bug Bounty Workflow

## Operating principles
- Maintain a durable record of target, scope evidence, asset source, observed behavior, hypothesis, requests/responses, account role, test-data ownership, confidence, and next step.
- Keep discovery separate from validation and reportability. A scanner alert, exposed version, unusual status code, or upstream writeup is a lead, not a finding.
- Never impose a fixed number of hypotheses or endpoints as a completion criterion. Continue while there are new, in-scope, non-duplicate leads and available authorization; use deduplication and evidence-based prioritization rather than arbitrary ceilings.
- Safety controls for destructive operations, request rate, concurrency, and resource-intensive checks remain mandatory. No arbitrary work limit does not mean permission to disrupt a target.

## Lifecycle
1. **Intake:** capture program rules, exclusions, rate limits, asset ownership confidence, and testing constraints. If scope is ambiguous, mark the asset unverified and use passive work until clarified.
2. **Inventory:** merge subdomains, URLs, JS-derived routes, API schemas, cloud/mobile artifacts, and user-supplied traffic. Preserve provenance and first/last seen; do not collapse different methods or parameter combinations.
3. **Hypothesis creation:** each candidate contains a specific control expectation, attacker prerequisites, safe test, expected secure result, vulnerable result, likely impact, and relevant skill/reference.
4. **Execution ledger:** mark each test PASS-SECURE, CANDIDATE, CONFIRMED, INCONCLUSIVE, BLOCKED, NOT-RUN, or OUT-OF-SCOPE. A failed request is not a passed security check.
5. **Validation:** use the least-impact reproducible proof; test with owned accounts and synthetic data. Re-test alternative explanations and authorization controls.
6. **Deduplication:** fingerprint by root cause, affected boundary, route/operation, and impact—not just title or URL. Link duplicate observations to one canonical issue while preserving evidence.
7. **Triage simulation:** assess reproducibility, attacker control, defense boundary, affected asset, realistic impact, scope fit, and remediation. Include counter-evidence and what remains unverified.
8. **Report:** give concise steps, sanitized HTTP evidence, account roles, expected/actual behavior, impact, remediation, and confidence. Never label a report confirmed when evidence is only inferred.
9. **Learning:** extract reusable principles and preconditions from public reports; preserve source attribution and separate researcher narrative from technical fact. Do not blindly replay historical payloads against live targets.

## Completion summary
Report counts by status and source type, plus skipped/blocked reasons. Never claim full coverage if some files were inaccessible, auth-gated, unsupported, or not processed. Identify remaining work without inventing success.

## Evidence record
Each hypothesis should link to a normalized target/endpoint key, source provenance, scope decision, baseline artifact, test identity/object, one changed variable, expected policy, observed result, negative control, impact, confidence, disposition, cleanup, and next action. Keep raw credentials and unnecessary private data out of global notes.

## Chain contract
A chain must state the observed parent signal, child hypothesis, exact trust boundary, required independent proof, and combined effect. A child finding does not inherit the parent's verdict. If the child link is unverified, label the chain as a hypothesis and report only the confirmed primitive.

## Review and regression
Before report submission, map every claim to evidence, confirm the target program's duplicate/severity/reporting policy, include a relevant negative control, and describe what was not tested. Store false-positive knowledge only when a valid control or contradictory evidence explains the result; blocked or unavailable tests remain inconclusive.

## References
- https://owasp.org/www-project-web-security-testing-guide/
- https://owasp.org/www-project-api-security/
- https://docs.hackerone.com/en/articles/8475116-quality-reports
- https://bugcrowd.com/vulnerability-rating-taxonomy/
