---
name: attack-bb-methodology
description: "Plan focused, evidence-led bug bounty work and route findings to relevant skills"
category: "methodology"
version: "1.0.0"
author: "CyberStrike contributors; adapted with upstream attribution"
tags: [bug-bounty, workflow, prioritization, scope, triage]
tech_stack: [web, api, infrastructure]
prerequisites:
  - "Written authorization and defined engagement type"
  - "Program scope, exclusions, and testing policy"
chains_with:
  - attack-web-recon
  - attack-idor-automation
  - attack-triage-validation
  - attack-evidence-hygiene
  - attack-report-writing
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/bb-methodology/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
---

# Bug Bounty Methodology

## 1. Purpose

Decide what to test, why it matters, when to change direction, and what evidence is needed before calling a behavior a vulnerability. The goal is to demonstrate reproducible security impact while respecting scope—not to generate the most requests.

## 2. Confirm engagement mode

Before active testing, record one:
- **Bug bounty / VDP:** report issues that satisfy the program policy and demonstrate security impact.
- **Authorized penetration test:** follow the signed statement of work and rules of engagement.
- **Red-team assessment:** include observations agreed with the client.
- **Lab / CTF:** stay within the lab's permitted environment.

If mode, ownership, or scope is ambiguous, stop and ask. Public reachability is not permission.

## 3. Session contract

Write down:
1. Target and scope: exact domains, apps, API hosts, exclusions, and permitted test types.
2. Objective: the feature or trust boundary and security property being tested.
3. Hypothesis: the behavior that might violate the expected rule.
4. Evidence bar: what observation would prove or disprove the hypothesis.
5. Stop conditions: rate limits, instability, real user data, unexpected state changes, and policy restrictions.

Choose one or two related test classes per focused session. Keep unverified ideas in a queue rather than repeating probes without a decision-changing reason.

## 4. Non-linear workflow

### Phase A — Reconnaissance
Identify in-scope assets, technologies, and exposed services. Prefer passive sources first; use active discovery only when permitted. Record provenance and confidence.

### Phase B — Map the application
Map routes, API operations, parameters, authentication context, roles, tenant boundaries, and important workflows. Separate observed facts from assumptions.

### Phase C — Form a hypothesis
For each candidate, state the expected rule, boundary to vary, safe test fixture, expected secure behavior, and observable proof.

### Phase D — Validate safely
Change one variable at a time. Capture a baseline, test with controlled identities or disposable objects, compare results, and repeat to rule out transient behavior.

### Phase E — Triage and report
Apply attack-triage-validation, redact artifacts with attack-evidence-hygiene, and draft the report with attack-report-writing. A newly discovered endpoint returns to mapping; a fix should trigger a scoped retest.

## 5. Prioritization

Rank candidates by exposure, trust boundary, demonstrated impact, evidence quality, cost, and risk. Do not prioritize solely by CVE age, product name, scanner count, or an unverified severity label.

## 6. Decision log

For each test, record the hypothesis, scope basis, endpoint, test identity/object, baseline, input change, result, evidence location, conclusion, and next action. Use these outcomes: confirmed, disproven, inconclusive, or blocked.

A negative result is meaningful only when the test exercised the relevant boundary and the observation was interpretable.

## 7. Stop conditions

Stop and reassess if scope is unclear, real third-party data appears, a test may send messages or move money/delete records/change access, service instability occurs, or a program restriction is reached.

## 8. CyberStrike integration contract

This document describes decision logic, not a claim that a runtime command exists. Verify the skill loader, tool registry, scope resolver, evidence store, and finding schema before automating. Skills must not bypass scope enforcement.

## References

- Claude-BugHunter methodology: https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/bb-methodology/SKILL.md
- Recon Skills: https://github.com/uphiago/recon-skills
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/
