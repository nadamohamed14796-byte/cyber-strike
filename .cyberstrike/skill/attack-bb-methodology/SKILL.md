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

## Practical hunting loop: hypothesis → request → decision
For each promising route, keep a lightweight note that links the observed signal to exactly one testable policy statement. Prefer replaying an already-captured request and altering one variable; do not invent a command/API because a skill mentions it.

```bash
# Adapt paths to the real target-workspace layout and available CyberStrike CLI.
find "$TARGET_WORKSPACE" -type f \\( -path '*/requests/*' -o -path '*/endpoints/*' -o -path '*/findings/*' \\) -print 2>/dev/null | sort
cyberstrike --help
```

Keep exploration open-ended while each new test is materially different and useful. Deduplicate by target + endpoint + security property + strategy, not by an arbitrary total count. Stop at decisive evidence, an exhausted set of relevant hypotheses, missing valid prerequisites, or a real program/safety boundary. Chain the strongest observed signal to its specialist skill, then triage before reporting.

## Targeted quality-loop enrichment (2026-10-19)

### Branch-selection and learning loop
At the end of each focused pass, record the most useful observation, the assumption it changed, and one next experiment that distinguishes competing explanations. When a result is interesting, cluster nearby routes in the same controller, API version, workflow, or trust boundary; test the same security property on siblings with their own baseline instead of copying an exploit blindly. Keep a negative-result note that says exactly which identity, object, method, and state were exercised, so future sessions do not repeat indistinguishable probes. Keep exploring when a new hypothesis can change the conclusion and is authorized; stop when the property is established, the meaningful branches are exhausted, or policy/safety blocks the next step.

## Coverage ledger and adaptive branch selection

For each workstream, maintain separate counts for assets discovered, endpoints normalized, hypotheses created, hypotheses attempted, findings confirmed, hypotheses disproven, blocked cases, and inconclusive cases. These counts must come from persisted records, not estimates in the model's prose.

Use a branch table to prevent repetitive hunting:

| Signal | Competing explanations | Cheapest discriminating check | Specialist handoff |
|---|---|---|---|
| 200 on protected-looking route | Public route, login shell, cached response, actual protected data | Compare anonymous and controlled authenticated baseline; inspect synthetic marker | Auth/BOLA/BFLA based on boundary |
| Input reflected in response | Safe encoding, inert reflection, HTML/JS context execution | Identify exact output context and controlled browser behavior | XSS only if execution is reachable |
| Secret-like string in JS | Public identifier, dummy value, credential, dead code | Record source and type without printing/using value; inspect approved docs/config | Secret triage/evidence hygiene |
| URL parameter accepted | Browser redirect, server-side fetch, ignored field | Correlate with actual navigation or controlled callback | Open redirect or SSRF based on observed actor |
| Header absent | Hardening gap, modern equivalent control, irrelevant response type | Inspect effective browser behavior on the relevant route | Header skill plus independently proven child impact |
| Two requests succeed | Idempotent behavior, duplicate response, duplicate side effect | Read authoritative state after a sequential control | Business logic/race only with invariant violation |

### Evidence-to-chain graph

Every cross-skill edge should store source finding/observation, exact trigger signal, child hypothesis, required independent proof, and relationship type (prerequisite, shared root cause, impact amplifier, or sibling lead). A child skill should not inherit the parent's verdict automatically. If the parent is disproven, re-evaluate the child only if it has independent evidence.

### Session closeout

Before ending a work session, report completed phases, phases blocked/partial, new and changed observations, confirmed/disproven/inconclusive hypotheses, evidence paths, cleanup, and one concrete next action. Do not say all resources were covered if a source or tool was unavailable. Preserve useful negative results and deduplicate exact retries without suppressing materially new hypotheses.

## Agent-executable CLI tooling, resources, and helper scripts

Runtime selection is dynamic: the names and commands below are optional, non-exhaustive capability examples, not a fixed toolkit or phase-to-tool assignment. For each phase or new evidence gap, search the current registered/connected tools, inspect schemas, and consider verified CLIs, suitable APIs, datasets, and local helpers. Use only candidates that add useful coverage and satisfy the actual scope, policy, and output contract; do not require or install a named candidate just because it is listed.

### Optional capability examples (non-exhaustive)
- `subfinder`, `dnsx`, `httpx`, `katana`, and `gau` — select phase-appropriate passive discovery, DNS validation, HTTP metadata, crawling, and historical URL collection.
- `jq`, `sort`, `comm`, and Python — normalize/deduplicate results while preserving provenance.
- Shared helpers under `.cyberstrike/skill/scripts/` — normalize URLs, inventory JavaScript endpoints, compare saved responses, and validate evidence manifests.

### Installation and verification
Use the official project documentation at https://docs.projectdiscovery.io/ and https://github.com/lc/gau. Verify each selected binary with its documented version/help option before use. Check optional local utilities with `command -v` and their version output. Do not install the entire tool catalog by default; install only what the active phase needs. Record missing dependencies and use a supported fallback.

### Resources
- https://owasp.org/www-project-web-security-testing-guide/
- https://docs.projectdiscovery.io/
- https://github.com/useosint/skills
- https://github.com/vavkamil/awesome-bugbounty-tools

### Evidence and handoff
Label each result passive, DNS-only, or active HTTP; preserve source, observation time, confidence, corroboration, tool/version, errors, and artifact paths. Passive discovery does not authorize active testing. Respect program scope/rates and stop if instability appears. Keep credentials, full cookies, reset links, private user data, and raw secrets out of notes and commits. Mark outcomes confirmed, disproven, or hypothetical.
