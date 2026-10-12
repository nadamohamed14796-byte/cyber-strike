---
name: triage-validation
description: "Evaluate candidate findings for scope, reproducibility, practical impact, duplicate status, evidence quality, and defensible severity before writing a report."
category: "process"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - triage
  - validation
  - false-positives
  - severity
  - reporting
  - cvss
tech_stack:
  - burp-suite
  - http
  - cvss
  - bug-bounty
chains_with:
  - evidence-hygiene
  - report-writing
  - attack-idor-automation
prerequisites: []
severity_boost:
  report-writing: "Validated findings with confirmed impact, scope, and severity can be communicated without speculative chain claims."
---

# Finding Triage and Validation Gate

## Objective

Turn a lead into a defensible finding—or explicitly discard it—before investing in a polished report. Distinguish the existence of a primitive from demonstrated attacker impact and avoid testing outside authorized boundaries.

## Methodology

### Phase 1: Gate 1: State a concrete attack path

Write down prerequisite, exact request/action, observed result, and security property violated. If no reproducible request or source-to-sink proof can be described, keep the item as a lead and gather evidence rather than asserting a vulnerability.

### Phase 2: Gate 2: Confirm scope and ownership

Re-check exact asset, path, account, test type, and program exclusions. Validate ownership for adjacent SaaS, cloud buckets, public repositories, mobile backends, and third-party identity services. If scope is ambiguous, stop active testing until clarified.

### Phase 3: Gate 3: Establish baseline and negative control

Compare normal behavior, a known-denied action, and the single altered condition. Record body/content differences, authoritative state, and role. A changed status code, error, timing spike, or public route is not enough by itself.

### Phase 4: Gate 4: Prove minimum impact safely

Use synthetic records, two accounts you control, or an isolated lab to establish the boundary. Do not retrieve real customer data, steal cookies, execute commands on production, trigger destructive actions, or bypass rate limits as proof. If policy forbids the next proof step, label impact unverified and request authorization.

### Phase 5: Gate 5: Check duplicates and intended behavior

Review program policy, vendor advisories, release notes, prior disclosed reports where public, and documented design decisions. Compare root cause and boundary, not just title. Respect private-report confidentiality and don't ask for another researcher's private report.

### Phase 6: Gate 6: Calibrate severity to facts

Separate demonstrated impact from plausible follow-on chains. Use the CVSS version requested by the program plus its own severity/VRT rules. Record privileges, interaction, scope change, confidentiality/integrity/availability, preconditions, and uncertainty. Do not infer critical impact from a vulnerability label.

### Phase 7: Gate 7: Reproduce and decide

Repeat from a clean state or fresh test session where safe, verify cleanup, and document any failed reproduction. Submit only when scope, reproduction, novelty assessment, impact, and sanitized evidence are defensible. Keep rejected leads in private notes with a reason, not as reports.

## What This Produces

- **Candidate / lead:** suspicious response, affected-version match, missing control, scan alert, or theoretical chain with an unverified step.
- **Confirmed finding:** repeatable, in-scope violation of a documented or reasonable security boundary with minimum necessary impact evidence.
- **Impact-qualified finding:** exact read/write/identity/action effect is demonstrated with controlled data and severity matches that effect.
- **Not ready:** scope is ambiguous, baseline missing, duplicate unresolved, result is status-only, or impact depends on an untested future chain.

## Evidence Requirements

- Written scope and asset ownership evidence.
- Exact request/action, baseline/control, account roles, timestamp, and reproducible result.
- Sanitized response or lab proof with the violated boundary explained.
- CVSS vector and program-specific mapping, with assumptions stated.
- Cleanup and failed/retracted reproductions recorded privately.

## Tools

- **Burp Repeater / browser DevTools:** reproduce controlled requests and browser context.
- **Vendor advisories and program policy:** validate prerequisites, scope, and known behavior.
- **CVSS calculator:** derive a vector from demonstrated facts, not desired severity.
- **Evidence-hygiene:** redact minimal PoC and attachments.
- **Public issue/report search:** check duplicates and documented behavior without exposing private reports.

## Seven-Gate Triage Matrix

| Gate | Question | Pass condition |
|---|---|---|
| 1. Attack path | What exact input/action changes behavior? | Reproducible step or source-to-sink evidence |
| 2. Scope | Is asset/action authorized? | Ownership and scope checked |
| 3. Baseline | What is normal and denied behavior? | Comparable control response and state |
| 4. Impact | What security boundary is crossed? | Minimum controlled proof, no unnecessary data |
| 5. Duplicate | Is it known or intended? | Advisory/docs/public-report check recorded |
| 6. Severity | What did the tester prove? | CVSS and program mapping tied to evidence |
| 7. Reproduction | Does it repeat from clean state? | Stable result and cleanup documented |

**False-positive controls:** 200 with identical body is not a bypass; malformed body may be rejected before authentication; reflection is not execution; DNS callback alone is not internal-data access; public metadata is not automatically disclosure; a CVE version hit is not exploitation proof; an unverified chain is not terminal impact.

## Verification and False Positives

- A malformed request may hit parser/WAF before authentication; compare a minimal well-formed unauthenticated request.
- A marker may collide with existing text or CSS/JS names; use unique canaries and inspect context.
- One timing sample, one 403-to-200 transition, or a scanner alert can be noise; compare content/state and repeat safely.
- A control may be intentionally public or documented; confirm the security contract.
- Never chase impact through credential guessing, data exfiltration, destructive changes, production RCE, or high-volume/DoS testing.

## References

- [uphiago/recon-skills — triage-validation](https://github.com/uphiago/recon-skills/tree/main/redteam/triage-validation)
- [Claude-BugHunter — triage-validation](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/triage-validation)
- [FIRST — CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [FIRST — CVSS v4.0 Specification](https://www.first.org/cvss/v4-0/specification-document)
