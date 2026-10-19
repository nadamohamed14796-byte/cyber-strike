---
name: report-writing
description: "Write concise, impact-first security reports with reproducible steps, sanitized evidence, honest severity reasoning, and concrete remediation."
category: "process"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - report-writing
  - bug-bounty
  - pentest
  - cvss
  - remediation
  - reproduction
tech_stack:
  - markdown
  - http
  - cvss
  - hackerone
  - bugcrowd
  - intigriti
  - immunefi
chains_with:
  - triage-validation
  - evidence-hygiene
prerequisites: []
severity_boost:
  evidence-hygiene: "Sanitized, reproducible evidence supports the report without leaking reusable credentials or personal data."
---

# Security Finding Report Writing

## Objective

Turn an already validated finding into a clear, reproducible report a triager or engineer can verify quickly. Do not use report language to imply impact that has not been demonstrated.

## Methodology

### Phase 1: Start with an impact-specific title and summary

Use a title shaped like “Bug class in endpoint/feature allows actor to perform demonstrated action.” The opening paragraph should state the affected asset, method/parameter, required privilege, violated boundary, and observed consequence. Avoid generic titles and discovery narratives.

### Phase 2: Write minimal exact reproduction steps

List prerequisites and synthetic/test-account roles, followed by numbered steps and a copyable sanitized HTTP request or lab command. Include necessary content type, relevant headers, and placeholders for test tokens. Keep the successful step obvious and make the procedure reproducible from a clean state.

### Phase 3: Show expected versus actual behavior

State intended policy and observed result. Include a minimal redacted response/screenshot and a negative control. For multi-step chains, label each independently verified prerequisite and the final effect; do not merge unrelated bugs or claim an unverified chain.

### Phase 4: Explain impact proportionately

Identify exactly which data, action, or identity boundary was exposed, who can exploit it, required privileges/interaction, and any scope limitation. Quantify only from authorized evidence. Do not claim mass impact, account takeover, RCE, or financial loss based solely on possibility.

### Phase 5: Choose severity transparently

Calculate CVSS using the version requested by the program and include the vector, then map separately to its severity/VRT policy. Explain privilege, interaction, scope change, confidentiality/integrity/availability, preconditions, and uncertainty. A platform's priority may differ from CVSS.

### Phase 6: Recommend a concrete fix and regression

Name the control to add or correct—server-side ownership/role check, strict type validation, parameterized query, token binding, safe output encoding, or safe storage—and a test that should fail before the fix and pass afterward. Avoid a broad generic remediation lecture.

### Phase 7: Tailor to the disclosure platform and review

Use the current platform form and policy. HackerOne commonly uses summary/details/steps/impact/fix; Bugcrowd emphasizes VRT category and severity request; Intigriti emphasizes PoC and recommendation; Immunefi emphasizes contract/protocol function, local PoC, and economic impact. Confirm current fields before submitting.

## What This Produces

- **Ready report:** one clear claim, confirmed root cause/boundary, exact reproduction, expected/actual result, demonstrated impact, defensible severity, sanitized evidence, and actionable fix.
- **Not ready:** speculative “could/may allow” language, no baseline, status-only proof, missing scope confirmation, or impact based on an unreproduced chain.

## Evidence Requirements

- Scope and asset identifier, timestamp, endpoint/method, test role, and environment.
- Sanitized request/response or PoC steps; placeholders for reusable tokens and credentials.
- Minimum impact proof, expected-versus-actual behavior, and redacted output fields.
- CVSS vector, platform mapping rationale, root cause, remediation, and regression recommendation.
- Note limitations, cleanup, and any unverified impact explicitly.

## Tools

- **Markdown editor:** maintain readable report structure and request/response blocks.
- **Burp Repeater / curl:** capture exact reproducible HTTP steps.
- **CVSS calculator:** derive a vector from observed conditions.
- **Evidence-hygiene:** check screenshots, HAR, and report body for secrets/PII.
- **Program policy/VRT/vendor docs:** align category, scope, severity, and remediation.

## Report Structure and Quality Matrix

| Section | Include | Avoid |
|---|---|---|
| Title | Bug class, endpoint/feature, actor, demonstrated impact | Vague “security issue found” |
| Summary | First-sentence impact, boundary, prerequisites | Long discovery narrative |
| Setup | Owned accounts, roles, in-scope host, test record | Real-user identifiers or secrets |
| Steps | Exact request, input, sequence, expected/actual | Missing headers or unexplained placeholders |
| Evidence | Minimal sanitized response/screenshot and negative control | Raw tokens, customer data, status-only proof |
| Impact | Specific verified action/data and scope | Hypothetical chain or invented population count |
| Severity | CVSS vector plus platform mapping rationale | Bug-class-only severity or payout assumptions |
| Remediation | Specific server-side control and regression test | “Improve security” only |
| Attachments | Sanitized, named files in approved private channel | Public links or unredacted HARs |

**Template variations:** use platform-specific fields where required. Do not assume a static template overrides current disclosure policy or submission form.

## Verification and False Positives

- Do not assert a chain step until terminal impact is reproduced in a controlled environment.
- A response status is not the same as authorization or persisted state; show a negative control.
- Keep one root cause per report unless platform guidance clearly treats dependent steps as one issue.
- Do not include real secrets, full victim PII, private tokens, or public target-identifying details.
- Severity frameworks differ; CVSS is not automatically the platform's VRT or payout priority.

## References

- [uphiago/recon-skills — report-writing](https://github.com/uphiago/recon-skills/tree/main/redteam/report-writing)
- [Claude-BugHunter — report-writing](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/report-writing)
- [FIRST CVSS Calculator](https://www.first.org/cvss/calculator/3.1)
- [OWASP Vulnerability Disclosure Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html)


## Targeted quality-loop enrichment (2026-10-19)

### Report fact/assumption split
Create a short claim ledger before writing: observed fact, artifact, inference, confidence, and omitted alternative explanations. The title and summary must name the real actor, affected route/feature, prerequisite, and demonstrated consequence. Include one direct negative control and the exact expected-versus-observed difference, then describe remediation plus a regression test tied to the root cause. Do not claim user counts, broad tenant reach, RCE, or ATO based on hypothetical siblings or chain links. If severity depends on a platform rubric, cite the applicable rule and explain the measured impact; preserve an artifact manifest with redaction and cleanup status.



## Agent-executable CLI tooling, resources, and helper scripts

Use CLI tools and local scripts the agent can invoke directly. Browser UI, browser extensions, and interactive intercepting proxies are not required dependencies. Check availability/version with tool_preflight.py before depending on an executable; do not install automatically.

### Recommended tools
- Python/jq — validate structured finding metadata
- markdownlint-cli2 — optional Markdown linting
- validate_evidence_manifest.py — evidence path checks
- git diff — inspect final report edits

### Resources
- https://www.hackerone.com/disclosure-guidelines
- https://bugcrowd.com/resources/levelup
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids; use official documentation for current behavior and limitations.

### Helper-script contract
Generate reports from verified finding records, not scanner prose. Validate reproduction steps, impact, affected asset, evidence references, remediation, and redaction; do not claim unverified impact.

Preserve original evidence separately from normalized outputs. Record tool/version, timestamps, source, confidence, errors, redaction, and stable artifact paths. Use structured output and local fixtures; never overwrite evidence silently.

### Handoff
Return actual commands and versions, evidence paths, passed/failed/inconclusive checks, false-positive reason where applicable, confidence, limitations, and next skill.
