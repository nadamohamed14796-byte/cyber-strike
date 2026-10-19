---
name: attack-triage-validation
description: "Validate candidate findings against reproducibility, scope, root cause, and demonstrated impact"
category: "validation"
version: "1.0.0"
author: "CyberStrike contributors; adapted with upstream attribution"
tags: [triage, validation, false-positives, severity]
prerequisites:
  - "A candidate with a recorded request, response, and test context"
  - "The target scope and disclosure policy"
chains_with: [attack-bb-methodology, attack-evidence-hygiene, attack-report-writing]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/triage-validation/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
---

# Finding Triage and Validation

## 1. Purpose

Use this gate before classifying or reporting a suspected vulnerability. A scanner alert, unusual response, stack trace, missing header, or HTTP 200 is a lead—not a confirmed finding. Conclusions must match evidence and program acceptance criteria.

## 2. Seven-question gate

Answer all seven for each candidate:

1. **In scope?** Is the exact asset and test type permitted?
2. **Reproducible?** Can the behavior be repeated from a known starting state?
3. **Security boundary?** Which identity, role, tenant, origin, parser, or trust boundary is violated?
4. **Expected behavior?** What should a secure implementation do, and what supports that expectation?
5. **Observed behavior?** What response or controlled state change proves the difference?
6. **Attacker capability and impact?** What can the tested actor actually access or change?
7. **Alternatives excluded?** Were cache effects, stale sessions, ownership confusion, soft-404s, and tool artifacts considered?

If an answer is unknown, mark the candidate inconclusive and gather only the evidence needed to resolve it. If disproven, record the negative result.

## 3. Validation procedure

1. Preserve the alert and discovery context.
2. Reproduce with a minimal, low-impact request.
3. Capture a baseline from a permitted account or fixture.
4. Change one variable at a time and document it.
5. Confirm with an independent observation where practical, without increasing risk.
6. Separate root cause from visible symptom.
7. State exactly what data or action was demonstrated, for which actor and under what conditions.
8. Rate confidence separately from severity.
9. Apply the program's rubric; do not inflate impact based on hypothetical chains.
10. Redact evidence before persistence or submission.

## 4. Confidence and severity are different

| Confidence | Meaning |
|---|---|
| High | Repeatable direct evidence; setup and alternatives checked |
| Medium | Plausible behavior with a material uncertainty |
| Low | Scanner-only, inferred from metadata, or not reproduced |

Severity depends on demonstrated confidentiality, integrity, availability, privilege, or business impact and the program rubric. High confidence does not imply high severity; an unproven high-impact hypothesis is not a confirmed critical finding.

## 5. Common false positives

- HTTP 200 with a login page, generic shell, or soft-404 body.
- CORS wildcard without a demonstrated sensitive cross-origin read.
- Technology/version match without proof the vulnerable path is reachable.
- Changed identifier returning public or synthetic data.
- Timing differences caused by network jitter, caching, rate limits, or cold starts.
- A JWT that decodes but has not been accepted by the server in a security-relevant way.
- An exposed path with no sensitive content.
- An error message with no security-relevant impact.
- A result requiring out-of-scope assets, privileged credentials, or prohibited actions.

## 6. Stop and escalation rules

Stop if validation risks real data, service availability, financial transactions, account lockout, or irreversible changes. Use controlled fixtures and read-only proof where possible. Validate each link in an impact chain independently and label unproven links as hypotheses.

## 7. Triage record

Record finding ID, discovery source, scope decision, setup/role, reproduction steps, expected versus observed behavior, redaction status, root-cause hypothesis, confidence, impact, severity rationale, false-positive checks, and disposition: confirmed, rejected, inconclusive, or blocked.

## 8. CyberStrike integration contract

Verify the actual finding schema and evidence lifecycle before wiring this skill into runtime. The orchestrator must not promote a candidate to confirmed solely because a skill loaded or a scanner returned a result.

## References

- Claude-BugHunter triage validation: https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/triage-validation/SKILL.md
- Recon Skills quality baseline: https://github.com/uphiago/recon-skills
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/


## Targeted quality-loop enrichment (2026-10-19)

### Verdict consistency and false-positive persistence
For each finding, maintain distinct fields for observed signal, expected policy, reproduced behavior, confidence, demonstrated impact, alternative explanation, and final disposition. Do not auto-promote because a specialist skill ran or a scanner returned high severity. A false-positive conclusion needs a relevant control or contradictory observation that actually explains the signal; lack of access, unavailable prerequisites, unstable responses, and exhausted-safe testing are blocked/inconclusive, not false positives. Record the exact request/identity/object state tried so the false-positive store can deduplicate the same root cause without suppressing a materially different boundary. Require all chain links to have independent evidence before describing combined impact.



## Agent-executable CLI tooling, resources, and helper scripts

Use CLI tools and local scripts the agent can invoke directly. Browser UI, browser extensions, and interactive intercepting proxies are not required dependencies. Check availability/version with tool_preflight.py before depending on an executable; do not install automatically.

### Recommended tools
- http_response_diff.py — baseline/control comparison
- validate_evidence_manifest.py — evidence completeness
- jq/Python — parse triage ledger and deduplicate findings
- A local JSONL ledger for hypothesis, controls, evidence, and disposition

### Resources
- https://owasp.org/www-project-web-security-testing-guide/
- https://portswigger.net/web-security
- https://www.hackerone.com/disclosure-guidelines
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids; use official documentation for current behavior and limitations.

### Helper-script contract
For every finding, record each meaningful test condition, control, result, confidence, evidence, and disposition reason. Keep false positives with reproducible reason codes; never count a blocked or unexecuted test as passed.

Preserve original evidence separately from normalized outputs. Record tool/version, timestamps, source, confidence, errors, redaction, and stable artifact paths. Use structured output and local fixtures; never overwrite evidence silently.

### Handoff
Return actual commands and versions, evidence paths, passed/failed/inconclusive checks, false-positive reason where applicable, confidence, limitations, and next skill.
