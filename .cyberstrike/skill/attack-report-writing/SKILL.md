---
name: attack-report-writing
description: "Write concise vulnerability reports tied to verified impact and program requirements"
category: "reporting"
version: "1.0.0"
author: "CyberStrike contributors; adapted with upstream attribution"
tags: [reporting, bug-bounty, impact, remediation]
prerequisites:
  - "A candidate that passed attack-triage-validation"
  - "Evidence reviewed by attack-evidence-hygiene"
chains_with: [attack-triage-validation, attack-evidence-hygiene, attack-bb-methodology]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/report-writing/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
---

# Security Finding Report Writing

## 1. Rule: report what was demonstrated

The first paragraph should state the affected feature, attacker prerequisites, and proven impact. Separate observed facts from hypotheses. Do not claim account takeover, broad data exposure, or privilege escalation unless the evidence proves it.

## 2. Recommended structure

### Title
Use: [Vulnerability class] in [endpoint/feature] allows [actor] to [demonstrated impact]. Avoid vague titles or unproven severity claims.

### Summary
In two to four sentences, explain what is vulnerable, who can exploit it, required access, what can be read/changed/executed, and which security boundary is violated.

### Preconditions
List only required setup: account role, test object, feature state, and user interaction.

### Steps to reproduce
1. Start from a clean authorized test state.
2. Identify the controlled account/object and role.
3. Provide sanitized HTTP requests or exact UI steps.
4. Include the observed response or state.
5. State the expected secure behavior.
6. Include cleanup steps for disposable objects.

### Impact
Describe concrete confidentiality, integrity, availability, privilege, or business-process consequences. Quantify only what was measured. Label broader untested impact as a hypothesis and do not base severity on it.

### Remediation
Recommend a root-cause fix, such as server-side object authorization, ownership/tenant checks, strict schema validation, safe state transitions, or consistent authorization across alternate endpoints. Tailor it to the demonstrated root cause.

### Evidence
Reference the redacted request/response or screenshot and state what it proves. Do not attach raw tokens, unrelated records, or unredacted HAR files.

## 3. Severity discipline

Follow the program's severity rubric first. If CVSS is requested, select metrics based on demonstrated prerequisites and impact, and include the vector and rationale. Do not use a generic severity table as a substitute for program rules.

Do not equate HTTP status with severity, assume a missing header is exploitable, claim a theoretical chain as demonstrated, count users without measuring safely, or call an issue critical just because that class can sometimes be critical.

## 4. Quality gate

- [ ] The finding passed the validation gate.
- [ ] The title names the actual endpoint/feature and impact.
- [ ] The first paragraph explains demonstrated impact.
- [ ] Steps are reproducible from a fresh authorized state.
- [ ] Expected and actual behavior are explicit.
- [ ] Evidence is redacted and minimally sufficient.
- [ ] Root cause and remediation are specific.
- [ ] Severity matches program policy and observed impact.
- [ ] No credentials, secrets, or unrelated personal data remain.
- [ ] Every claim can be traced to evidence.

## 5. Platform-specific formatting

Use the destination program's required template and fields. HackerOne, Bugcrowd, Intigriti, Immunefi, and client reports may differ. Do not assume a report accepted by one platform is suitable for another.

## 6. CyberStrike integration contract

The skill should consume a validated finding and references to redacted artifacts, not raw credentials. Verify the actual finding schema, report generator, platform adapters, and storage contract before wiring it into runtime. This document does not claim those integrations already exist.

## References

- Claude-BugHunter report writing: https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/report-writing/SKILL.md
- Recon Skills: https://github.com/uphiago/recon-skills
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/


## Targeted quality-loop enrichment (2026-10-19)

### Evidence-to-claim traceability
Create a claim map before drafting: each sentence about access, affected data/action, prerequisites, and scale must point to one sanitized artifact or be labeled as inference. Keep the primary finding focused on one root cause and one end-to-end impact path; mention sibling routes only when independently reproduced, and avoid combining unrelated defects into an inflated severity. Include a direct negative control, setup/reset instructions, observed versus expected behavior, role/tenant context, remediation, and a regression test. If broader impact would require untested assumptions, state that limitation instead of filling it in. Check the target program's duplicate policy and disclosure template before submission.


## Evidence-backed report skeleton

Use this as a draft structure, not a replacement for the destination program's template.

- **Finding ID / root-cause key:** stable local identifiers only.
- **Title:** class + exact feature + demonstrated consequence.
- **Affected asset and endpoint:** normalized route/method/version; no secrets.
- **Scope and prerequisites:** authorization basis, controlled role/tenant, required user action.
- **Expected invariant:** the exact rule that should hold and its source.
- **Reproduction:** baseline, one changed condition, observed result, independent read-back, negative control.
- **Evidence map:** claim → sanitized artifact reference → what the artifact proves.
- **Demonstrated impact:** only the confirmed data/action/permission boundary and scale actually measured.
- **Not demonstrated:** plausible but untested consequences and unavailable prerequisites.
- **Root cause:** confirmed code/config defect or explicitly labeled hypothesis.
- **Remediation:** specific server-side control and regression test.
- **Cleanup:** restored fixture, revoked test session/token, and any remaining state.
- **Program formatting:** required severity, duplicate, disclosure, and attachment rules.

### Claim-level review

Before finalizing, label each sentence internally as OBSERVED, INFERRED, or RECOMMENDED. Every OBSERVED claim needs an artifact. Every INFERRED claim must be phrased as a hypothesis with assumptions. RECOMMENDED content should address the root cause without claiming a fix has already been applied.

### Regression handoff

Provide a compact test case with setup, expected result, actual pre-fix result, post-fix expected result, and cleanup. Avoid using live credentials in sample requests; replace them with placeholders and redact cookies, tokens, personal fields, and sensitive response bodies. Do not attach an entire HAR when a minimal sanitized request pair proves the issue.
