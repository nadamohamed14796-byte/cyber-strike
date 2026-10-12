---
name: bugcrowd-reporting
description: "Apply Bugcrowd-specific VRT mapping, severity-request, scope-justification, chain cross-reference, and submission hygiene after a finding is validated."
category: "process"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - bugcrowd
  - vrt
  - reporting
  - severity
  - scope
  - bug-bounty
tech_stack:
  - bugcrowd
  - markdown
  - cvss
  - vulnerability-rating-taxonomy
chains_with:
  - triage-validation
  - report-writing
  - evidence-hygiene
prerequisites: []
severity_boost:
  report-writing: "Bugcrowd VRT and severity policy complement the core report structure when the default category does not match demonstrated impact."
---

# Bugcrowd VRT and Submission Workflow

## Objective

Help a researcher choose the most accurate current VRT, justify demonstrated severity, respond to scope/impact objections with evidence, and keep each submission honest. This is a process aid, not a promise about Bugcrowd's current policy or reward amounts.

## Methodology

### Phase 1: Confirm program and target selection

Read the program's live scope, exclusions, testing policy, target list, authentication requirements, and special rules before submitting. Confirm whether the tested asset is production, QA, mobile/API, or a third-party integration. Do not infer scope from a hostname or prior submission.

### Phase 2: Choose the closest accurate VRT node

Search the current VRT by primary bug class, actual data/action affected, control bypassed, endpoint type, then the closest parent/Other category. Select the most specific accurate category; never choose a different vulnerability class solely to obtain a higher default priority. Record the VRT label and the priority the current form suggests.

### Phase 3: Evaluate a severity override from evidence

If the default under-rates the demonstrated outcome, write a short severity request at the beginning of the description. State the requested priority, exact tested impact, prerequisites, attacker privilege, user interaction, affected scope, and why the closest VRT example differs. Do not cite reward amounts unless the live program page confirms them.

### Phase 4: Handle scope or OOS concerns factually

Quote the exact relevant program clause and explain why the demonstrated condition does or does not fit it. For rate limiting, distinguish authentication from non-authentication endpoints; for enumeration, distinguish low-risk existence signals from sensitive PII; for schema disclosure, show the actual authorization/control effect. Never argue from theoretical impact or reinterpret a clear exclusion.

### Phase 5: Document dependent chains honestly

When two independent issues combine, identify each root cause and fix surface, and reference report IDs only after they exist. State each primitive's standalone impact and the end-to-end result that was actually reproduced. Do not overstate each primitive as independently critical or assume the program pays separately for each fix.

### Phase 6: Use QA and test accounts transparently

Select the target matching the actual environment and include a note when testing QA. Use program-approved test aliases/accounts where the program asks for them. Restore test state, revoke sessions, and report irreversible side effects honestly. If an account is locked or challenged, contact the program rather than creating accounts to evade the control.

### Phase 7: Prepare attachments and submit

Run triage-validation and evidence-hygiene first. Verify exact VRT, clean title, reproducible steps, expected/actual behavior, sanitized evidence, remediation, and program-specific severity. Keep all communications private and don't publicly disclose without explicit permission.

## What This Produces

- **Ready to submit:** the finding passed the triage gate, the selected VRT accurately describes the root cause, the claimed severity matches proven impact, and the required evidence is sanitized.
- **Needs review:** the VRT default looks too low, but the request must cite demonstrated impact and current program policy.
- **Not ready:** category chosen only to inflate priority, target selection is inaccurate, impact relies on a theoretical chain, or an explicit scope exclusion applies.

## Evidence Requirements

- Current program scope/policy URL and the actual tested target/environment.
- Exact current VRT label and form-suggested priority at submission time.
- Severity-request paragraph grounded in verified test account, request, response, and outcome.
- For chain findings: relevant report IDs, independent root causes/fix surfaces, and end-to-end evidence.
- Sanitized evidence and restoration/cleanup note; no live credentials, real-user PII, or public disclosure.

## Tools

- **Bugcrowd program scope and submission form:** authoritative current target and policy context.
- **Bugcrowd VRT:** choose an accurate category and observe the live suggested priority.
- **CVSS calculator:** document technical severity separately from Bugcrowd's priority taxonomy.
- **triage-validation:** confirm scope, reproduction, duplicate checks, and impact before filing.
- **evidence-hygiene:** sanitize screenshots/HARs and ensure test data is minimized.

## Bugcrowd Submission Decision Matrix

| Decision | Preferred action | Avoid |
|---|---|---|
| Exact VRT exists | Select accurate specific node | Picking a higher node that misstates root cause |
| No exact VRT | Choose the closest accurate parent/Other and explain mapping | Inventing a category |
| VRT default appears too low | Add an evidence-grounded severity request first | Requesting P1 from a primitive-only result |
| OOS objection | Quote exact clause and map proven facts to its wording | Arguing from “could be chained” |
| Chain has multiple roots | Identify independent fix surfaces and cross-reference IDs | Treating every primitive as terminal impact |
| QA tested | Choose QA target if present and explain constraints | Claiming production impact without production evidence |
| Account locked/challenged | Contact program through approved channel | Evading with new accounts, proxies, or rotating identities |
| State-changing PoC | Restore test state and disclose residual effects | Hiding or leaving changed account state |

**Severity-request starter:**

“Requested severity: [priority]. The closest accurate VRT is [current VRT label], whose current default is [shown value]. The demonstrated impact is [specific observed result] under [required role/preconditions]. This differs from the VRT's typical case because [evidence-backed reason]. I have not claimed [unverified chain step].”

## Verification and False Positives

- VRT categories/defaults and program-specific priority mapping can change; check the live form every time.
- A VRT mapping is not a guarantee of program acceptance or payout.
- Do not cite historical payout values unless current and sourced; they do not establish the severity of this finding.
- A public route, rate-limit observation, or enumeration signal does not override an explicit exclusion.
- If end-to-end impact is missing, lower the claim or continue authorized validation instead of overstating severity.
- Do not recommend evading rate limits, CAPTCHAs, lockouts, or account controls to create stronger evidence.

## References

- [uphiago/recon-skills — bugcrowd-reporting](https://github.com/uphiago/recon-skills/tree/main/redteam/bugcrowd-reporting)
- [Claude-BugHunter — bugcrowd-reporting](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/bugcrowd-reporting)
- [Bugcrowd Vulnerability Rating Taxonomy](https://bugcrowd.com/vulnerability-rating-taxonomy)
- [Bugcrowd — Disclosure and submission guidance](https://docs.bugcrowd.com/researchers/reporting-a-bug/)
