---
name: attack-bugcrowd-reporting
description: "Prepare concise, reproducible security reports aligned with Bugcrowd triage expectations"
category: "reporting"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [bugcrowd, reporting, triage, evidence, remediation]
tech_stack: [markdown, web, api]
prerequisites:
  - "A validated finding within the program's scope"
  - "Redacted evidence and program-specific submission rules"
chains_with: [attack-triage-validation, attack-evidence-hygiene, attack-report-writing]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/bugcrowd-reporting/SKILL.md"
---

# Bugcrowd Report Preparation

## When to use

Use when a finding is ready for submission to a Bugcrowd program or when an existing draft needs a quality and policy review.

## Preconditions

Confirm the affected asset is in scope, the issue is not excluded, and the evidence supports the stated impact. Follow the target program's current submission template and disclosure rules; this skill does not replace program-specific policy.

## Procedure

1. **Write a precise title.** Name the affected component and security impact without exaggerating severity.
2. **Summarize impact first.** State what an attacker can do, under which preconditions, and which trust boundary is violated.
3. **List prerequisites.** Specify required account, role, victim interaction, configuration, and attacker capabilities.
4. **Give reproducible steps.** Number steps from a clean starting state. Include only the minimum request/response evidence needed to reproduce.
5. **Separate observation from conclusion.** Quote meaningful response fields or state changes. A status code, scanner output, or version string alone is not proof.
6. **Explain impact.** Describe confidentiality, integrity, or availability consequences supported by the evidence. Do not assume maximum impact.
7. **Suggest remediation.** Recommend the control that addresses root cause, not just filtering one payload or hiding a UI control.
8. **Check evidence hygiene.** Remove cookies, API keys, personal data, internal identifiers, and unrelated user records. Never include live credentials.
9. **Review program policy.** Confirm duplicates, accepted vulnerability classes, asset scope, and disclosure constraints before submission.

## Pitfalls

- Do not claim a vulnerability from a theoretical attack chain.
- Do not include unrelated findings in one report unless program policy explicitly allows it.
- Do not use severity labels as a substitute for impact reasoning.
- Avoid large raw logs or screenshots containing sensitive data.

## Verification checklist

- [ ] A reviewer can reproduce the issue from the steps.
- [ ] The target and endpoint are in scope.
- [ ] Expected behavior and actual behavior are distinguished.
- [ ] Impact is supported by evidence.
- [ ] Evidence is redacted.
- [ ] Remediation addresses root cause.
- [ ] Severity follows the program's current policy.
