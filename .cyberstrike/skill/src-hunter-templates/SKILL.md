---
name: src-hunter-templates
description: "On-demand report-submission template for findings already supported by current-target evidence."
category: reporting
tags: [src-hunter, reporting, hackerone, bug-bounty, cvss, evidence]
---

# SRC-Hunter reporting template

## When to load

Load only when a candidate finding has reproducible current-target evidence and is ready for reporting. Read `report-submission.md` and adapt its structure to the program's required format.

Replace illustrative hosts, payloads, accounts, impact assertions and timestamps with current evidence. Do not copy example PoCs blindly, claim unverified impact, or include secrets/third-party personal data. Use the returned runtime paths.

## Agent-executable CLI tooling, resources, and helper scripts

### Tools and verification
Use this reference only when a candidate finding is supported by current-target evidence and is ready for reporting. Read `report-submission.md` from this skill's returned `Base directory` and `<skill_files>`. Verify local helper availability only if actually needed, using `command -v python3` and `python3 --version`; do not install a reporting tool just to read the template. Replace every illustrative value with current evidence and redact secrets/personal data. Never claim the template was used unless its contents were read.

### Official resources
- https://www.hackerone.com/
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/nadamohamed14796-byte/src-hunter
- Shared local tooling/preflight guidance: `.cyberstrike/skill/TOOLING_CATALOG.md`.

The program's required submission format and saved evidence take precedence over this generic template.
