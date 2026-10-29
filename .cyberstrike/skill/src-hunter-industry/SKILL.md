---
name: src-hunter-industry
description: "Conditional industry-specific SRC-Hunter references for banking/finance and telecom/ISP targets."
category: vulnerability-research
tags: [src-hunter, industry, banking, finance, telecom, isp]
---

# SRC-Hunter industry references

## When to load

Load this skill only when the authorized target's industry or observed architecture makes one vertical playbook relevant. Read `00-index.md` first, then only the matching file:
- `banking-finance.md` for in-scope banking, payment or financial workflows.
- `telecom-isp.md` for in-scope telecom, ISP, BOSS or carrier workflows.

Use this skill's returned `Base directory` and `<skill_files>`. These references help prioritize hypotheses; they do not authorize tests or expand the saved scope.

## Agent-executable CLI tooling, resources, and helper scripts

### Tools and verification
The industry playbooks are read-only references for hypothesis selection, not an operational scanner or permission to test. Read only the matching vertical file using the returned `Base directory` and `<skill_files>`. Verify a required local helper with `command -v python3` and `python3 --version`; do not install an industry toolset simply because the reference mentions it. Before any target interaction, verify the asset and exact action are within the saved scope and program policy.

### Official resources
- https://owasp.org/www-project-web-security-testing-guide/
- https://owasp.org/www-project-application-security-verification-standard/
- https://github.com/nadamohamed14796-byte/src-hunter
- Shared capability examples and preflight guidance: the `TOOLING_CATALOG.md` companion listed in `community-tool-selection`'s returned `<skill_files>` (read it using that skill's returned `Base directory`; do not resolve against the target workspace).

Use the smallest relevant reference. If the target's industry is uncertain or outside the approved scope, do not apply a vertical playbook by assumption.
