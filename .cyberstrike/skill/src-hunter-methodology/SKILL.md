---
name: src-hunter-methodology
description: "On-demand shared SRC-Hunter methodology for attack prioritization, permitted test variations, evidence discipline, control-gap hunting and timeboxing."
category: vulnerability-research
tags: [src-hunter, methodology, prioritization, evidence, control-gap]
---

# SRC-Hunter methodology references

## When to load

Load this skill only when the current evidence gap needs shared testing methodology. Read `00-index.md` first, then the one specific reference needed:
- `01-attack-priority.md` — prioritize an evidenced hypothesis.
- `02-bypass-toolkit.md` — consult only for a permitted, low-impact variation after a concrete in-scope request is blocked. Never use it to evade scope, authorization, rate limits, monitoring, or program restrictions.
- `03-evidence-discipline.md` — assess evidence quality, controls, reproducibility and false positives.
- `04-control-gap-hunting.md` — translate observed behavior into a specific missing-control hypothesis.
- `05-srctimebox-priority.md` — apply priority/timebox guidance only when relevant.

Use this skill's returned `Base directory` and `<skill_files>`. Do not preload the whole folder. CyberStrike's saved scope, program policy and runtime checks remain authoritative.

## Agent-executable CLI tooling, resources, and helper scripts

### Tools and verification
This skill is a reference router, not a tool installer or an authorization check. Read the exact methodology file from the returned `Base directory` and `<skill_files>`; do not assume the repository checkout or target workspace is the reference root. Verify any needed local helper with `command -v python3` and `python3 --version`. Do not install tools solely because a methodology mentions them; verify current availability and official documentation before use. If the needed local file is missing, record the exact blocker and do not claim it was read.

### Official resources
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/nadamohamed14796-byte/src-hunter
- Shared candidate CLI/helper catalog: `.cyberstrike/skill/TOOLING_CATALOG.md` (reference only; inspect the current runtime schema and installed tools before use).

Choose references only to resolve a concrete evidence gap. Tool selection remains dynamic, and the saved scope, policy, and runtime checks always take precedence.
