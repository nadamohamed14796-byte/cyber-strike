---
name: src-hunter-methodology
description: "On-demand shared SRC-Hunter methodology for attack prioritization, permitted test variations, evidence discipline, control-gap hunting and timeboxing."
category: vulnerability-research
tags: [src-hunter, methodology, prioritization, evidence, control-gap]
---

# SRC-Hunter methodology references

Load this skill only when the current evidence gap needs shared testing methodology. Read `00-index.md` first, then the one specific reference needed:
- `01-attack-priority.md` — prioritize an evidenced hypothesis.
- `02-bypass-toolkit.md` — consult only for a permitted, low-impact variation after a concrete in-scope request is blocked. Never use it to evade scope, authorization, rate limits, monitoring, or program restrictions.
- `03-evidence-discipline.md` — assess evidence quality, controls, reproducibility and false positives.
- `04-control-gap-hunting.md` — translate observed behavior into a specific missing-control hypothesis.
- `05-srctimebox-priority.md` — apply priority/timebox guidance only when relevant.

Use this skill's returned `Base directory` and `<skill_files>`. Do not preload the whole folder. CyberStrike's saved scope, program policy and runtime checks remain authoritative.
