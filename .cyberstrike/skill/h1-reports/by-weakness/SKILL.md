---
name: hackerone-disclosed-reports
description: On-demand router for the local HackerOne disclosed High/Critical report corpus. Load when an evidence-backed hypothesis benefits from a comparable root-cause or impact pattern; read only the matching weakness report file.
category: vulnerability-research
tags: [hackerone, disclosed-reports, bug-bounty, idor, injection, ssrf, business-logic, authentication, authorization]
---

# Local HackerOne disclosed-report corpus

Use this skill's returned **Base directory for this skill** and `<skill_files>` list. Read `index.md` from that base directory to route the current hypothesis, then read only the relevant weakness file(s) listed there. Do not assume a repo-relative `.cyberstrike/` path exists in the installed runtime, and do not load the full corpus.

These are historical examples, not proof about the current target. Never copy their finding claims or use them as permission. Extract a testable root-cause hypothesis, then validate it with current in-scope traffic, controlled identities, and minimum-impact evidence. Redact secrets and personal data. The four files previously sanitized by repository secret scanning contain redacted secret-like strings and are not byte-for-byte copies of the source.
