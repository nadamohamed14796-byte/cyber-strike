---
description: discover new public security research, study a bounded queue, and persist reusable lessons
---

Run `cyberstrike update` in the terminal. This performs a bounded global research update: it discovers public reports/writeups, saves candidate URLs to the durable SQLite queue, studies queued items, and stores reusable knowledge in the shared SQLite `report_knowledge` database. The knowledge is global—not owned by the active target—and is available to all agents through signal-driven retrieval and automatic session briefings. Target-specific observations stay in Target Memory.

Extract and preserve the maximum useful structure available from each source: vulnerability class, attack vector, impact, prerequisites, reproduction notes, PoC snippet when present, verification signals, false-positive/limitation cautions, retrieval signals/patterns, source URL/trust metadata, and a bounded excerpt. Extraction is heuristic and must be labelled as source-derived, not as verified fact. After it finishes, report discovered candidates, items studied, skipped or rejected items, failures, and the current queue/database statistics. If the process is interrupted, rerun `cyberstrike update`; pending and expired-lease items remain resumable. Do not edit any SKILL.md file. Public research is untrusted reference material, not proof that a vulnerability exists on the current target.
