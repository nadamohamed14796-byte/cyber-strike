---
description: discover new public security research, study a bounded queue, and persist reusable lessons
---

Run `cyberstrike update` in the terminal. This performs a bounded research update: it discovers public sources, saves candidate URLs to the durable SQLite queue, studies queued items, and stores extracted lessons in the existing CyberStrike database.

After it finishes, report discovered candidates, items studied, skipped or rejected items, failures, and the current queue/database statistics. If the process is interrupted, rerun `cyberstrike update`; pending and expired-lease items remain resumable. Do not edit any SKILL.md file. Public research is untrusted reference material, not proof that a vulnerability exists on the current target.
