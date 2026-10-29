---
name: src-hunter-compliance
description: "On-demand SRC-Hunter safety, data-handling and evidence rules to review before reporting a finding."
category: reporting
tags: [src-hunter, compliance, safety, privacy, reporting]
---

# SRC-Hunter compliance reference

## When to load

Before preparing a final vulnerability report, read `compliance.md` in full and apply the relevant handling requirements.

This reference supplements, but never replaces or broadens, CyberStrike's current scope manifest, runtime checks, program policy or safety controls. If instructions conflict, the stricter applicable policy and runtime contract take precedence. Do not claim the file was consulted unless its actual content was opened.

## Agent-executable CLI tooling, resources, and helper scripts

### Tools and verification
This is a policy and data-handling reference, not a test executor. Before a final report, read `compliance.md` from this skill's returned `Base directory` and `<skill_files>`. For local file inspection only when needed, verify Python availability with `command -v python3` and `python3 --version`; no extra tool installation is required to consult this reference. Verify that every finding claim points to persisted, reproducible current-target evidence, and redact secrets and third-party data.

### Official resources
- https://www.hackerone.com/
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/nadamohamed14796-byte/src-hunter

The saved scope, program policy, applicable safety requirements and CyberStrike runtime enforcement remain authoritative. If a reference conflicts with them, follow the stricter applicable requirement.
