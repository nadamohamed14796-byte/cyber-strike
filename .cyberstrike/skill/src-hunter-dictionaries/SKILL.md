---
name: src-hunter-dictionaries
description: "Conditional component-fingerprint and default-credential references for matching evidence on in-scope targets."
category: vulnerability-research
tags: [src-hunter, dictionaries, fingerprint, default-credentials, middleware]
---

# SRC-Hunter dictionaries

## When to load

Load this skill only after target evidence matches a component or configuration pattern. Read `00-index.md` and then the smallest relevant reference:
- `chinese-srcfingerprints.md` for observed component fingerprints.
- `default-credentials-cn.md` only when the program permits a narrowly targeted default-credential check.

Do not spray credentials, test unrelated hosts, or treat a listed default as permission. Use the returned runtime paths to open the exact file.

## Agent-executable CLI tooling, resources, and helper scripts

### Tools and verification
These dictionaries support matching observed fingerprints and tightly scoped configuration checks; they are not a list to test blindly. Read only the relevant file from the returned `Base directory` and `<skill_files>`. For local text inspection, verify Python availability with `command -v python3` and `python3 --version`. Do not install scanners or spray credentials; a dictionary entry does not prove a service is vulnerable or permit authentication attempts. Check the saved scope and program rules before any network request.

### Official resources
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/nadamohamed14796-byte/src-hunter
- Shared tool availability/preflight guidance: `.cyberstrike/skill/TOOLING_CATALOG.md`.

Use verified observations and version evidence, not fingerprints or listed defaults alone, to support a finding.
