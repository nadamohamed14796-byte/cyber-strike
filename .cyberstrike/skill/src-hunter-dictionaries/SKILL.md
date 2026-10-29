---
name: src-hunter-dictionaries
description: "Conditional component-fingerprint and default-credential references for matching evidence on in-scope targets."
category: vulnerability-research
tags: [src-hunter, dictionaries, fingerprint, default-credentials, middleware]
---

# SRC-Hunter dictionaries

Load this skill only after target evidence matches a component or configuration pattern. Read `00-index.md` and then the smallest relevant reference:
- `chinese-srcfingerprints.md` for observed component fingerprints.
- `default-credentials-cn.md` only when the program permits a narrowly targeted default-credential check.

Do not spray credentials, test unrelated hosts, or treat a listed default as permission. Use the returned runtime paths to open the exact file.
