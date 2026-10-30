---
name: community-tool-selection
description: Choose and verify a fit-for-purpose external tool, API, dataset, or local helper without duplicating the canonical tool catalog.
category: information-gathering
version: "1.0.0"
author: cyberstrike-official
tags:
  - tool-selection
  - cli-tooling
  - recon
  - bug-bounty
  - tool-preflight
  - research
prerequisites:
  - recon-methodology
---

# Tool Selection

## When to load

Load this skill only when a concrete task has an evidence gap that may benefit from a native tool, external CLI, public API, local library, wordlist, or dataset. Do not load it merely to repeat workflow instructions already present in the active command.

## Single source of truth

Use the `TOOLING_CATALOG.md` companion listed in this skill's returned `<skill_files>`, reading it from this skill's returned `Base directory` rather than the target workspace. It is the one shared reference for candidate tools, APIs, local helpers, official references, availability/preflight guidance, and output expectations. It is a candidate catalog, not a tool allowlist or proof that a tool is installed. Do not copy its inventory into individual skills.

## Procedure

1. State the missing evidence and the phase that owns it.
2. Check registered CyberStrike tools and existing helpers first. Inspect the actual schema/help before assuming an invocation exists.
3. Treat the active checkpoint as the work objective and artifact contract, not as a tool allowlist. Search registered tools and inspect real capabilities. Install an exact named CLI with `ensure_tools` when the user explicitly requests that executable or the workflow genuinely depends on its specific behavior or output format. Otherwise, choose the best available native tool, helper, API, or CLI for the evidence gap; do not install a tool merely because it appears in an example. When the selected tool is absent from the catalog, inspect official upstream installation guidance and use a verifiable source. Do not silently replace an explicitly requested tool or a genuine format dependency with an equivalent. If installation is blocked, preserve the exact error and mark only dependent work blocked. The catalog contains examples, not mandatory or exhaustive assignments.
4. For an external CLI, verify its identity, path, version, and current help output once per runtime/binary version. Use `tool_preflight.py` only after resolving its actual absolute path from the installed skill/catalog root; never guess a path relative to the target workspace. If the helper is unavailable, use `command -v` plus the CLI's documented version/help flags. Do not repeat successful checks while the binary is unchanged.
5. Before installation or first use, review official documentation, maintenance, licensing, platform/dependencies, package provenance, privileges, network behavior, flags, output, and rate behavior. Installation is not authorization.
6. Keep requests inside the saved program scope and policy. Use non-destructive defaults, test-owned accounts/data, controlled markers, and an explicit stop condition. Never use discovered credentials or send target secrets to third-party services.
7. Save raw evidence only when it adds provenance/debugging value, and merge normalized results into the canonical workspace inventory. Record source/tool/version, input, timestamp, outcome, exit/error status, artifact path, confidence, and limitations. Never create one output file per equivalent tool or source. Preserve real checkpoint dependencies and status, but do not use phase order to restrict tool selection or execution. Persisted scope checks and the explicit opt-in gate for vulnerability testing remain mandatory.
8. Validate meaningful signals with a baseline and negative control. Tool alerts, endpoint existence, status codes, response lengths, banners, dangling DNS, or secret-like strings are leads, not findings.
9. Report actual status accurately: successful, zero results, failed, blocked, unavailable, intentionally not selected, or still pending. A missing or blocked source is never a successful empty result.

## Route to the appropriate procedure

- Recon, DNS, ports, TLS, origins, virtual hosts, URL history, parameters, and JavaScript: load the relevant `recon-*` or JavaScript skill.
- A concrete vulnerability hypothesis: load its canonical `attack-*` or OWASP WSTG skill before choosing specialist tooling.
- Source exposure, secrets, dependency/CVE, cloud, containers, CMS, CI/CD, mobile, or identity: load the relevant platform or assessment skill.
- Evidence/reporting: use evidence-hygiene, triage-validation, report-writing, and the validators listed in the canonical catalog.

## General references

- [Python CLI documentation](https://docs.python.org/3/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Bug bounty tool discovery index](https://github.com/vavkamil/awesome-bugbounty-tools)

Use each selected tool's own official project documentation for exact installation and flag semantics. The discovery index is a source of candidates, not proof of maintenance, compatibility, or safety.

## Completion check

Before handing off, confirm the selected tool really ran, output and errors were inspected, artifacts were saved and verified, sensitive values are redacted, and remaining gaps have explicit reasons. Do not claim installation, execution, coverage, or vulnerability confirmation without evidence.
