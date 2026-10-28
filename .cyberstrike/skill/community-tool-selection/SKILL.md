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

Use `.cyberstrike/skill/TOOLING_CATALOG.md` for tool candidates by task, helper scripts, official references, availability checks, output expectations, and canonical artifact formats. Do not create or maintain another tool/source list in a skill.

## Procedure

1. State the missing evidence and the phase that owns it.
2. Check registered CyberStrike tools and existing helpers first. Inspect the actual schema/help before assuming an invocation exists.
3. Treat the active checkpoint as the work objective and artifact contract, not as a tool allowlist. Inspect registered tool schemas and existing helpers first; when the needed capability is missing or uncertain, search the connected registry for it, load a small relevant shortlist, then inspect the full schemas before invocation. If the user explicitly requires a named CLI that is missing, use `ensure_tools` for that exact tool and do not silently substitute. If the task asks for a general capability, choose the best verified available method and install a CLI only when it adds material coverage beyond the current tools/helpers. Use alternatives for a distinct evidence path, corroboration, or recovery—not to increase tool count. If a specifically required tool cannot be installed, preserve the error and mark only dependent work blocked while continuing independent work. Catalog entries are examples, not requirements.
4. For an external CLI, verify local availability/version once per runtime or binary using the catalog's preflight helper. Do not repeat successful checks while the binary is unchanged.
5. Before installation or first use, review official documentation, maintenance, licensing, platform/dependencies, package provenance, privileges, network behavior, flags, output, and rate behavior. Installation is not authorization.
6. Keep requests inside the saved program scope and policy. Use non-destructive defaults, test-owned accounts/data, controlled markers, and an explicit stop condition. Never use discovered credentials or send target secrets to third-party services.
7. Save raw evidence only when it adds provenance/debugging value, and merge normalized results into the canonical workspace inventory. Record source/tool/version, input, timestamp, outcome, exit/error status, artifact path, confidence, and limitations. Never create one output file per equivalent tool or source. Retain checkpoint order, persisted scope checks, and the explicit opt-in gate for vulnerability testing; tool-choice flexibility does not relax them.
8. Validate meaningful signals with a baseline and negative control. Tool alerts, endpoint existence, status codes, response lengths, banners, dangling DNS, or secret-like strings are leads, not findings.
9. Report actual status accurately: successful, zero results, failed, blocked, unavailable, intentionally not selected, or still pending. A missing or blocked source is never a successful empty result.

## Route to the appropriate procedure

- Recon, DNS, ports, TLS, origins, virtual hosts, URL history, parameters, and JavaScript: load the relevant `recon-*` or JavaScript skill.
- A concrete vulnerability hypothesis: load its canonical `attack-*` or OWASP WSTG skill before choosing specialist tooling.
- Source exposure, secrets, dependency/CVE, cloud, containers, CMS, CI/CD, mobile, or identity: load the relevant platform or assessment skill.
- Evidence/reporting: use evidence-hygiene, triage-validation, report-writing, and the validators listed in the canonical catalog.

## Agent-executable CLI tooling, resources, and helper scripts

Use the canonical `.cyberstrike/skill/TOOLING_CATALOG.md` for the current tool candidates and output contracts. If tool_preflight.py is available under the installed skill/catalog root, resolve its absolute path and run it once per active runtime/version; never assume `.cyberstrike/skill/scripts/` is relative to the target workspace. If it is unavailable, use `command -v` plus the tool's documented version/help check. Review official docs, flags, license, dependencies, permissions, and network behavior before installation or use. Do not install or run every catalog entry.

Official general references: [Python CLI documentation](https://docs.python.org/3/), [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/), and the [bug bounty tool discovery index](https://github.com/vavkamil/awesome-bugbounty-tools). Prefer each tool's own official project documentation for exact flags and installation details.

## Completion check

Before handing off, confirm the selected tool really ran, output and errors were inspected, artifacts were saved and verified, sensitive values are redacted, and remaining gaps have explicit reasons. Do not claim installation, execution, coverage, or vulnerability confirmation without evidence.
