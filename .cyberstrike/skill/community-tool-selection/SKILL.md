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
prerequisites:
  - recon-methodology
---

# Tool Selection

Use this skill only when the current evidence gap genuinely requires a tool, CLI, API, helper, wordlist, or dataset that is not already available.

## Source of truth

- The Target Workflow Contract owns tool choice, installation, recovery, scope, and execution sequencing.
- TOOLING_CATALOG.md owns the shared candidate reference and reusable helper guidance.
- The active command and phase matrix own the required evidence and canonical output.
- A specialist skill owns its technique and evidence criteria.

## Procedure

1. Identify the exact missing evidence and the artifact that should change.
2. Inspect currently loaded/registered tool schemas and existing helpers. Search the connected tool registry only when the needed capability is missing or uncertain; load a small shortlist and inspect its real schemas.
3. Once a specific CLI has been selected for a distinct capability, check its real identity/version/help. If missing or incompatible, call ensure_tools for that exact CLI. For an uncatalogued CLI, review official upstream installation docs, then supply the exact package manager, package/module, executable, HTTPS documentation URL, and documented verification arguments. Do not silently replace the selected tool with an inferior alternative. Only choose a different method after exact installation genuinely fails or is blocked; record the reason and coverage trade-off.
4. Inspect actual output, errors, and artifacts after invocation. Retry only after a material correction; do not run equivalent tools just to increase counts.
5. Preserve source/tool/version, input, outcome, counts, error status, canonical path, and limitations. Merge results into the existing target inventory; do not create an output file per tool.
6. Installation is not authorization. Every request respects the saved scope, exclusions, policy, rate/impact controls, and explicit testing permissions.

## Agent-executable CLI tooling, resources, and helper scripts

Use the Target Workflow Contract for exact-tool selection, installation, verification, and recovery. Use `.cyberstrike/skill/TOOLING_CATALOG.md` as the one shared capability reference; do not duplicate its tool list here.

For a selected CLI, verify with `command -v TOOL` and the CLI's documented `--version`/help syntax. If it is missing, call `ensure_tools` for that exact CLI. For uncatalogued tools, review official upstream instructions and pass the verified package-manager method, package, executable, HTTPS source, and version/help arguments; do not silently substitute a different tool.

Official resources: https://owasp.org/www-project-web-security-testing-guide/ and the selected tool's official upstream documentation.

## Route by evidence

Load the relevant recon/JavaScript or attack skill only when the observation supports it. A catalog entry or tool alert is a lead, not proof that an action ran or a vulnerability exists.
