---
name: target-workspace-workflow
description: "Keep scope, evidence, notes, and reports in one target workspace"
category: methodology
version: "1.1.0"
author: "CyberStrike"
tags: [target-workspace, scope, recon, persistence, evidence, reports]
tech_stack: [web, api, infrastructure]
chains_with: [attack-web-recon, attack-bb-methodology, attack-evidence-hygiene, attack-report-writing]
---

# Target Workspace — Quick Rules

## 1. Initialize or resume

- Call `target_workspace(action="init", target_url="<program/root URL>")` and use the exact returned path.
- Reuse one workspace for the whole program. Do not create a workspace for every host or create a second progress ledger.
- A workspace is storage, not permission to test.

## 2. Configure scope once

- For a supplied complete scope list/file, import the whole list in one call with `user_confirmed_scope_list=true` when the user confirms it is authorized. Use `merge_existing=true` only for an additive update.
- For one confirmed asset, use `user_confirmed_scope=true` for an unconfigured scope or `merge_existing=true` to add that exact asset.
- Prefer a verified official policy for a full program import. Preserve exclusions and source details. Never infer sibling hosts or widen scope.
- Reuse the saved decision while scope is unchanged. Validate new or changed scope once. Active-request tools must still check each URL and redirect.

## 3. Save to the canonical path

- Use `target_artifact` for target files, `target_note` for evidence-backed observations, `target_workspace(action="record_summary")` for the run summary, and `recon_checkpoint` for recon phase state.
- Canonical inventories live at the workspace root: `subdomains.txt`, `live-hosts.txt`, `urls.txt`, `parameters.txt`, `javascript-analysis.md`, `endpoints.txt`, and `findings.md`. The final recon report is `reports/recon-final.md`.
- Keep JavaScript/source maps and their manifest under `javascript/`; supporting requests, endpoint details, and recon logs belong under `recon/`; test evidence under `findings/`; reports under `reports/`.
- Initialization guarantees only `scope/`, `assets/`, and `runs/`. Create a missing destination directory before shell redirection. Do not invent another workspace root or a folder per tool/phase.
- Merge and deduplicate existing canonical inventories. Preserve useful provenance, errors, and partial results. Do not overwrite generated scope/workspace manifests with generic file tools.

## 4. Resume and finish

- Use the existing `recon_checkpoint` as the single phase ledger. Complete a phase only after its real operation and required artifacts are verified. Repair rejected checkpoint updates before advancing dependent phases.
- Inspect a failed command's error, exit status, process state, and partial output. Fix the cause or change method; do not repeat an unchanged failure or start duplicate long-running work.
- Continue useful independent work. Do not claim downloaded/analyzed/tested/confirmed unless the saved evidence proves it. Keep counts tied to actual artifacts and explicitly label zero results, incomplete work, and blockers.
- Finish with one verified report and an exact resume point for anything unresolved. Keep credentials and secret values out of notes, logs, and reports.
