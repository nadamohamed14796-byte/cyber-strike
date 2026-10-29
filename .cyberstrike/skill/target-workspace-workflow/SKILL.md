---
name: target-workspace-workflow
description: "Run a target engagement from scope setup through verified evidence and reporting in one canonical workspace"
category: methodology
version: "1.2.0"
author: "CyberStrike"
tags: [target-workspace, scope, recon, persistence, evidence, reports, resume, workflow]
tech_stack: [web, api, infrastructure]
chains_with: [attack-web-recon, attack-bb-methodology, attack-evidence-hygiene, attack-report-writing]
---

# Target Workspace Workflow

Use this skill for every multi-step target engagement. The shared Target Workflow Contract controls autonomy and recovery; this skill defines workspace state, evidence persistence, and phase handoffs. Complete routine work without asking the user to run commands or approve each phase.

## 1. Initialize or resume exactly once

- Inspect existing target state first: workspace, persisted scope, run summary, recon checkpoint, todo queue, and saved inventories.
- If no canonical workspace exists, call `target_workspace(action="init", target_url="<program/root URL>")` and use the exact returned path. Reuse it for all assets belonging to the same authorized program/root.
- Never create a second workspace for each hostname, tool, phase, or subagent. Never maintain competing progress ledgers.
- Initialization guarantees only `scope/`, `assets/`, and `runs/`. Create a missing parent directory before shell redirection into any other directory. Prefer supported artifact tools for canonical files.
- A workspace is storage and provenance, not permission to test.

## 2. Configure scope once, then reuse it

- When the user supplies a complete authorized scope list/file, import the whole list in one operation with `user_confirmed_scope_list=true`. Use `merge_existing=true` only for an additive update.
- For one explicitly confirmed asset, use `user_confirmed_scope=true` for a new scope or `merge_existing=true` to add only that asset.
- Prefer a verified official program policy when importing a program-wide scope. Preserve inclusions, exclusions, wildcards, source, and policy details.
- If persisted scope is unchanged and valid, reuse it. Revalidate only when scope is missing, changed, or unresolved; do not repeatedly ask for confirmation of the same decision.
- Scope exclusions always win. Do not infer siblings, shared-IP neighbors, certificate names, CNAME providers, or ASN ranges as authorized. Those can be leads only.
- Every actual request and redirect must be checked against current runtime scope. A loaded skill, known hostname, existing artifact, or workspace must never bypass authorization.
- A rejected request is not permission to try an unchecked wrapper. Record the reason and continue unrelated safe work.

## 3. Use one authoritative artifact map

Use `target_artifact` for canonical files, `target_note` for evidence-backed observations, `target_workspace(action="record_summary")` for the run summary, and `recon_checkpoint` for the phase ledger.

Canonical root inventories:
- `subdomains.txt`: normalized discovered hostnames, deduplicated, with source provenance kept in the supported inventory/notes.
- `live-hosts.txt`: hosts verified as live by a completed check. Do not mix failed or unprocessed hosts with confirmed live hosts.
- `urls.txt`: absolute HTTP(S) URLs gathered from crawling, captures, contracts, and other sources.
- `parameters.txt`: observed/inferred parameters with endpoint, method, location, and source when known.
- `javascript-analysis.md`: consolidated analysis and coverage/status counts for eligible downloaded JavaScript and source maps.
- `endpoints.txt`: one merged endpoint inventory derived from URLs, JavaScript, API contracts, forms, and captured requests.
- `findings.md`: only evidence-backed test outcomes/findings, with redacted supporting evidence.
- `reports/recon-final.md`: the single final recon report.

Supporting evidence areas:
- `javascript/`: JavaScript/source maps, download manifest, per-file status, and correlation artifacts.
- `recon/`: crawling/path/parameter results, request and response references, endpoint sidecars, tool settings, and useful logs.
- `findings/`: supporting test evidence where needed.
- `reports/`: final and intermediate report artifacts.
- `runs/`: run summaries and the authoritative checkpoint. Do not create duplicate status files elsewhere.

Merge into these canonical inventories; do not create alternate copies by tool name or phase. Preserve meaningful method/query variants, source attribution, partial results, and errors. Do not overwrite generated scope/workspace manifests with generic file tools. Store secrets only when the system explicitly supports protected storage; otherwise redact secret values and preserve safe fingerprints/source locations.

## 4. Run phases in dependency order

For a normal web recon engagement, reuse verified work and continue this sequence:
1. Scope and workspace foundation.
2. Asset discovery and eligible hostname normalization.
3. DNS/live-host checks and permitted service verification.
4. URL/path collection, forms, browser captures, API descriptions, and request history.
5. Parameter discovery and useful non-destructive content discovery.
6. Download and analyze every eligible JavaScript/source-map asset; resume pending work after interruption.
7. Merge and verify the canonical endpoint inventory.
8. If the request is recon-only, mark targeted testing deferred and continue. If testing was explicitly requested, wait for completed scope and endpoint prerequisites, then use relevant skills and authorized tools.
9. Verify the final report and reconcile the checkpoint/todo queue.

A checkpoint is the phase ledger, not a tool allowlist. Scope/workspace prerequisites must be completed before advancing checkpoint transitions, but a stale phase label alone must not block ordinary recon tools that enforce request-level scope. When a transition is rejected, repair the specific prerequisite before marking a phase complete.

## 5. Download and account for every eligible JavaScript asset

- Gather unique URLs from HTML, script/module tags, inline scripts, crawlers, captures, the URL inventory, extensionless JavaScript responses, imports, and source maps. Resolve relative URLs against the observed page or asset.
- Submit the full deduplicated set to `ingest_javascript_urls` or the best registered equivalent. Download first; analyze only files confirmed saved. Do not execute downloaded scripts.
- Do not impose arbitrary URL/file/analysis caps. Analyze each saved file, or use a verified resumable worker that guarantees every item receives a recorded status. Do not treat a partial queue page as full coverage.
- Record each URL as pending, downloaded, analyzed, failed, out of scope, or incomplete. A failed download is not an analyzed file. Include newly discovered eligible imports/maps and resume unfinished items after interruption.
- Extract endpoints/routes, methods, parameters, headers, auth/session hints, API/GraphQL operations, browser storage/messaging, imports, source locations, and useful security signals. Static indicators are leads, not findings; redact secret values.
- Link code-derived leads to captured requests, API descriptions, application behavior, and other evidence. Merge endpoint discoveries into root `endpoints.txt`. Report actual unique, downloaded, analyzed, failed, pending, and incomplete counts.

## 6. Load skills and companion references properly

- Keep the catalog searchable/loadable; do not preload every skill into context.
- Search by the observed technology, behavior, evidence gap, vulnerability class, tag, or CWE. Load the exact canonical skill name returned and confirm full content, not just the search snippet or outline.
- Read companion files only through paths supplied by the loaded skill. Follow `chains_with` or a prerequisite skill only when the current evidence and stated condition justify it.
- Do not repeat the same skill search or reload the same content without new evidence. If a skill is missing, search a canonical alternative and continue other useful work; report a real catalog gap only after checking alternatives.
- Skills guide methods; they never establish target scope or authorize an action.

## 7. Recover from failures without looping

For every failed action:
1. Inspect actual error text, exit status, tool metadata, process state, and partial artifacts.
2. Classify the cause: invalid input/schema, missing prerequisite, permission/scope denial, unavailable tool, transient failure, or operation failure.
3. Correct the specific input or prerequisite, or choose a materially different method. Retry an unchanged failing call only when new evidence shows it is safe and likely to work.
4. Preserve useful partial output and keep independent tasks moving.
5. Verify the successful artifact before advancing progress state.

Do not repeatedly poll the same status, rewrite identical checkpoints, reload identical skills, or rerun the same scan without a changed input. After a loop warning, switch to a different evidence-producing action or move to the next independent item. If no safe alternative remains, record the exact blocker and resume point; never fabricate completion.

## 8. Complete work only after verification

- Use one todo queue and one recon checkpoint. Mark an item complete only after its observable condition and required artifacts are verified.
- Mark verified zero-results explicitly. Keep failures, unavailable sources, pending items, and incomplete coverage distinguishable from zero results.
- Derive counts from actual saved artifacts, not intended work or tool-call counts. Distinguish discovered, in-scope, live, downloaded, analyzed, inferred, tested, and confirmed.
- Complete every safely actionable phase in this run. Do not leave the report until the end if evidence can be saved as it is produced.
- Finish with one verified `reports/recon-final.md`. Include the outcome, real counts and paths, useful evidence, source failures, limitations, and the exact resume point for remaining work. Do not call unprocessed items complete.
- Keep routine progress out of chat. Never ask “continue?” between phases; ask only for a genuinely missing decision that cannot be derived safely from current state.
