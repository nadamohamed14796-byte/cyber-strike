---
name: target-workspace-workflow
description: "Maintain one canonical target workspace with correct artifact paths, durable evidence, and strict separation between targets"
category: methodology
version: "1.4.0"
author: "CyberStrike"
tags: [target-workspace, persistence, recon-artifacts, endpoint-inventory, evidence, artifact-management, target-isolation]
tech_stack: [web, api, infrastructure]
prerequisites:
  - "An authorized target or an explicitly supplied target workspace"
chains_with:
  - recon-master
  - attack-javascript-analysis
  - attack-finding-correlation
  - attack-bb-methodology
  - attack-evidence-hygiene
  - attack-report-writing
---

# Target Workspace and Evidence Persistence

## 1. Responsibility boundary

The shared Target Workflow Contract in `packages/cyberstrike/src/agent/prompt/methodology/target-workflow.txt` owns engagement ordering, authorization decisions, scope configuration, retries, delegation policy, and closeout. The `/recon` command template and `recon_checkpoint` own reconnaissance execution and phase state. The recon phase matrix defines canonical outputs.

This skill owns only the target-workspace contract: workspace identity, directory semantics, canonical artifact persistence, durable evidence handling, and target isolation. Do not treat it as a second orchestration workflow or copy global scope/tool-selection rules here.

## 2. Workspace identity and delegated work

- One program/engagement uses one canonical workspace root, identified by the exact workspace ID, target URL, and absolute path returned by `target_workspace`.
- The target/workspace owner initializes a missing workspace and owns any scope-manifest change. Workspace creation is storage setup, not authorization.
- A delegated specialist must reuse the exact target URL, target ID, workspace path, and scope context supplied by its caller. It must not create a second root, attach a child workspace, change scope, or invent an alternate path.
- A specialist may use `target_notes_read`, `target_note`, or `target_artifact` only when the tool is present in its live tool list and permitted. If access is denied or workspace identity is missing, return normalized evidence plus the exact blocker to the caller; do not write a parallel copy.
- Separate genuinely distinct programs/projects. Do not make one workspace per hostname, subdomain, API, endpoint, browser session, or discovered asset. A separate child workspace is allowed only when the operator explicitly requests independent investigation storage for a specific in-scope asset.

## 3. Canonical layout

The normal workspace root is `.cyberstrike/targets/<stable-slug>/` inside the active CyberStrike project. Always use the absolute path returned by `target_workspace`; never resolve it from the current shell directory or guess it.

| Location | Ownership and contents |
|---|---|
| `scope/` | Persisted authorization manifest and imported scope snapshots. Do not overwrite the generated `scope/scope.json` through the generic artifact API. |
| `assets/` | Registry for explicitly requested independent child workspaces. Normal discovery stays in the parent inventory. |
| `runs/` | Run index and resumable metadata not already owned by a dedicated checkpoint. Scripts and PID files also belong here. |
| `recon/` | Raw/structured recon evidence, request/response references, URL/parameter sidecars, concise logs, and endpoint sidecars. Logical areas such as `urls/`, `parameters/`, `requests/`, `scans/`, and `logs/` map here; they are not separate physical root folders. |
| `javascript/` | Downloaded JS/source maps, the asset manifest, captured-source index, and JS analysis graph. Keep raw assets local and secret-bearing material out of model-facing summaries. |
| `findings/` | Test matrices, tester surveys, validation evidence, finding records, and redacted evidence references. |
| `reports/` | Final recon and security reports. |
| Workspace root | Stable metadata, notes, and canonical inventories such as `subdomains.txt`, `live-hosts.txt`, `urls.txt`, `parameters.txt`, `javascript-analysis.md`, `endpoints.txt`, and `findings.md`. |

Initialization deliberately creates only `scope/`, `assets/`, and `runs/`. Before writing to a nested directory that does not yet exist, create it under the exact returned workspace path. Prefer structured target tools for canonical artifacts over shell-relative redirection. Do not create one folder or report per tool, phase, host, or asset.

Keep request/response bodies in the canonical captured-request store by default. Do not copy each capture into a standalone JSON file or paste raw headers/cookies into notes. Keep generated identity files such as `workspace.json` and `target.json` under their owning runtime API; do not edit them manually.

## 4. Canonical inventories and endpoint identity

- The recon phase matrix owns the canonical root-level inventory names and completion artifacts. Reuse those exact paths instead of creating alternative manifests or numbered copies.
- The root `endpoints.txt` and structured endpoint records are the canonical endpoint inventory. Endpoint identity is normalized origin + route template + API version; HTTP methods are separate operations nested under the endpoint.
- Merge JavaScript, observed HTTP traffic, forms, API contracts, and other sources into the same endpoint record where they describe the same endpoint identity. Preserve per-operation parameters, headers, content type, auth context, source file/request IDs, confidence, and observed-versus-static/contract provenance.
- A method seen only in captured traffic remains traffic-only evidence; do not claim that JavaScript or an API contract declared it. Do not create a separate endpoint root for each method, parameter value, or request capture.
- Use `target_endpoint` for adding or enriching canonical endpoint records when that tool is available. Do not create per-method `target_note` entries as a substitute for endpoint records.
- JavaScript collection, per-file coverage, source-map handling, and source analysis belong to `attack-javascript-analysis`; endpoint aggregation and evidence-graph updates belong to `attack-finding-correlation`. This skill only defines where their durable artifacts belong.

## 5. Artifact persistence rules

Use `target_artifact` for complete target-local text/JSON/CSV artifacts. Supply the canonical target URL, a supported logical area, and a simple filename. The tool accepts content up to 2 MB or an absolute `source_path` up to 32 MB for copying a local text file without loading its contents into model context.

- Use `area="root"` only for canonical top-level inventories required by `recon_checkpoint`; it writes directly to the workspace root, not to a folder named `root`.
- Read the tool result and preserve the exact returned absolute path, input hash (when supplied), and byte count in the relevant run/evidence record.
- Evidence artifacts are immutable by default. For a normalized inventory, read the current artifact, merge and deduplicate new observations while retaining provenance, then intentionally update the same canonical filename with `target_artifact(overwrite=true)`.
- If a canonical filename exists, inspect and merge it; do not create a suffixed or numbered alternative merely to avoid updating the original. Use unique run IDs only for genuinely distinct raw evidence or historical snapshots.
- Never overwrite reserved generated manifests, scope metadata, or runtime-owned indexes through the generic artifact tool.
- For large tool output, parse locally and persist only normalized data plus raw evidence that adds reproducibility, distinct evidence, or diagnostic value. Reuse a target-local scratch path sequentially and remove it after normalization when it is no longer needed.
- Use `target_note` for durable, target-specific technical observations only when the tool is available and its preconditions are met. A refused write is not a saved note.
- Use `target_workspace(action="record_summary")` only for verified run status, scope-file provenance, checkpoint counts, canonical output paths, and the end-of-run summary. It updates workspace notes through the durable note API; it does not replace structured artifacts or validation.
- Use `report_vulnerability` for a structured finding when the registered tool and required evidence are available. Confirm endpoint attribution and persisted scope before recording it. Keep supporting redacted evidence references under `findings/`.
- Generic shell `write` or relative file output is not the target persistence interface. Never claim an artifact is saved until the tool succeeds and the path/content is verified.

## 6. Checkpoint and supplementary run metadata

Use one authoritative state ledger per workflow:
- When a workflow has a dedicated checkpoint such as `recon_checkpoint`, that checkpoint owns phase order, phase status, and workflow completion. Do not create a second manifest that mirrors its phase states or invent new phase names/status enums.
- Add a run manifest under `runs/` only when it contributes data the authoritative checkpoint does not store, such as input hashes, tool/version/settings, source-item cursors, artifact hashes, exit codes, or detailed retry/failure evidence. Reference the existing checkpoint/run ID; do not shadow it.
- For a task without a dedicated checkpoint, use one run manifest as its state ledger rather than creating overlapping status files.

After a meaningful work unit, persist its evidence and any supported resume cursor. On interruption, resume unfinished work only; do not reset completed items or overwrite raw evidence. At closeout, reconcile planned versus processed items, canonical artifact paths and counts, failures, and remaining work. The human-readable `notes.md` is a summary, never a substitute for the structured state ledger.

Use `runs/index.json` only through its structured runtime API; the generic artifact tool reserves it.

## 7. Target isolation and sensitive data

- Never mix scope, assets, endpoints, notes, accounts, evidence, findings, or reports from separate programs/projects.
- Public research and upstream reports are hypothesis sources, not facts about the current target. Never copy their hosts, object IDs, accounts, responses, or PoCs into the target's evidence as if observed.
- Do not place live credentials, full cookies, bearer tokens, reset links, private customer data, or unnecessary personal data in ordinary notes, summaries, indexes, logs, commits, reports, or exports.
- A narrowly necessary exact value may be retained only in a private target-local evidence artifact when essential for reproduction, with source location and an explicit unverified-candidate label. Prefer keeping the value outside model-facing context and exposing only a redacted preview or fingerprint.
- `target_notes_read` returns note content to the agent/model context. Local disk storage alone does not guarantee that a value remains local to the machine; do not claim provider isolation unless the runtime/provider configuration proves it.
- Redact model-facing previews, exports, and reports; preserve the minimum information needed to reproduce the observation.

## Shared tool catalog

Tool choice and installation are outside this skill's responsibility. Consult the single shared `TOOLING_CATALOG.md` reference exposed by `community-tool-selection` when a concrete persistence/validation task needs an external executable or helper; do not reproduce its inventory here. Verify any selected local utility with `command -v <tool>` and its documented version/help flags. Prefer the structured target APIs described above over generic CLI output.

- Python CLI documentation: https://docs.python.org/3/
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/

## 8. Workspace handoff checklist

Before a delegated worker returns or a run closes, verify:
- The canonical target ID, target URL, and absolute workspace path are unchanged.
- Scope and authorization were not broadened by asset discovery.
- Normalized evidence was merged into the existing canonical artifact, with source/provenance retained.
- Distinct HTTP methods, roles, tenants, objects, and security states remain distinguishable.
- The successful tool response, exact artifact path, counts, and hashes (when available) were captured.
- Raw evidence is retained only when useful and sensitive values are redacted from summaries.
- Pending, failed, blocked, incomplete, and unprocessed items are explicit; they are not reported as complete.
- Any missing write permission, workspace identity, or prerequisite is returned to the parent as a concrete blocker.
