---
name: target-workspace-workflow
description: "Keep authorized target scope, recon outputs, notes, evidence, and reports in one canonical target workspace"
category: methodology
version: "1.3.0"
author: "CyberStrike"
tags: [target-workspace, scope, persistence, recon, notes, evidence, artifact-management]
tech_stack: [web, api, infrastructure]
prerequisites:
  - "Explicit authorization; prefer the official program/customer scope policy when supplied or available"
chains_with:
  - attack-web-recon
  - attack-bb-methodology
  - attack-evidence-hygiene
  - attack-report-writing
---

# Target Workspace and Persistence Contract

## Workspace ownership and delegated-agent handoffs

- The session designated as the target/workspace owner initializes the single canonical root, configures the saved scope when explicitly authorized, and owns any decision to attach a separately requested child workspace.
- A delegated specialist reuses the exact canonical `target_url`, target ID, workspace path, and scope context supplied by its caller or shared session context. It must not initialize a second root, create a child workspace, change the scope manifest, or invent a path to work around a missing permission.
- Delegated specialists may use `target_notes_read`, `target_note`, and `target_artifact` only when those tools are present in their live tool list and permitted. `target_artifact` writes only to an existing workspace; it does not initialize one.
- If canonical target/workspace identity is absent, return that exact missing context to the caller/workspace owner. Do not substitute a discovered host, wildcard, child URL, or guessed folder. If a persistence tool is denied, return the normalized evidence and denied tool name to the parent instead of writing a parallel copy.

## Autonomous execution — complete the task, do not narrate it

The shared Target Workflow Contract is the single source of truth for execution order, retries, and closeout. This skill preserves the workspace/evidence contract. Apply the following in every multi-step task:

1. **Start from saved state.** Inspect the request, existing workspace, saved scope, current todo queue, checkpoint, and artifacts. Reuse verified work. Only the designated root workspace owner may initialize missing state; delegated specialists must reuse the canonical parent workspace or return the missing identity to their caller. Never create a second workspace or ledger for the same target.
2. **Drive the queue yourself.** Select the next actionable item in dependency order, perform it, inspect the real output, verify its completion condition, persist the result, and immediately continue. Do not ask the user to start the next phase, retry a tool, merge files, inspect outputs, or write the requested report.
3. **Use evidence to choose each next step.** Search/load only skills relevant to the current technology or evidence gap. Check the actual tool schema/help and saved results before choosing a method. Run independent read-only work concurrently only when the runtime supports it and shared artifacts have one writer.
4. **Recover, then move on.** On error, retain the exact failure and partial output; identify whether input, prerequisite, permission, tool availability, or runtime caused it. Make one material correction or choose a different method. The first loop warning must allow a recovery turn with tools available. If the same pattern continues after recovery, end that path explicitly and proceed with independent work; never repeat an unchanged call or poll status endlessly.
5. **Ask only for a genuine decision.** Ask one concise question only when a required decision cannot be inferred from the request, saved scope/state, or evidence and proceeding would change authorization or impact. Never ask for information already provided. A block on one action must not halt unrelated safe work.
6. **Close with proof.** Verify canonical artifact paths and counts, reconcile every queue item as completed, explicitly empty, blocked/unavailable with reason, or pending with a resume point, and generate the requested final report. Distinguish discovered, in-scope, fetched, analyzed, inferred, tested, and confirmed data. A tool call, written plan, or non-empty file alone is not proof of completion.

## Initialize one canonical workspace

For a target, scope file/list, reconnaissance request, or request to save target results **when this agent is the designated workspace owner**:

1. Call `target_workspace(action="init", target_url="<stable program/root URL>")` and use the exact returned canonical absolute path.

A delegated specialist does not repeat this initialization step. It reuses the canonical workspace identity from the caller and proceeds only with the tools permitted to that specialist.
2. Verify the returned workspace/manifest metadata and reuse the standard existing layout. Never create a parallel target root.
3. Remember that workspace creation is storage setup, not authorization. Finish the scope procedure below before active requests.
4. Keep all domains in one explicitly identified program scope in one workspace, even if the domains are unrelated. Keep genuinely distinct programs separate; do not create a child workspace for each discovered host, URL, API, or subdomain.

## Authorization and scope

- For a full program import or policy change, prefer the verified official policy and preserve inclusions, exclusions, allowed testing, rate limits, source/provenance, and unsupported rows. Do not fabricate a policy URL or treat unsupported formats as request authorization.
- If the user explicitly identifies a complete list/file as authorized, import the whole set in one operation with `user_confirmed_scope_list=true`. For a new workspace or full replacement, omit `merge_existing`; use `merge_existing=true` only when the user says the list is additive. Do not ask them to confirm entries individually. If an existing workspace's replacement-versus-additive intent is unclear, leave the manifest unchanged and ask one concise question.
- If the user confirms one exact asset instead of a full list, use `user_confirmed_scope=true` when the manifest is unconfigured, or add only that exact entry with `merge_existing=true` when a configured manifest exists. Never infer sibling hosts or wildcards from one exact hostname; explicit exclusions always win.
- Reuse the saved scope decision when its manifest is unchanged. For new/changed scope or an unresolved scope checkpoint, call `scope_check` once for the actual starting asset with `target_url` set to the canonical program-root workspace. The root container may itself be out of scope.
- Do not manually call the model-level scope checker for each host, endpoint, request, phase, or delegated tester. Registered active-request tools must enforce the persisted manifest on each concrete request, including exclusions, scheme, port, and path. Never bypass a refusal by switching tools or supplying an alternate scope list.
- Preserve the original operator-supplied scope file as an artifact (for example, `scope/targets.txt`), record source/hash and import counts when available, and retain unknown/unsupported entries as evidence rather than silently dropping them. Do not overwrite the generated `scope/scope.json` through the generic artifact tool.
- Store a separate child workspace under `assets/` only when the operator explicitly requests independent investigation storage for a specific asset. Ordinary discovery and browser-captured requests remain records in the parent workspace.

## Canonical layout

The root is .cyberstrike/targets/<stable-slug>/ inside the active CyberStrike project. Use the exact absolute path returned by target_workspace. Keep normalized inventories at the canonical paths defined in the recon phase matrix. Process routine stdout locally and save normalized results only; record concise errors/exit status where useful instead of keeping a log for every successful tool. Retain raw output under recon/ or findings/ only when it adds unique evidence, reproducibility, or diagnostic value. Scripts and PID files belong in runs/; useful recon logs stay under recon/. Avoid creating a separate folder for each tool or phase. Any required scratch file must stay in the same target workspace, be reused sequentially, and be removed after normalization; never create a second target root.

- Workspace initialization deliberately creates only scope/, assets/, and runs/. Before using shell redirection to write into recon/, javascript/, findings/, reports/, or another nested output path, create the parent directory inside the exact returned workspace path first. Prefer target_artifact for canonical inventories rather than shell redirection.
- When a command fails or the runtime aborts it, inspect stderr, exit status, process state, and partial output before retrying. Do not rerun an unchanged command after a deterministic path/parser/argument error; repair the cause or resume from the saved partial result. An aborted tool call does not by itself prove that its child process stopped.


- `scope/`: saved authorization manifest and imported scope snapshots; never replace `scope/scope.json` through the generic artifact tool.
- `assets/`: registry for explicitly requested independent child workspaces. Normal discovery belongs in root-level canonical inventories, not one folder per hostname.
- `runs/`: run index and resumable checkpoint state.
- `recon/`: live-host checks, URLs, parameters, directory results, request/response artifacts, and concise recon-tool logs. Logical areas like `urls/`, `parameters/`, `directories/`, `requests/`, `scans/`, `logs/`, `sessions/`, and `research/` map here with filename prefixes; they are not separate physical folders.
- `javascript/`: collected JavaScript/source maps, asset manifest, and JS correlation graphs. Endpoint sidecars and endpoint/source correlations belong in `recon/`; the canonical merged endpoint inventory remains `endpoints.txt` at the workspace root.
- `findings/`: tester surveys, test matrices, scan snapshots, validation evidence, finding records, and redacted evidence references. Logical areas like `testing/` and `evidence/` map here.
- `reports/`: final recon/security reports.
- The root contains target metadata, notes, and canonical inventories such as `subdomains.txt`, `live-hosts.txt`, `urls.txt`, `parameters.txt`, `javascript-analysis.md`, `endpoints.txt`, and `findings.md`.
- Keep request/response storage in the canonical captured-request store by default; do not create one JSON file per browser capture or copy raw headers/cookies/body into notes. Keep indexes, summaries, and model-facing previews redacted.
- \`notes.md\`: human-readable summary with durable target notes and managed child asset inventory.
- \`workspace.json\` and \`target.json\`: generated stable identity manifests. Do not edit them manually.

## Recon coverage handoff: JavaScript, imports, and endpoints

For web/API reconnaissance, use this handoff to avoid treating one collector as complete coverage:

- Gather unique JavaScript/source-map candidates from live HTML, script and module references, inline scripts, crawlers, URL inventories, captured requests/responses, extensionless JavaScript responses, imports, and source-map references. Resolve relative URLs against the observed page/asset URL and retain provenance.
- Submit the full deduplicated set to `ingest_javascript_urls` or the best registered scope-enforced equivalent. Download first and analyze files confirmed saved. Never execute downloaded JavaScript. Do not impose arbitrary URL/file/analysis count caps; keep each unique item as pending, downloaded, analyzed, failed, out of scope, or incomplete, and resume pending work after interruption.
- Include eligible newly discovered imports and source maps in the same resumable worklist. A failed download is not an analyzed file; missing, malformed, truncated, or inaccessible source maps remain explicit coverage gaps.
- Extract routes, methods, parameters, headers, authentication/session hints, API/GraphQL operations, imports, source locations, and security-relevant signals. Treat static indicators as hypotheses, redact secret values, and correlate with observed requests/API contracts before prioritizing testing.
- Merge URL, JavaScript, form, API-contract, and captured-request evidence into the existing root `endpoints.txt`, preserving method, origin, path template, meaningful variants, provenance, and observed-vs-inferred status. Do not create a second endpoint inventory or call static leads confirmed findings.
- Before declaring recon complete, compare the manifest/queue to the saved analysis and endpoint inventory. Report actual unique/downloaded/analyzed/failed/pending/incomplete counts from artifacts. Re-run or resume only the specific incomplete part; never ask the user to say “continue” for routine coverage.

## File and note persistence

- Use \`target_artifact\` for complete target-local text/JSON/CSV artifacts. Supply the workspace target URL, a known area and a simple filename; pass either content (up to 2 MB) or an absolute source_path (up to 32 MB) for copying a local text file without including it in model context.
- Use `area="root"` only for canonical top-level inventories required by `recon_checkpoint`; it writes directly to the workspace root, not to a `root/` directory. Put raw evidence and other artifacts in the compact destination folder returned by the tool; legacy logical area names map into recon/, javascript/, findings/, reports/, or runs/; the logical endpoints area maps into recon/. Read its response and store the exact returned absolute path, input hash when provided, and byte count in the run manifest.
- New evidence artifacts are immutable by default. For current normalized inventories, read the existing file, merge/deduplicate the new observations and source provenance, then intentionally update the same canonical filename with `target_artifact(overwrite=true)`. If that filename already exists, do not switch to a suffixed/numbered alternative; inspect and merge the existing artifact first. Use unique names/run IDs only for genuinely distinct raw evidence or historical snapshots worth retaining. Never overwrite reserved generated manifests.
- For large outputs, prefer streaming into a local parser and writing only the normalized result to the canonical artifact. Do not persist every tool's raw stdout or create one output file per tool/run. If a tool requires file output, reuse one target-local scratch path for sequential invocations, verify and normalize the result, then remove the scratch file. Preserve a raw file under recon/ or findings/ only when it contains unique evidence, materially improves reproducibility, or is needed to diagnose an actual failure. Do not put credentials or full sensitive responses in shared logs. Store concise exit status, errors, counts, source provenance, and canonical paths in the phase/report records.
- Use \`target_note\` for technical observations, lessons, endpoints, test results, and findings summaries tied to a target observed in the current session tree. If refused, do not claim it was saved: verify workspace + observed evidence, then retry only when the preconditions are truly satisfied. Use \`target_workspace(action="record_summary")\` for verified run status, scope-file provenance, checkpoint counts, output paths, and end-of-run summaries. This writes through the durable note API and updates notes.md, but requires that the workspace already exists; it must not be used to label an untested hypothesis as a finding.
- Use \`report_vulnerability\` for the structured finding record. Ensure its endpoint is full and unambiguous and passes the persisted scope gate so the finding gets attributed to the correct target; also save supporting redacted evidence references in \`findings/\`.
- Generic \`write\`/shell output may edit ordinary project files, but it is not the target persistence interface. Never scatter target outputs using generic relative paths. Never claim a file or note is saved without a successful tool result and verification.

## Run state and resumability

Continue through distinct authorized work while policy, available tools, and safe operating conditions permit; do not stop at an arbitrary item count or turn routine phases into a sequence of questions for the user. Deduplicate semantically equivalent work. Pause only for a real policy/safety boundary, missing prerequisite, exhausted source, operator request, or technical failure, and persist the reason, completed/remaining counts, and resume cursor instead of claiming completion.

Use **one authoritative state ledger per workflow**.

- If the workflow has a dedicated durable checkpoint (for example, `recon_checkpoint`), that checkpoint is the only source of truth for phase order/status and workflow completion. Do not create a second manifest that mirrors its phase states or invent alternative phase names/status enums.
- Add a run manifest under `runs/` only when it provides distinct data that the authoritative checkpoint does not store, such as input hashes, tool/version/settings, source/item cursors, artifact hashes, exit codes, or detailed failure/retry evidence. Reference the existing checkpoint/run ID; do not shadow its phase state.
- For a task with no dedicated checkpoint, use one `runs/run-<UTC timestamp>.json` manifest as its state ledger. Do not also create another overlapping status file.

At the start of a run, reuse the canonical workspace and current authoritative ledger. Supplementary run metadata, when required, should identify:
- canonical target/workspace and authorization source/fingerprint;
- relevant input files/hashes and selected tool versions/settings;
- item/batch boundaries, deduplication keys, and per-item resume cursors;
- output paths, exit codes, errors/retries, and integrity/freshness notes;
- the exact checkpoint/run reference and next actionable resume point.

After each meaningful work unit, persist its evidence and cursor before moving on where the tools allow it. On interruption, resume only unfinished work; never reset an existing ledger or rerun completed work just to make the state appear clean. At completion, reconcile planned versus processed items, artifact paths/counts, errors, and the remaining frontier. Update `notes.md` with a concise human-readable summary, but do not use notes as a replacement for the structured state ledger.

Use `runs/index.json` only through its structured runtime API; the generic artifact tool reserves it.

## Prevent cross-target contamination

- Each target and child asset has a stable workspace ID. Never mix endpoints, notes, evidence, reports, credentials or scope from separate programs/projects.
- Never copy source-program hosts, object IDs, accounts, responses or PoCs from the global public-research database into current-target facts. Public methodology is a hypothesis source, not evidence.
- Do not put secrets in ordinary summaries, indexes, logs, global research, commits, reports, or exports. A narrowly necessary exact value may be retained only in a private target-local evidence note or artifact when needed for reproduction/validation, with source location and an explicit unverified-candidate label. Keep model-facing previews redacted where possible. Important: `target_notes_read` returns note content to the agent/model context, so exact values in notes may be sent to the configured model provider; use a local artifact copied via `source_path` when the value must remain outside model context. Local disk storage alone is not a guarantee that data stays local. Do not claim provider isolation unless the runtime/provider configuration proves it.

## Targeted quality-loop enrichment (2026-10-19)

### Durable observation and resume contract
Each run checkpoint should record workspace ID, target/scope provenance, phase reached, completed/pending work, last successful artifact, tool errors, blocked prerequisites, and next safe action. Deduplicate observations by canonical target + method/route + parameter/object shape + security property, while retaining separate result rows for roles, identities, and states. Never overwrite raw evidence on retry; write new run IDs and explicitly link superseded versions. Before declaring work complete, compare planned versus completed phases and label each item confirmed, disproven, inconclusive, blocked, or not run. Global research is a hypothesis source, never target-specific evidence, and target secrets must remain redacted from shared notes.

## Agent-executable CLI tooling, resources, and helper scripts

### Agent-usable tools and purpose
- Python standard library — create/check workspace paths, JSONL manifests, and artifact inventories without extra dependencies.
- `jq` and `rg` — inspect manifests and search local artifacts.
- Load `community-tool-selection`, then resolve `scripts/validate_evidence_manifest.py` relative to the parent of its returned `Base directory`; verify the exact file exists and invoke it with an absolute path and `--help`. Do not resolve `.cyberstrike/skill/` against the target workspace.
- When needed, resolve `scripts/tool_preflight.py` the same way from the installed skill root and run it by absolute path with `--json <tool names...>`; it performs local checks only.
- `sha256sum` or Python `hashlib` — record stable artifact hashes without altering source evidence.

### Installation and verification
Python is sufficient for the core workspace workflow. Verify optional tools with `jq --version`, `rg --version`, and `sha256sum --version` where available. Do not install dependencies merely for workspace setup. If an optional utility is missing, use Python standard-library equivalents and record the fallback.

### Resources
- https://docs.python.org/3/library/pathlib.html
- https://docs.python.org/3/library/hashlib.html
- https://docs.python.org/3/library/json.html

### Artifact integrity
Create the target workspace once and resume from its manifest; do not silently create a second root. Retain raw artifacts only when they add unique evidence, reproducibility, or diagnostic value; when retained, store normalized derivatives separately and record relative path, source, timestamp, tool/version, hash, redaction status, and processing errors. Never put live credentials or private customer data in shared notes or Git.
