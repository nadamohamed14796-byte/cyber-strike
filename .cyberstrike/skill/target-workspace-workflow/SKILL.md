---
name: target-workspace-workflow
description: "Keep authorized target scope, recon outputs, notes, evidence, and reports in one canonical target workspace"
category: methodology
version: "1.0.0"
author: "CyberStrike"
tags: [target-workspace, scope, persistence, recon, notes, evidence, artifact-management]
tech_stack: [web, api, infrastructure]
prerequisites:
  - "Explicit authorization and the official program/customer scope policy"
chains_with:
  - attack-web-recon
  - attack-bb-methodology
  - attack-evidence-hygiene
  - attack-report-writing
---

# Target Workspace and Persistence Contract

## Mandatory initialization

When the user supplies a target, a scope file, a list of domains/subdomains, a recon/hunting objective, or asks to save target results:

1. Call \`target_workspace(action="init", target_url="<stable root/program URL>")\` before starting recon or active testing.
2. Record the exact canonical absolute workspace path returned by the tool. It is the only default root for all target-specific output in this engagement.
3. Verify the paths in the tool result. Do not assume a directory exists because it appeared in a plan or because another tool printed a success-looking message.
4. Workspace creation is bookkeeping only, not authorization. Reuse the configured manifest for unchanged scope. For a policy import, prefer verified official policy provenance. If the user explicitly confirms one exact asset, accept that without requesting a policy link: configure it with user_confirmed_scope=true when no manifest exists, or add only that exact asset with merge_existing=true when a configured manifest exists. If the user explicitly identifies a complete supplied scope file/list as the authorized list, import all entries in one operation with user_confirmed_scope_list=true; do not ask them to approve entries one by one. Omit merge_existing when the supplied list is the complete replacement; use it only when the user says the list is additive. If a verified HTTPS policy reference exists, preserve it. Otherwise record the exact confirmation provenance rather than fabricating a URL. Exclusions always remain authoritative; never infer siblings that were not supplied. Verify the saved result and record provenance in target notes.

## Authorization and scope

- Review the official program/customer policy, scope inclusions, exclusions, allowed test types, and rate limits.
- For a full scope import, prefer verified official policy provenance when available. If the user explicitly identifies the supplied complete list/file as the authorized scope, process the entire list together with user_confirmed_scope_list=true; never require a separate confirmation for every domain. For a new workspace, configure that complete set in one call; on an existing workspace, use merge_existing=true only for an additive list and omit it for an explicitly intended full replacement. If the user confirms one exact asset instead, reuse an already-authorizing manifest or add only that asset with merge_existing=true; when no manifest exists use user_confirmed_scope=true. Do not demand a policy URL or repeated proof after clear confirmation. Preserve the supplied entries, provenance and exclusions, and never infer any sibling host or wildcard not actually supplied.
- Never demand a policy URL, screenshot, citation, or repeated proof after the user explicitly confirms an exact asset. During setup, call scope_check once for the actual starting asset with target_url set to the canonical program-root workspace; the root hostname may itself be outside scope. Do not manually check every discovered URL, endpoint, request, phase, or delegated tester. Active tools enforce the persisted scope on each concrete request, and exclusions always win.
- Store an original operator-supplied scope file as a root-workspace artifact, such as \`scope/targets.txt\`. For a local input file, call \`target_artifact\` with \`source_path\` and the destination area/filename; this preserves large files without loading every line into model context and returns the source SHA-256. Do not overwrite \`scope/scope.json\`, which is the authoritative generated authorization manifest.
- If the scope is enormous (tens/hundreds of thousands of hosts), preserve the raw input file, process bounded chunks/streams, and maintain counts/checkpoints. Keep all discovery inventories in the single canonical root workspace. Do not create a child workspace for each discovered, live, or browser-observed host.
- Use the operator-provided program/root as the canonical workspace for ordinary recon. Record discovered origins in the root inventories and preserve their source/provenance; do not call \`attach_asset\` or \`registerObservedAsset\` for ordinary discovery or request capture. A separate child workspace is allowed only when the operator explicitly requests independent investigation storage for a specific asset.

## Canonical layout

The root is .cyberstrike/targets/<stable-slug>/ inside the active CyberStrike project. Use the exact absolute path returned by target_workspace. Create every output directly in its final target-local area from the start: do not create a target artifact in /tmp, the shell current directory, /root/targets, the project root, or another external folder and then copy it back. Save scripts and run manifests under runs/, tool stdout/stderr under logs/, raw tool outputs under scans/ or the relevant area, and normalized inventories under assets/, urls/, parameters/, javascript/, or endpoints/. Temporary scratch files must also live under the same target workspace and be removed after use; never create a second target root.

- \`scope/\`: saved authorization manifest and input scope snapshots (never replace \`scope/scope.json\` through the generic artifact tool).
- \`assets/\`: optional registry for explicitly requested independent child workspaces. The normal discovery inventory belongs in the root-level canonical files, not one directory per hostname.
- \`recon/\`, \`urls/\`, \`endpoints/\`, \`javascript/\`: reconnaissance inventory, live assets, URL/API endpoints, JS analysis.
- \`requests/\`: request/response references and correlation metadata. Keep ordinary indexes, summaries, and model-facing previews redacted. If an exact secret-like value is essential to reproduce or validate a finding, preserve it only in a clearly labeled private target-local evidence artifact with its source/location and candidate status; never place it in shared summaries, reports, commits, global research, or external exports.
- \`testing/\`: hypotheses, test matrices, verification outcomes, and negative results.
- \`findings/\`, \`evidence/\`, \`reports/\`: finding references, redacted evidence indexes, and report drafts.
- \`scans/\`, \`runs/\`, \`logs/\`, \`sessions/\`: resumability, tool manifests, output logs, and safe session references.
- \`research/\`: target-specific hypotheses/observations only. General public writeups and methodology stay in the global research database.
- \`notes.md\`: human-readable summary with durable target notes and managed child asset inventory.
- \`workspace.json\` and \`target.json\`: generated stable identity manifests. Do not edit them manually.

## File and note persistence

- Use \`target_artifact\` for complete target-local text/JSON/CSV artifacts. Supply the workspace target URL, a known area and a simple filename; pass either content (up to 2 MB) or an absolute source_path (up to 32 MB) for copying a local text file without including it in model context. Read its response and store the exact returned absolute path, input hash when provided, and byte count in the run manifest.
- New artifacts are immutable by default. Use \`overwrite=true\` only for an intentional replacement of a file that is not a reserved generated manifest. Prefer unique names or run IDs for evidence so retries cannot silently replace prior data.
- For binary or large tool outputs, set the external tool output option to the exact final path inside the workspace and immediately verify exit status, file existence, size, and format. Do not write to an external temporary path and copy later. If a tool cannot write directly to a path, stream raw output into scans/ or logs/ inside the target workspace and normalize a separate result under the proper inventory folder. Keep full raw data on disk and only summary counts/paths/errors in model context; use bounded stdout only for genuinely small outputs.
- Use \`target_note\` for technical observations, lessons, endpoints, test results, and findings summaries tied to a target observed in the current session tree. If refused, do not claim it was saved: verify workspace + observed evidence, then retry only when the preconditions are truly satisfied. Use \`target_workspace(action="record_summary")\` for verified run status, scope-file provenance, checkpoint counts, output paths, and end-of-run summaries. This writes through the durable note API and updates notes.md, but requires that the workspace already exists; it must not be used to label an untested hypothesis as a finding.
- Use \`report_vulnerability\` for the structured finding record. Ensure its endpoint is full and unambiguous and passes the persisted scope gate so the finding gets attributed to the correct target; also save supporting redacted evidence references in \`evidence/\`.
- Generic \`write\`/shell output may edit ordinary project files, but it is not the target persistence interface. Never scatter target outputs using generic relative paths. Never claim a file or note is saved without a successful tool result and verification.

## Work continuation and non-arbitrary completion
Do not stop because a fixed number of endpoints, files, hypotheses, or stages has been reached. Continue through all distinct authorized work items while the program policy, available tools, and safe operating conditions permit. Deduplicate semantically equivalent work; stop or pause only for a real policy/safety boundary, missing prerequisite, exhausted source, operator request, or technical failure. If paused, persist the exact reason, completed/remaining counts, and resume cursor rather than labeling the run complete.

## Run state and resumability

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
- `python3 .cyberstrike/skill/scripts/validate_evidence_manifest.py --help` — inspect the actual evidence-manifest validator interface before use.
- `python3 .cyberstrike/skill/scripts/tool_preflight.py --json <tool names...>` — verify selected local command availability/version without target traffic.
- `sha256sum` or Python `hashlib` — record stable artifact hashes without altering source evidence.

### Installation and verification
Python is sufficient for the core workspace workflow. Verify optional tools with `jq --version`, `rg --version`, and `sha256sum --version` where available. Do not install dependencies merely for workspace setup. If an optional utility is missing, use Python standard-library equivalents and record the fallback.

### Resources
- https://docs.python.org/3/library/pathlib.html
- https://docs.python.org/3/library/hashlib.html
- https://docs.python.org/3/library/json.html

### Artifact integrity
Create the target workspace once and resume from its manifest; do not silently create a second root. Preserve raw artifacts, store normalized derivatives separately, and record relative path, source, timestamp, tool/version, hash, redaction status, and processing errors. Never put live credentials or private customer data in shared notes or Git.
