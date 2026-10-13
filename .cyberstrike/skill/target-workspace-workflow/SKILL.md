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
4. Workspace creation is bookkeeping only. It is not authorization. If scope is not configured, inspect the official policy and explicitly configure it; otherwise stop active testing.

## Authorization and scope

- Review the official program/customer policy, scope inclusions, exclusions, allowed test types, and rate limits.
- Only after that review, call \`target_workspace(action="configure_scope", target_url=..., include=[...], exclude=[...], authorization_source=..., authorization_reference="https://...")\`.
- Never guess a wildcard or treat all discovered subdomains as authorized. Exclusions win. Call \`scope_check\` with \`target_url\` before active requests and fail closed on missing, ambiguous, invalid, or unconfigured scope.
- Store an original operator-supplied scope file as a root-workspace artifact, such as \`scope/targets.txt\`. Do not overwrite \`scope/scope.json\`, which is the authoritative generated authorization manifest.
- If the scope is enormous (tens/hundreds of thousands of hosts), do not dump the whole list into model context and do not pre-create an empty workspace for every host. Preserve the raw input file, process bounded chunks/streams, maintain counts and checkpoints, and create nested child workspaces as individual hosts are validated and worked.
- Use the operator-provided root domain/program as the parent workspace key. For an authorized child origin, call \`target_workspace(action="attach_asset", parent_target_url=..., asset_url="https://child.example", asset_type="subdomain")\`. The core API verifies that saved parent and ancestor scopes authorize the child and nests it under the parent's \`assets/\`.

## Canonical layout

The root is \`.cyberstrike/targets/<stable-slug>/\` inside the active CyberStrike project. Do not redirect output into \`/root/targets\`, the current shell directory, a temporary folder, or an agent-invented alternative unless the user explicitly requests that and an explicit mapping is recorded.

- \`scope/\`: saved authorization manifest and input scope snapshots (never replace \`scope/scope.json\` through the generic artifact tool).
- \`assets/\`: child-workspace registry; child workspaces are nested here.
- \`recon/\`, \`urls/\`, \`endpoints/\`, \`javascript/\`: reconnaissance inventory, live assets, URL/API endpoints, JS analysis.
- \`requests/\`: request/response references and correlation metadata; redact secrets.
- \`testing/\`: hypotheses, test matrices, verification outcomes, and negative results.
- \`findings/\`, \`evidence/\`, \`reports/\`: finding references, redacted evidence indexes, and report drafts.
- \`scans/\`, \`runs/\`, \`logs/\`, \`sessions/\`: resumability, tool manifests, output logs, and safe session references.
- \`research/\`: target-specific hypotheses/observations only. General public writeups and methodology stay in the global research database.
- \`notes.md\`: human-readable summary with durable target notes and managed child asset inventory.
- \`workspace.json\` and \`target.json\`: generated stable identity manifests. Do not edit them manually.

## File and note persistence

- Use \`target_artifact\` for complete target-local text/JSON/CSV artifacts. Supply the workspace target URL, a known area, a simple filename, and the complete content. Read its response and store the exact returned absolute path in the run manifest.
- New artifacts are immutable by default. Use \`overwrite=true\` only for an intentional replacement of a file that is not a reserved generated manifest. Prefer unique names or run IDs for evidence so retries cannot silently replace prior data.
- For binary or large tool outputs, set the external tool's output option to the exact workspace path; immediately verify its exit status, file existence, size, and format. If the tool cannot accept an output path, capture a bounded stdout result and persist that via \`target_artifact\`.
- Use \`target_note\` for concise semantic observations, lessons, endpoints, test results, follow-ups, and findings summaries. It requires an existing workspace and a target observed in the current session tree. If refused, do not claim it was saved: verify workspace + observed evidence, then retry only when the preconditions are truly satisfied.
- Use \`report_vulnerability\` for the structured finding record. Ensure its endpoint is full and unambiguous and passes the persisted scope gate so the finding gets attributed to the correct target; also save supporting redacted evidence references in \`evidence/\`.
- Generic \`write\`/shell output may edit ordinary project files, but it is not the target persistence interface. Never scatter target outputs using generic relative paths. Never claim a file or note is saved without a successful tool result and verification.

## Every run must be resumable

At run start, create or update a manifest under the root workspace, for example \`runs/run-<UTC timestamp>.json\`, containing:
- canonical root target and workspace path, operator scope snapshot/reference, exclusions and permitted activity;
- input files and hashes or stable source IDs, tool versions/commands, rate limits/concurrency, and run start time;
- work-unit/chunk boundaries, processed/remaining counts, deduplication rules and checkpoint cursor/last completed item;
- per-stage status, exact output paths, exit codes, errors/retries, end time, and whether the run is complete, partial, blocked, or budget-capped.
Use \`runs/index.json\` only through the structured runtime API; the generic artifact tool deliberately reserves it.

After each stage, persist the output before moving on. On interruption, continue from the manifest and existing output files; do not restart destructive or expensive work blindly. At the end, verify output paths, file sizes, final counts, and remaining queue/errors. Update root \`notes.md\` with a concise summary, links/relative paths to artifacts, and next steps. Keep per-asset notes and evidence with that child workspace.

## Prevent cross-target contamination

- Each target and child asset has a stable workspace ID. Never mix endpoints, notes, evidence, reports, credentials or scope from separate programs/projects.
- Never copy source-program hosts, object IDs, accounts, responses or PoCs from the global public-research database into current-target facts. Public methodology is a hypothesis source, not evidence.
- Secrets, cookies, bearer tokens, API keys, and unredacted personal data must never be written to notes/artifacts.
