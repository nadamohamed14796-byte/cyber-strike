---
name: target-workspace-workflow
description: "Keep authorized target scope, recon outputs, notes, evidence, and reports in one canonical target workspace"
category: methodology
version: "1.0.0"
author: CyberStrike
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

# Target Workspace

The shared Target Workflow Contract is the authority for authorization semantics, inheritance, and automatic execution. This skill defines only the workspace operations and file-persistence rules.

## Agent-executable CLI tooling, resources, and helper scripts

Use the Target Workflow Contract for scope inheritance, tool selection/installation, and end-to-end sequencing. This skill owns only workspace setup and persistence. Do not create a separate output per tool or target.

Resolve `tool_preflight.py` from the installed skill/catalog root and invoke it by absolute path; do not assume the target workspace is the repository root. If the helper is unavailable, verify the selected executable with `command -v` plus its documented version/help check. If the selected CLI is missing, use `ensure_tools` for that exact CLI and verify installation before choosing another method.

Official resources: https://owasp.org/www-project-web-security-testing-guide/ and the selected tool's official upstream documentation.

## Initialize and configure

1. Call target_workspace with action=init for one stable program/root URL. Use the exact canonical absolute path returned. Workspace creation is storage setup, not authorization.
2. When scope is new or changed, configure it once through target_workspace. Prefer the verified program policy and preserve both inclusions and exclusions. If the user explicitly supplies a complete authorized list, import it as a unit with user_confirmed_scope_list=true; do not ask them to approve each entry separately. Use merge_existing=true only for an explicitly additive change.
3. A user-confirmed exact single asset may use user_confirmed_scope=true only when no policy reference is available. That option does not authorize wildcards, CIDRs, siblings, or related hosts. If the confirmed input is a wildcard or complete list, use the complete-list path instead.
4. Reuse unchanged scope decisions. Do not ask for scope or policy proof again when the same saved decision is valid. Exclusions and actual request-level scope controls always win.

## One workspace and clear outputs

- Keep all ordinary discovered domains, subdomains, APIs, URLs, and scripts in the one root program workspace. Create a separate child workspace only when the user explicitly requests an independent investigation. Register ordinary discovered assets without creating one full workspace per host.
- Canonical root inventories: subdomains.txt, live-hosts.txt, urls.txt, parameters.txt, endpoints.txt, and javascript-analysis.md. The final human-readable summary is reports/recon-final.md. Update these canonical files; do not create parallel per-tool inventories.
- Keep only necessary supporting evidence under the existing scope/, javascript/, endpoints/, requests/, testing/, findings/, evidence/, reports/, or scans/ areas. Use runs/ for resumability only. Do not create a new directory or file for each URL, tool, batch, phase, or hypothesis.
- Keep routine stdout local and save normalized records. Retain raw output only when it adds unique evidence, reproducibility, or diagnostic value. Preserve exact error/status and source attribution where it affects interpretation.

## Persist and verify

- Use target_artifact for text/JSON/CSV artifacts and the exact existing workspace URL. Use area=root for the canonical root inventories; root is an area selector, not a literal root/ directory.
- Before updating a canonical filename, read its current contents, merge/deduplicate while preserving provenance, then intentionally overwrite that same filename. Do not switch to numbered/suffixed alternatives to avoid merging. Do not overwrite reserved scope/scope.json, workspace.json, or target.json through generic artifact writes.
- Use target_note for grounded, target-local observations and target_workspace(action=record_summary) for the verified run summary. A note, task record, or checkpoint is not proof that recon or testing succeeded.
- Verify actual saved paths and counts against the canonical artifacts before reporting. Do not store raw tokens/cookies/credentials in shared summaries or reports. Findings remain unconfirmed until the existing evidence, validation, and triage workflow supports them.
