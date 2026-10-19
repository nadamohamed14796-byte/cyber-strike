# Recon Phase Tool Matrix

This is the operational tool-selection contract for CyberStrike's canonical recon phases. It is a candidate map, not a claim that any executable is installed or that every candidate must be run. For each phase, select a primary method plus a complementary method only when it adds distinct evidence; check availability before invocation, inspect actual help/version, and record all outcomes.

## Required preflight for every phase

1. Read the current `recon_checkpoint(action="status")` and inspect the canonical target workspace. Reuse valid artifacts; do not repeat completed work without new evidence or a documented invalidation.
2. Read the applicable skill(s) using the registered skill tool: first `recon-methodology` and `community-tool-selection`, then the task-specific skill(s) below. A search result or candidate list is not a loaded skill.
3. Check local candidates without installing them:
   `python3 .cyberstrike/skill/scripts/tool_preflight.py --json <candidate names...>`
   If that path is not present in this runtime, locate the repository's actual helper path and verify it exists before invoking it. Never assume a repo helper is installed globally.
4. For each available candidate, inspect its actual `--help` and documented version flag. Verify the CLI syntax from local help/official docs; do not copy guessed flags from memory.
5. Choose based on task, platform, permissions, program policy, input size, and available evidence. Do not install automatically. If installation is justified, explain why, use the official source, inspect install instructions first, then re-run preflight.
6. Save raw output, stderr/error, exit status, tool/version, redacted command, input artifact, timestamp, normalized output, deduplication counts, and provenance to the canonical target workspace. A command exit code of zero alone does not complete a phase.
7. If a primary tool is missing or fails, attempt a suitable installed alternative where it adds value. If no suitable method remains, record the precise gap and mark the phase unavailable/blocked/partial according to the checkpoint schema; never claim exhaustive coverage.
8. Do not run active probes until the phase gate and saved authorization permit them. The agent-level canonical scope setup check is performed once; this does not waive enforcement of the persisted scope at each concrete request boundary.

## Phase matrix

| Canonical phase | Required capability and candidates | Alternatives / complementary evidence | Required saved artifacts and completion check |
|---|---|---|---|
| `scope_validation` | `target_workspace`, `scope_check`, official program policy/source; no scanner | Preserve raw policy and unsupported entries for manual review | Scope source, include/exclude rules, policy URL/hash/time, decision and ambiguity. Exactly one explicit canonical setup check; reuse saved decision. |
| `workspace_setup` | `target_workspace`, `recon_checkpoint`, `target_artifact` | Local filesystem verification | Canonical workspace and required directories exist; manifest initialized/resumed; paths verified. |
| `asset_discovery` | `subfinder`, `amass`, `assetfinder` when installed | Certificate transparency / passive DNS / official program asset lists; `host_inventory.py` for local normalization | Raw outputs by source, normalized deduplicated host inventory, provenance per host, scope disposition, unresolved-source list. |
| `live_hosts_ports` | `dnsx` or system DNS tools for DNS; `httpx` for HTTP metadata; `naabu` or `nmap` only where port scanning is authorized | `dig`, `host`, `curl` for bounded single-host checks; `tlsx` for TLS metadata | DNS records/CNAME chain, resolved addresses, live HTTP observations, TLS/service/port evidence where permitted; separate raw and normalized files. |
| `url_collection` | `gau`, `waybackurls`, or `katana` for historical URLs | Wayback CDX read-only lookup; `waymore`/other crawler only through a scope-aware crawl path | URLs with source attribution and timestamp; deduped canonical list; per-source counts/errors. Do not use generic shell crawlers that can follow unchecked off-scope links. |
| `directory_fuzzing` | `ffuf`, `feroxbuster`, or `dirsearch`, only if program policy allows and rate/request settings are bounded | Small relevant wordlist; existing crawl inventory | Save wordlist/hash, URL/method/settings/rate, output, normalized results, exclusions and false-positive handling. Not a default prerequisite for every target if policy forbids it. |
| `parameter_discovery` | Local URL/query/form inventory; `paramspider` for historical URL mining where suitable | `Arjun` or `x8` only for authorized active parameter discovery | Parameter name, location, method, endpoint template, source, confidence; distinguish observed from inferred. |
| `parameter_fuzzing` | `Arjun` or `x8` only after policy and phase gate permit requests | Minimal hand-crafted controlled probes | Exact baseline, parameter candidate, request settings, result and negative controls. No brute-force default or uncontrolled rate. |
| `javascript_analysis` | Local scripts `js_endpoint_inventory.py`; `getJS`/ `xnLinkFinder`/ `LinkFinder`/ `jsluice` when available and appropriate | Source-map metadata and locally downloaded bundles; grep/AST-based local parsing | Bundle URL/hash/source, extracted routes, parameter/method hints, line/offset, confidence; no execution of untrusted JS. |
| `endpoint_inventory` | `target_artifact`, local normalization helpers, existing request/URL/JS/API-spec artifacts | `normalize_urls.py`, `js_endpoint_inventory.py`, `jq`/Python | Deduplicated endpoint records with method/origin/path/template/parameters/auth context/source links; verify each artifact path and record counts. Mandatory before testing. |
| `vulnerability_testing` | Specific skill-selected CLI or registered native tool based on evidence and hypothesis; never run all scanners by default | Local response-diff helper, controlled request comparisons, manual test plan | Hypothesis, preconditions, baseline/control, exact low-impact test, request/response evidence, status and stop condition. Must not begin until endpoint inventory is complete. |
| `reporting` | `validate_evidence_manifest.py`, report-writing and triage skills | `jq`/Python local schema checks | Verify evidence paths, redaction, reproduction steps, impact, limitations, and save the final report to `reports/recon-final.md`. |

## Tool selection rules

- The phase matrix does not replace actual registered-tool discovery. For native CyberStrike tools, inspect the available tool registry/schema and call the registered tool; do not try to invoke a native tool as a CLI.
- The CLI name in a row is a candidate only. A tool is usable only after local preflight confirms it is executable and its real CLI behavior is verified.
- Use one primary source/tool and a second independent source when it adds meaningful coverage. Use additional sources when earlier sources fail, evidence is incomplete, or the target context justifies them; do not stop after the first tool simply because it returned some results.
- Tool availability must be checked against this runtime/environment, not inferred from skill text, community maps, or another machine.
- Preserve partial results even if a source fails. Retry only after changing the cause or when a bounded retry is justified; avoid infinite retry loops.
- Keep phase completion honest: `complete` means required capabilities were attempted appropriately, eligible work was exhausted, and artifacts were verified. If a tool is missing, disclose the gap; do not imply the unavailable data source returned zero results.
- Never install every tool in the matrix as a batch. Install only when a concrete phase need exists, after checking official instructions, source integrity, platform compatibility, and permission.
