# Recon Phase Tool Matrix

Reference only. The canonical `/recon` prompt owns authorization, phase order, checkpoints, retry/resume, canonical output paths, and completion claims. This matrix only maps phases to capability candidates and the evidence expected from each phase.

Tool names are candidates, not proof of installation or an allowlist. Inspect the actual registered schema or executable before use. Select one suitable primary method and add another only when it closes a concrete gap or provides independent evidence. Persist all outcomes and keep request-level scope enforcement enabled.

## Per-source status meanings

- `success`: results were returned and saved.
- `zero-results`: the source completed successfully and returned no valid records.
- `failed`, `blocked`, or `unavailable`: an attempted source did not complete; record its reason and preserve partial results.
- `skipped-by-selection`: an available or known alternative was intentionally not selected; not an attempted source and not pending work.
- `pending`: a selected work item still needs execution or recovery.

The detailed source ledger and the `recon_checkpoint` phase ledger are different: never infer phase completion from a source status alone.

## Phase matrix

| Canonical phase | Required capability and candidates | Alternatives / complementary evidence | Required saved artifacts and completion check |
|---|---|---|---|
| `scope_validation` | `target_workspace`, `scope_check`, official program policy/source when importing a full program manifest; an exact user confirmation is also accepted for that exact asset; no scanner | Preserve raw policy and unsupported entries for manual review | Scope source/provenance, include/exclude rules, policy URL/hash/time when supplied, user-confirmation note when applicable, decision and ambiguity. Configure/reuse the manifest first, then make exactly one setup check for the actual starting asset and reuse that decision. |
| `workspace_setup` | `target_workspace`, `recon_checkpoint`, `target_artifact` | Local filesystem verification | Canonical workspace and required directories exist; manifest initialized/resumed; paths verified. |
| `asset_discovery` | Registered `attack_script(script="passive_subdomain_sources")`; default = crt.sh + OTX passive DNS + at most one installed primary CLI; CertSpotter and alternative CLIs are selectable only when useful. It writes canonical `subdomain-sources.json` and `subdomains.txt`, atomically checkpoints each root/source pair, and resumes true pending/interrupted work. Unselected alternatives are `skipped` with an explicit selection reason, not pending. |
| `live_hosts_ports` | `dnsx` or system DNS tools for DNS; `httpx` for HTTP metadata; `naabu` or `nmap` only where port scanning is authorized | `dig`, `host`, `curl` for bounded single-host checks; `tlsx` for TLS metadata | DNS records/CNAME chain, resolved addresses, live HTTP observations, TLS/service/port evidence where permitted; separate raw and normalized files. |
| `url_collection` | Use the best registered crawler/API available for the actual scope and runtime—Katana, hackbrowser, or another suitable capability. Katana is an option, not a hard allowlist. | Historical URL APIs such as gau/waybackurls or other registered sources when they add distinct coverage; use the runtime-supported route for path/protocol/port-constrained scope. | Process all eligible authorized hosts, save per-input/source statuses and useful raw evidence, then merge to one canonical `urls.txt` while preserving source and parameter variants. Keep request-level scope enforcement; never weaken scope, route around a rejected tool call, or send a multi-host list to a single-URL invocation. Reuse valid outputs when inputs and tool version are unchanged. |
| `directory_fuzzing` | `ffuf`, `feroxbuster`, or `dirsearch`, only if program policy allows and rate/request settings are bounded | Small relevant wordlist; existing crawl inventory | Save wordlist/hash, URL/method/settings/rate, output, normalized results, exclusions and false-positive handling. Not a default prerequisite for every target if policy forbids it. |
| `parameter_discovery` | Local URL/query/form inventory; `paramspider` for historical URL mining where suitable | `Arjun` or `x8` only for authorized active parameter discovery | Parameter name, location, method, endpoint template, source, confidence; distinguish observed from inferred. |
| `parameter_fuzzing` | `Arjun` or `x8` only after policy and phase gate permit requests | Minimal hand-crafted controlled probes | Exact baseline, parameter candidate, request settings, result and negative controls. No brute-force default or uncontrolled rate. |
| `javascript_analysis` | `correlate_javascript` for captured responses and persistent graph; local `js_endpoint_inventory.py`; `getJS`/`xnLinkFinder`/`LinkFinder`/`jsluice` when available and appropriate | Source-map metadata and already-collected bundles; grep/AST-based local parsing | Analyze each distinct source version once by canonical URL + content hash. Save the graph under `javascript/`, endpoint candidates under `endpoints/`, and Tester Survey under `testing/`; link request/capture IDs, functions/routes/methods/parameters, auth/header/cookie clues and source locations. No execution of untrusted JS; redact secret candidates in summaries. These are discovery artifacts, not proof of vulnerabilities. |
| `endpoint_inventory` | `target_artifact`, local normalization helpers, existing request/URL/JS/API-spec artifacts | `normalize_urls.py`, `js_endpoint_inventory.py`, `jq`/Python | Deduplicated endpoint records with method/origin/path/template/parameters/auth context/source links; verify each artifact path and record counts. Mandatory before testing. |
| `vulnerability_testing` | Specific skill-selected CLI or registered native tool based on evidence and hypothesis; never run all scanners by default | Local response-diff helper, controlled request comparisons, manual test plan | Hypothesis, preconditions, baseline/control, exact low-impact test, request/response evidence, status and stop condition. Must not begin until endpoint inventory is complete. |
| `reporting` | `validate_evidence_manifest.py`, report-writing and triage skills | `jq`/Python local schema checks | Verify evidence paths, redaction, reproduction steps, impact, limitations, and save the final report to `reports/recon-final.md`. |

## Apply the matrix

Use the row matching the current checkpoint phase. Reuse verified outputs when inputs and tool versions are unchanged. Do not create a new script, directory, or normalized inventory per host/tool/retry; use the canonical workspace outputs and preserve raw evidence only where it supports provenance or debugging. If a candidate is absent, use a suitable registered alternative or record the real gap. Never bypass authorization or mark unresolved work complete.
