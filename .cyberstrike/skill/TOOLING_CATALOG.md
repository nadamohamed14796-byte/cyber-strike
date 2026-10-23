# CyberStrike Tool Catalog

The single canonical reference for agent-executable tools, local helpers, APIs, datasets, and installation/preflight. Skills define **how to test**; this file records non-exhaustive capability examples and how to verify/invoke candidates. It is not a phase-to-tool allowlist. Do not create a second tool/source inventory. Add a tool here once, then link to this catalog from skills.

This is a candidate catalog, not proof that a binary is installed, maintained, compatible, enabled, or authorized. Prefer native registered CyberStrike tools and existing helpers when they cover the need. Browser UI, browser extensions, and interactive proxy GUIs are not agent-executable CLI dependencies.

## Source-of-truth boundaries

- This file owns the shared tool/API/CLI/helper catalog and the asset-discovery source-ledger schema. It does not own recon phase state or define a second phase-to-artifact list.
- `.cyberstrike/skill/RECON_PHASE_TOOL_MATRIX.md` owns the documented phase-to-artifact mapping and phase completion criteria. The recon orchestrator defines execution policy; the registered `recon_checkpoint` schema/runtime enforces actual phase state and accepted artifact paths.
- Specialist skills own technique-specific decision steps and evidence criteria. They may include a minimal command example needed to explain a technique, but must not repeat the general tool inventory, helper inventory, installation/preflight guide, or source-ledger schema. Add a shared tool/helper here once, then reference it from skills.
- `packages/cyberstrike/src/research/sources.ts` is the executable source-adapter registry for global public-research ingestion via `/update`; `.cyberstrike/skill/RESEARCH_SOURCES_2026-10-19.md` is a dated reference list for skill maintenance, not a runtime source registry or tool catalog. Both are separate from target reconnaissance's per-root `subdomain-sources.json`, which records actual source outcomes for a specific run. Do not delete or merge these merely because all refer to sources.
- If instructions disagree, actual registered tool schemas and runtime validation determine what can execute. Reconcile the single authoritative documentation location instead of adding another list, manifest, collector, or helper.

## Selection rules

1. Identify the active checkpoint's objective and the exact evidence gap; the checkpoint does not assign a fixed tool to that objective.
2. Search the available registered tools and existing helpers, then consider suitable reachable APIs and installed CLIs. Do not exclude a candidate because its nominal category differs from the active checkpoint; extend an existing helper instead of adding a duplicate.
3. Preflight external CLIs with `command -v TOOL` and the documented version/help flag. Use tool_preflight.py only after resolving its real path from the installed skill/catalog root, and invoke it by absolute path; do not assume `.cyberstrike/skill/scripts/` exists relative to the target workspace. If the helper is unavailable, use direct local checks—do not copy the helper or fail a phase solely because its path is unavailable. Reuse successful checks only while the same runtime/binary version remains.
4. Prefer official docs/releases; review maintenance, license, platform/dependencies, package provenance, permissions, network behavior, flags, output format, and rate behavior before install/use.
5. Do not preassign a primary tool or a fixed number of tools to a checkpoint. Search the live registry for the current objective, compare the returned candidates with existing helpers, installed CLIs, and suitable APIs, and use the combination required to close the evidence gap. Add alternatives only for distinct coverage, corroboration, or recovery; do not run equivalent collectors just to increase counts.
6. Preserve provenance and execution metadata that affect interpretation: tool/version, exact redacted command, inputs, timestamp, exit status, errors, source attribution, limitations, and canonical output path. Persist raw output only when it adds unique evidence, reproducibility, or diagnostic value; otherwise parse/normalize stdout and merge the results into the canonical inventory without saving a raw file for every invocation.
7. Use machine-readable output where supported and store artifacts in the canonical target workspace. Do not create one output file per tool if a shared phase ledger/artifact can retain provenance.
8. Tool output is a lead, not a finding. Use a baseline, a relevant negative control, and minimal controlled validation. Never claim a tool ran or succeeded without its actual result.
9. Installation is not authorization. Apply program scope, rate limits, privacy, non-destructive defaults, and explicit permission for state-changing tests. Never send secrets or production customer data to third-party services.
10. Public passive-research APIs queried through `curl` must use `curl -q -sS` (where `-q` is the first option to disable user config) with a read-only GET/HEAD route and one clear domain in a conventional lookup query. Do not add a request body, credentials/cookies/API keys in headers or query parameters, redirects, proxy/routing overrides, or TLS overrides. Do not use `wget` for this scope-aware routing because it follows redirects by default. The runtime checks the queried domain against persisted target scope rather than treating the external research provider as the target. An unlisted provider can be used when it follows this contract; if its API requires credentials or a nonstandard request shape, use a suitable registered capability or add a narrowly tested route rather than bypassing the gate.

## Capability examples (non-exhaustive; not a phase-to-tool allowlist)

Search the live connected-tool registry through `tool_search` at the start of a new checkpoint or when new evidence changes the needed capability; use `load_tools` for the exact relevant IDs, then inspect their schemas. Built-in CyberStrike tools, verified local CLIs, and suitable APIs/datasets are also candidates. The checkpoint governs workflow state, prerequisites, and artifact validation—not which ordinary tool IDs may be considered. The rows below are optional, non-exhaustive examples only: they do not assign primary tools, require binaries, or imply that listed tools are installed. Choose any fit-for-purpose combination based on evidence need and actual capability. Keep the explicit vulnerability-testing gate and request-level scope/impact controls.

| Evidence gap / capability | Example candidates (optional, unranked) | Other examples / supporting methods | Output / evidence contract |
|---|---|---|---|
| Passive subdomain collection | Choose reachable reputable public APIs/indexes, registered native tools, or installed CLIs based on the evidence gap. crt.sh, OTX passive DNS, subfinder, and Amass are examples, not a fixed allowlist. | CertSpotter, assetfinder, Findomain, Sublist3r, first-party links, and other independent sources only when they add distinct coverage | Write the canonical `subdomains.txt` and `subdomain-sources.json` using the schema below; preserve per-root/source status, timestamps, errors, counts, and provenance. |
| DNS validation / wildcard handling | dnsx, dig/drill; existing `host_inventory.py` for normalization | puredns/shuffledns only when active discovery is permitted | DNS records, CNAME chain, TTL, resolver status, wildcard controls, source attribution |
| ASN / organizational asset expansion | asnmap when a concrete, evidenced organization/ASN seed exists | Public RIR/BGP datasets, first-party asset lists, certificate transparency | Preserve seed and source provenance; candidates are not in scope until the persisted scope resolver accepts them. No IP-wide scanning without program authorization. |
| Ports / services / TLS | naabu, nmap, tlsx | httpx for HTTP metadata; fingerprintx where available | host/port/protocol, service fingerprint, timestamp, confidence, rate/authorization notes |
| HTTP liveness / tech fingerprinting | httpx, WhatWeb | curl; TLS metadata | status, redirect chain, title, content type, technology clues, stable fingerprint |
| URL history / crawling | gau, waybackurls, waymore; katana for authorized crawling | hakrawler; `uro`/`anew` for local normalization/deduplication; first-party links and documentation | normalized URL, method/parameters when known, source, first-seen, collection status |
| Content / directory / virtual-host discovery | ffuf, feroxbuster, dirsearch | context-appropriate wordlists; hakrawler for links | status, length, fingerprint, error/negative-control data; conservative rate |
| Parameter discovery | Arjun, x8, ParamSpider | endpoint inventory and controlled request comparison | endpoint template, method, parameter, source; preserve auth/content-type context |
| JavaScript / endpoint analysis | jsluice, xnLinkFinder, LinkFinder | local source-map review; retire.js for dependency clues | bundle hash, route, method/parameter, line/offset, confidence; use existing `js_endpoint_inventory.py` where suitable |
| API / GraphQL / WebSocket | graphql-cop, Clairvoyance where schema discovery is permitted, websocat/wscat | kiterunner for route inventory; curl, Python requests, local API schemas | operation/field/route inventory, auth boundaries, controlled evidence |
| Template / CVE checks | nuclei with reviewed templates; cvemap for metadata | technology-specific checks and vendor advisories | template ID/version, matched request/response, scope, manual validation status |
| XSS / client-side injection | dalfox for suitable authorized checks | browser-independent reflection/source-sink analysis; Semgrep for source | payload context, source/sink, minimal proof; alerts alone are not findings |
| SQL injection | sqlmap or ghauri for explicitly authorized validation | controlled baseline/variant requests | minimal proof and response diff; no database dumping by default |
| SSRF / OOB behavior | interactsh-client with a unique controlled token | Python for callback/evidence parsing | token, timestamped callback, request correlation; no internal/cloud metadata access without explicit authorization |
| JWT / sessions / auth | jwt_tool; Python requests | local redacted claim comparison and controlled account matrix | redacted claims, session boundary, expected/observed authorization; never persist live tokens |
| IDOR / BOLA / tenant authorization | Python requests, jq, pytest | existing `authorization_matrix.py`, `http_response_diff.py` | principal/object/action, expected policy, control result, redacted evidence; use test-owned accounts/objects |
| TLS / headers / CORS / redirects | testssl.sh, curl, Python requests | httpx metadata; response diff helper | raw relevant headers with secrets redacted, redirect chain, baseline/variant, policy impact |
| Race conditions | pytest and requests-racer in controlled fixtures | deterministic local harness | initial state, request ordering/timing, final controlled state; avoid repeated real-world mutations |
| Secrets / exposed source | Gitleaks, TruffleHog, Nosey Parker, detect-secrets, whispers | local Git inspection; git-dumper only when explicitly authorized and permitted | detector, file/commit, redacted fingerprint; never print or use discovered secrets |
| Source / dependencies / containers / IaC | Semgrep, Trivy, Checkov | vendor advisories, language-native tooling | rule/advisory, path/resource, version, remediation |
| Cloud / CI / platform review | Prowler, ScoutSuite, provider CLIs where authorized | Checkov, Trivy, Semgrep | identity/resource, least-privilege finding, source/config evidence; read-only first |
| Subdomain takeover triage | subzy plus provider conditions from can-i-take-over-xyz | DNS/CNAME and provider documentation | dangling record and provider-specific evidence; never attempt to claim a real target |
| Evidence / normalization / reporting | Python stdlib, jq | shared helpers below | reproducible evidence references, redaction, disposition, validation errors |

## Canonical asset-discovery artifacts and ledger schema

The recon command and registered `recon_checkpoint` enforce this contract. This is the only place that defines the source-ledger format; recon skills and phase references must link here rather than invent a second schema.

### Required files

- `subdomains.txt`: one normalized hostname per line, sorted and globally unique across the approved root set. It must exactly match the `host` values in the JSON ledger. It may be empty only when the ledger also has zero hosts and the source results support that outcome.
- `subdomain-sources.json`: one JSON object with `schema_version: 1`, `roots`, `sources`, `hosts`, `counts`, and `run_status`. Preserve provenance per source/root pair; do not create one file per source.

### Source-ledger rules

1. `roots` is a non-empty, duplicate-free array of normalized root hostnames drawn from the saved scope. Do not put URLs, paths, wildcard prefixes, or unvalidated candidates in this array.
2. `sources` contains exactly one record for every `root` × `source` pair represented in the run. Every root must have a record for each source name used anywhere in the ledger. Source names are discovered dynamically; the examples in the tool matrix are not an allowlist.
3. Every source record contains `root`, `source`, `status`, `started_at`, `finished_at`, `attempt_count`, `raw_records`, `valid_observations`, `unique_hosts`, `duplicate_observations`, `rejected_records`, `hosts`, and `attempt_history`. Use the terminal statuses `success`, `zero-results`, `failed`, `unavailable`, `blocked`, or `skipped`. Never leave a `pending` record when completing the phase.
4. A completed attempt has a real start/finish timestamp and `attempt_count >= 1`. A deliberately unselected alternative uses `status: "skipped"`, `skipped_by_selection: true`, `attempt_count: 0`, a finish timestamp, zero counts, and a plain-language `error` or `reason`. The same source names must be represented for every root; use a per-root skipped/failed/unavailable record when appropriate.
5. Counts must reconcile for each record: `raw_records = valid_observations + rejected_records`; `valid_observations = unique_hosts + duplicate_observations`. `hosts` is the duplicate-free list of normalized hostnames produced by that source for that root, and its length must equal `unique_hosts`. For an attempted source with no valid results, use `zero-results` only when the source actually completed successfully; otherwise record the true failure/blocked/unavailable state and reason.
6. `hosts` at the ledger root is the globally deduplicated array of objects with at least a `host` field. Preserve useful `roots`, `sources`, `observations`, and `observation_count` fields so merging duplicates does not discard source attribution. Do not store live credentials or secrets in evidence summaries.
7. `counts` must contain reconciled integer values for `roots`, `sources_attempted`, `sources_pending`, `sources_not_started`, `sources_running_or_interrupted`, `sources_success`, `sources_zero_results`, `sources_failed`, `sources_blocked`, `sources_unavailable`, `sources_skipped`, `sources_not_selected`, `unique_hosts`, and `duplicate_observations`. These are derived from the saved records, not estimates. Terminal ledgers have all three pending/not-started/interrupted counters at zero.
8. Set `run_status: "complete"` only when every root/source record is terminal and there are no failed, unavailable, blocked, or non-selection-skipped records. Use `"finished_with_gaps"` when any such gap exists. Intentional `skipped_by_selection` records are reported separately and are not falsely counted as attempted.
9. Write both files through the canonical target workspace, read them back, recompute all counts, compare the host list with ledger hosts, and only then complete `asset_discovery`. A source being omitted from the tool selection is not proof that it returned zero results.

The existing helper `host_inventory.py` is an offline observation normalizer, not a network collector or source ledger writer. Use it for hostname normalization when its JSONL input/output fits the task; do not claim it queried a source. Do not restore or create a dedicated collector merely to duplicate the catalog: the agent selects and invokes suitable registered tools, reachable APIs, and available CLIs directly, then persists the validated ledger above.

## Workspace/skill helper scripts

These helpers live with the installed skill/repository assets, not necessarily beside the executable or inside a target workspace. Resolve the actual installed path before calling them. Use helpers when their input/output contract fits the task; otherwise use an equivalent local operation without creating duplicate files.

- **host_inventory.py**: offline hostname normalization from JSONL, retaining every source observation and writing invalid-record diagnostics. It is not a network collector or source-ledger writer.
- **normalize_urls.py**: local URL normalization/deduplication.
- **js_endpoint_inventory.py**: local JavaScript endpoint candidate inventory.
- **http_response_diff.py**: compare baseline and controlled variants.
- **authorization_matrix.py**: validate explicit test-owned principal/object/action cases and create a planned JSONL matrix; no network traffic.
- **validate_evidence_manifest.py**: validate evidence manifests.
- **tool_preflight.py**: local CLI presence/version checks only; does not install tools or contact targets.
- **audit_skill_enrichment.py** and **validate_skill_catalog.py**: repository-maintainer quality checks, not target-assessment tools. Do not use them as part of recon or vulnerability testing.

Before adding a helper, search the existing helper directory and extend a helper if responsibilities overlap. Helpers need a documented CLI, deterministic input/output, useful exit codes, safe secret handling, and a self-test/smoke path.

## Bundled attack_script capabilities

The registered attack_script tool exposes only these bundled keys and argument forms; invoke them through the native tool, not as arbitrary script paths. The runner starts Python directly and does **not** apply the generic Bash scanner/scope gate, so its presence is not permission to use it. Validate the real target and current phase against the saved engagement scope before any network operation.

| Registered script | Purpose and input | Network/impact rules |
|---|---|---|
| **jwt_tamper** | TOKEN [--decode-only] [--set key=value] [--set-header key=value] [--key SECRET] [--json-output] | Local token manipulation only. Use test tokens; never place live tokens, signing keys, or claims in persistent notes. |
| **race_tester** | URL [-m METHOD] [-H key:value] [-d JSON_BODY] [-c COUNT] [--delay MS] [--json-output] | Sends concurrent HTTP requests; default is POST with 20 requests. Use only in an explicitly requested vulnerability-testing phase on a test-owned/approved operation; specify method, count, body, delay, and stop condition explicitly. |
| **ssrf_listener** | [-p PORT] [-o OUTPUT_FILE] [--timeout SECONDS] | Starts a local HTTP listener. Bind/use only the planned callback port, choose a finite timeout, and save only necessary redacted evidence. |
| **file_upload_tester** | URL [--field NAME] [-H key:value] [--data JSON] [--json-output] | Sends multiple crafted uploads, including executable PHP/JSP content and SVG payloads referencing cloud metadata. Active testing only with explicit permission and a dedicated test upload endpoint; do not run during recon or against real user data. |
| **cloud_storage_enum** | TARGET [--names BUCKET_NAME...] [--check-writes] [--json-output] | Read-only storage checks by default. The optional --check-writes flag attempts an S3 PUT and then DELETE; cleanup can fail and leave an object, so require explicit written program authorization. Guessed bucket names and root-domain matches are not authorization. |
| **subdomain_takeover** | FILE_OR_DOMAIN [--json-output] | Resolves CNAMEs and sends HTTP checks. Only use with a fully scope-checked candidate list; never register/claim a resource and do not infer takeover from a fingerprint alone. |
| **github_dorker** | ORG [--repo ORG/REPO] [--patterns PATTERN...] [--commits] [--json-output] | Uses gh to search GitHub content/commit metadata. Restrict searches to an owned or explicitly program-authorized organization/repository; redact any secret-like output and never use discovered credentials. |
| **wayback_endpoints** | DOMAIN [--probe] [--limit N] [--json-output] | Default mode queries public archive history; use only for URL collection after verifying the domain. --probe sends live HEAD requests to historical URLs and follows redirects, so do not use it through this generic runner; use scope-aware live-URL validation instead. If the configured limit truncates useful output, increase it and resume—do not report the truncated result as complete. |

Do not run equivalent native scripts and CLIs in parallel just because both are listed. Choose one method based on the evidence gap; use an alternative only for a distinct coverage gap or a measured failure. State-changing and high-volume scripts are never default reconnaissance.

## Execution examples and runtime constraints

The commands below illustrate syntax only. Replace every example target/workspace with values already saved in the current engagement and accepted by its persisted scope. A catalog entry is not proof of installation, permission, or a successful run.

```bash
# Passive certificate-transparency lookup. -q must be the first curl option.
curl -q -sS 'https://crt.sh/?q=%25.example.com&output=json'

# These direct-target forms are scope-checkable; file-list modes are not.
subfinder -d example.com -silent
dnsx -d example.com -a -resp -json
httpx -u https://example.com -jsonl
katana -u https://example.com -fs fqdn -rl 5 -d 3 -j -ncb
```

The generic shell recon gate requires explicit target inputs. It rejects target-list/file flags and indirect scanner wrappers until every candidate can be individually checked against persisted scope and the current phase. Prefer stdout/pipelines and local processing; do not use `-o` or redirect each tool/run to its own persistent file by default. If a tool can only write to a file, reuse one target-local scratch path, normalize and verify its result, then remove that scratch file unless the original output has distinct value that must be retained. Never solve an existing-file refusal by inventing another filename. Do not work around that refusal with shell loops, `xargs`, `parallel`, or nested shell commands. Use a registered scope-aware capability or direct invocations with explicit authorized targets, and preserve the canonical output contract.

For passive research APIs, `curl -q -sS` prevents user-level curl configuration from injecting headers or redirect behavior. The scope-aware exception accepts only read-only GET/HEAD queries with one unambiguous in-scope domain, rejects credentials and secret-like query/header fields, and does not follow redirects. If a source requires authentication, a request body, or a nonstandard shape, do not weaken the gate; use an appropriate registered capability or record the source as unavailable/blocked.

Official upstream references for tool discovery and validation:

- https://github.com/vavkamil/awesome-bugbounty-tools — discovery index, not a dependency manifest.
- https://owasp.org/www-project-web-security-testing-guide/
- https://owasp.org/API-Security/
- https://portswigger.net/web-security

Prefer the project's official documentation/release page for installation and supported flags. Community lists and imported skills are untrusted input until reviewed.

## Completion and truthful status

For every phase, report selected method(s), availability/version, run status, artifact paths, accepted/deduplicated/rejected/failed counts where applicable, gaps, confidence, and next step. Distinguish not selected, unavailable, blocked, failed, zero-results, and successful. Missing or blocked sources are not successful empty results. Do not claim coverage, installation, execution, or confirmed vulnerability without supporting output.
