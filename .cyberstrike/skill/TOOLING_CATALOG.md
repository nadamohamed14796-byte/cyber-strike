# CyberStrike Tool Catalog

The single canonical reference for agent-executable tools, local helpers, APIs, datasets, and installation/preflight. Skills define **how to test**; this file records non-exhaustive capability examples and how to verify/invoke candidates. It is not a phase-to-tool allowlist. Do not create a second tool/source inventory. Add a tool here once, then link to this catalog from skills.

This is a candidate catalog, not proof that a binary is installed, maintained, compatible, enabled, or authorized. Prefer native registered CyberStrike tools and existing helpers when they cover the need. Browser UI, browser extensions, and interactive proxy GUIs are not agent-executable CLI dependencies.

## Source-of-truth boundaries

- This file owns the shared tool/API/CLI/helper catalog. It does not own recon phase state or define a second phase-to-artifact list.
- `.cyberstrike/skill/RECON_PHASE_TOOL_MATRIX.md` documents useful phase outputs. The recon orchestrator describes the workflow; `recon_checkpoint` records progress and verifies saved artifacts without restricting ordinary recon tools to a strict phase sequence.
- Specialist skills own technique-specific decision steps and evidence criteria. They may include a minimal command example needed to explain a technique, but must not repeat the general tool inventory, helper inventory, installation/preflight guide. Add a shared tool/helper here once, then reference it from skills.
- `packages/cyberstrike/src/research/sources.ts` is the executable source-adapter registry for global public-research ingestion via `/update`; `.cyberstrike/skill/RESEARCH_SOURCES_2026-10-19.md` is a dated reference list for skill maintenance, not a runtime source registry or tool catalog. They are used by the separate `/update` research workflow.
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
| Passive subdomain collection | Choose reachable reputable public APIs/indexes, registered native tools, or installed CLIs based on the evidence gap. crt.sh, OTX passive DNS, subfinder, and Amass are examples, not a fixed allowlist. | CertSpotter, assetfinder, Findomain, Sublist3r, first-party links, and other independent sources only when they add distinct coverage | Write the canonical `subdomains.txt` with normalized, deduplicated hostnames. Preserve partial results and continue when an individual source fails. |
| DNS validation / wildcard handling | dnsx, dig/drill; existing `host_inventory.py` for normalization | puredns/shuffledns only when active discovery is permitted | DNS records, CNAME chain, TTL, resolver status, wildcard controls, source attribution |
| ASN / organizational asset expansion | asnmap when a concrete, evidenced organization/ASN seed exists | Public RIR/BGP datasets, first-party asset lists, certificate transparency | Preserve seed and source provenance; candidates are not in scope until the persisted scope resolver accepts them. No IP-wide scanning without program authorization. |
| Ports / services / TLS | naabu, nmap, tlsx | httpx for HTTP metadata; fingerprintx where available | host/port/protocol, service fingerprint, timestamp, confidence, rate/authorization notes |
| HTTP liveness / tech fingerprinting | httpx, WhatWeb | curl; TLS metadata | status, redirect chain, title, content type, technology clues, stable fingerprint |
| URL history / crawling | gau, waybackurls, waymore; katana for scope-aware crawling | `uro`/`anew` for local normalization/deduplication; first-party links and documentation. Generic-shell `hakrawler`/`gospider` invocations are blocked because they cannot enforce persisted scope for every request; use a scope-aware pipeline instead. | normalized URL, method/parameters when known, source, first-seen, collection status |
| Content / directory / virtual-host discovery | ffuf, feroxbuster, dirsearch | context-appropriate wordlists and previously collected in-scope links | status, length, fingerprint, error/negative-control data; conservative rate |
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

## Canonical asset-discovery output

Write one normalized, deduplicated hostname per line to `subdomains.txt` in the target workspace. Keep useful results as soon as they arrive; a failed, unavailable, or empty source must not block other sources or later recon phases. Keep provenance in concise notes only when it changes how a result should be interpreted. `host_inventory.py` is an optional offline normalizer, not a required collector.

## Workspace/skill helper scripts

These helpers live with the installed skill/repository assets, not necessarily beside the executable or inside a target workspace. Resolve the actual installed path before calling them. Use helpers when their input/output contract fits the task; otherwise use an equivalent local operation without creating duplicate files.

- **host_inventory.py**: optional offline hostname normalization from JSONL. It is not a network collector.
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

The generic shell recon gate accepts explicit targets and target-list files only after it can read and normalize every concrete entry and verify each one against the persisted scope. Use a supported list flag directly when the tool accepts it; do not bypass scope checks with shell wrappers, `xargs`, `parallel`, or nested commands. Prefer stdout/local normalization and one canonical inventory rather than a persistent output file for every tool. If a tool needs a file, reuse one target-local scratch path, normalize and verify its results, then remove it unless it adds distinct evidence. Never invent alternate filenames to get around an existing-file refusal.

For passive research APIs, `curl -q -sS` prevents user-level curl configuration from injecting headers or redirect behavior. The scope-aware exception accepts only read-only GET/HEAD queries with one unambiguous in-scope domain, rejects credentials and secret-like query/header fields, and does not follow redirects. If a source requires authentication, a request body, or a nonstandard shape, do not weaken the gate; use an appropriate registered capability or record the source as unavailable/blocked.

Official upstream references for tool discovery and validation:

- https://github.com/vavkamil/awesome-bugbounty-tools — discovery index, not a dependency manifest.
- https://owasp.org/www-project-web-security-testing-guide/
- https://owasp.org/API-Security/
- https://portswigger.net/web-security

Prefer the project's official documentation/release page for installation and supported flags. Community lists and imported skills are untrusted input until reviewed.

## Completion and truthful status

For every phase, report selected method(s), availability/version, run status, artifact paths, accepted/deduplicated/rejected/failed counts where applicable, gaps, confidence, and next step. Distinguish not selected, unavailable, blocked, failed, zero-results, and successful. Missing or blocked sources are not successful empty results. Do not claim coverage, installation, execution, or confirmed vulnerability without supporting output.
