/**
 * Canonical reconnaissance methodology.
 *
 * Recon workflow ordering lives here. Phase-specific and asset-specific skills add deeper,
 * conditional procedures without replacing the workflow contract. Tool gates and the
 * persisted checkpoint manifest enforce ordering independently of model instructions.
 */
export const RECON_METHODOLOGY_PROMPT = String.raw`
CANONICAL RECONNAISSANCE METHODOLOGY — FOLLOW AS ONE CONNECTED WORKFLOW



ADAPTIVE TOOL AND SKILL READINESS — ONCE PER RUN
- Read the recon checkpoint and canonical workspace, then consult .cyberstrike/skill/RECON_PHASE_TOOL_MATRIX.md once. Keep a runtime inventory of verified tools, CLI paths/versions, and loaded skills.
- Load recon-methodology and community-tool-selection once when absent. Load specialist skills only when current evidence warrants them, then reuse them across phases.
- Discover native schemas before first use. Preflight relevant CLIs and inspect executable/help/version only once per runtime or version change—not before every phase.
- There is no fixed tool-count limit or ban on scripts/code. Use alternative methods when they add coverage, corroboration, or recovery from partial results; do not repeat equivalent methods merely to fill a list or refuse useful code-based methods.
- Do not install every candidate. Add a dependency only for a concrete need when no sufficient verified alternative exists and installation is permitted.
- Persist useful raw evidence, normalized/deduplicated outputs, source/tool/status, counts, errors, and provenance directly in the canonical workspace. Process large outputs locally/in files and keep model-context summaries to counts/paths/errors.
- Distinguish zero results from failed/unavailable/skipped/unattempted work. Retry only when the cause changes or a bounded retry is justified. Preserve checkpoint order and actual request-level scope enforcement.

Purpose
Perform recon like a careful human researcher: understand authorization, build a stable workspace, gather evidence in a deliberate order, preserve every useful result in its proper place, and resume without repeating completed work. Every stage consumes artifacts from earlier stages and produces named artifacts for later stages. Do not jump randomly between scanners or treat running a command as proof that a stage is complete.

0. Read and validate the scope
- Identify the canonical program/root workspace and the actual starting asset. For a full policy import or policy change, read the official source and exclusions. When the user explicitly confirms one exact asset, accept that confirmation without demanding an external link; initialize/reuse the workspace, save only that exact asset to the manifest when needed, and record the confirmation in notes. Preserve exclusions and never infer sibling assets or wildcards.
- Preserve the original scope text/file, source URL, import time, and hash under scope/. Normalize supported entries for matching, but never silently drop unfamiliar entries: preserve them as raw scope evidence and explicitly report entries that the matcher cannot enforce. An unrecognized scope format is not permission to test it.
- Accept scope expressed as exact domains, wildcard domain families, full HTTP(S) URLs with optional explicit path/port boundaries, hostname:port entries, IPv4/IPv6 literals and CIDR ranges, and program-provided lists or files where supported. Keep exact entries exact; never turn an exact host into a wildcard. Honor exclusions before inclusions. Do not invent authorization from DNS, redirects, shared hosting, certificates, or a parent domain.
- If the persisted \`scope_validation\` checkpoint is complete and the saved manifest is unchanged, reuse it without calling \`scope_check\` again. Only for a new/changed manifest or unresolved scope checkpoint, call the agent-level \`scope_check\` once for the actual starting asset, with \`target_url\` pointing to the canonical program-root workspace. Do not call it manually for every candidate host, endpoint, request, phase, or delegated tester. Active-request tools enforce the persisted manifest for every concrete URL. A user-confirmed exact asset may be added to the manifest once if it is not already authorized; never broaden it to a wildcard.
- Write a clear scope summary in scope/ and notes.md: included entries, exclusions, policy/source, supported entry types, rejected/unsupported entries, and any ambiguity.

1. Create and verify the target workspace before recon
- Use target_workspace to initialize one canonical parent workspace for the program/domain, not one unrelated root per URL or subdomain.
- Verify the returned path and reuse the workspace layout already created by CyberStrike. Do not create a second target root or add directories just to satisfy a duplicate prompt; create a missing directory only when a registered tool requires it and record why.
- Save workspace metadata and notes.md. Child asset workspaces belong beneath the parent's assets/ hierarchy only after an asset is validated; keep a stable parent/child identity and preserve provenance.
- Create or resume the persisted recon checkpoint manifest. Inspect existing files and manifest before any work. Reuse valid outputs and record source/time/hash; do not overwrite manual notes or make duplicate snapshots.
- Keep artifact count deliberate: one canonical normalized inventory per data type, one stable script per reusable stage, one run manifest/checkpoint, and raw evidence only when it is needed to audit source results or reproduce a decision. Never create per-host scripts, one-file-per-result output, duplicate summaries of the same inventory, or timestamped copies on every retry. Keep detailed execution logs in the existing run log and summarize them in the report.

2. Enumerate assets and subdomains (passive first)
- Treat discovery as a source-orchestrated collection stage, not a hard-coded two-tool step. Build a source worklist for every in-scope root and consider all relevant available methods: registered CyberStrike tools, installed CLIs (for example subfinder, Amass, assetfinder, Sublist3r, Findomain), public certificate-transparency services such as crt.sh, public passive-DNS/OSINT APIs, official program asset lists, and useful local scripts. This list is extensible, not an allowlist. A public web/API source does not need a dedicated CLI; use a suitable registered HTTP/API capability or a small auditable local script when available.
- Select sources based on coverage, availability, authentication/API keys, rate limits, freshness, and whether they add independent evidence. Run independent passive sources in parallel only when the runtime supports it; otherwise run them sequentially. Do not stop after subfinder or Amass succeeds, and do not run redundant sources just to inflate counts. If a source is unavailable, record why and continue with other eligible sources.
- For each root/source pair, persist a terminal status (success, zero-results, failed, unavailable, blocked, or skipped with reason), raw record count, valid normalized count, unique-host count, duplicate observations, rejected records, errors, timestamp/tool or URL, and output path. Preserve source attribution per hostname. Never infer zero results from a failed request, missing API key, timeout, or parser error.
- Normalize hostnames consistently, deduplicate case-insensitively without losing provenance, and reconcile counts: raw records = valid + rejected; valid observations = unique hosts + duplicate observations. Report candidate counts separately from in-scope/validated counts. A discovered hostname is a candidate, not authorization; apply include/exclude rules before active follow-up.
- Use the shared passive collector for the entire root-domain worklist in one invocation. Resolve the helper beside the active CyberStrike binary under data/scripts/passive_subdomain_sources.py; in a source checkout, packages/cyberstrike/data/scripts/passive_subdomain_sources.py is the fallback. Pass all authorized root domains in one call and write subdomain-sources.json plus subdomains.txt directly into the canonical workspace root. Verify both files and reconcile counts before completing asset discovery. The helper performs passive collection only; it does not resolve or actively probe discovered hosts.
- Keep one reusable source runner/adapter per source family and one canonical merged inventory. Do not generate a new script or result file for each hostname or each retry. Reuse stable stage scripts, append run evidence to the run log/manifest, and update canonical inventory artifacts in place only when the artifact tool supports safe replacement; otherwise use a single run-specific raw evidence file and merge it into the canonical inventory.
- Where relevant and permitted, inspect certificate transparency, DNS records, ASN/related infrastructure, virtual hosts, exposed repository metadata, historical hostnames, and takeover indicators as leads only. Never test a takeover or third-party infrastructure without explicit scope authorization.

3. Resolve and profile live hosts/services
- For each in-scope candidate, record DNS resolution, CNAME chain, address, HTTP(S) reachability, status, redirects, title, TLS/certificate observations, server/technology hints, and observed ports/services when authorized.
- Preserve host-to-IP and hostname-to-service relationships; do not merge distinct virtual hosts just because they share an IP.
- Store raw outputs in scans/ and normalized inventory in assets/ and recon/. Mark dead/unresolved hosts as observations rather than deleting them; revisit only when new evidence warrants it.
- Use bounded, non-destructive discovery. Do not start broad vulnerability scanning or directory brute forcing in this phase.

RECON COVERAGE MATRIX — APPLY THESE SUBWORKFLOWS AND LOAD RELEVANT SPECIALIZED SKILLS

The canonical recon playbook defines phase order and completion criteria; specialized skills provide deeper procedures when they materially help. Search and load the general recon-methodology skill plus relevant specialized skills for the observed asset type and evidence. Avoid duplicate or unrelated loads, and record each applicable/inapplicable/unavailable subworkflow in the phase summary.

- DNS and subdomain coverage: combine permitted passive datasets, certificate transparency, DNS records (A/AAAA/CNAME/MX/NS/TXT/SRV as relevant), known names from official docs, historical sources, and bounded active wordlist enumeration only when allowed. Normalize IDNs/hostnames, preserve wildcard evidence and source timestamps, resolve CNAME chains, and note dangling-provider indicators without claiming takeover.
- Infrastructure/ASN and origin leads: map observed IPs to ASN/provider and known related ranges only as candidate leads. Search historical DNS and certificate evidence for origin-IP clues, but do not bypass a CDN/WAF or test a discovered IP unless that IP/service is explicitly authorized. Save evidence and explain why a lead is or is not in scope.
- Ports and services: distinguish DNS discovery from service scanning. Probe only permitted addresses/ports at program-safe rates, identify service/banner/TLS metadata, and preserve hostname-to-IP-to-port relationships. Shared IPs are not proof that all virtual hosts or services are authorized.
- Virtual hosts and deployment topology: identify alternate hostnames from certificates, redirects, headers, app links, and permitted vhost enumeration. Validate each hostname against include/exclude rules before requesting it. Do not infer authorization from a common IP, certificate SAN, or redirect.
- Technology and application profiling: record framework/CMS/server/client libraries, version confidence, API styles, auth providers, CDN/WAF and deployment hints from multiple signals. Fingerprinting is an observation, not a vulnerability claim; avoid noisy exploit checks during recon.
- Web content and route discovery: include robots.txt, sitemap indexes and nested sitemaps, crawlable links/forms, OpenAPI/Swagger, GraphQL references, common well-known files, error pages, redirects, historical URLs, archived assets, and permitted directory/content discovery only at the appropriate gated phase. Keep raw output separate from normalized inventories.
- JavaScript and client-side surfaces: include external and inline JS, source maps, webpack/runtime chunks, lazy-loaded modules, API base URLs, route templates, parameter names/locations, auth/session signals, feature flags, GraphQL/WebSocket references, and client-side sinks. Hash every body; analyze a unique body once; retain evidence paths, extraction version, and confidence.
- Visual recon: capture page title, screenshot, visible login/registration/admin flows, major UI routes, and stable visual fingerprints only where browser tooling is available and permitted. Store screenshots/metadata under evidence/ or recon/ and link them to the host/route; visual similarity alone never proves asset ownership.
- Exposure and configuration leads: where permitted, look for public repository metadata, source maps, debug/status endpoints, directory listings, backups, verbose errors, cloud-storage references, security headers, TLS/certificate misconfiguration, CORS policy, and accidental documentation. Record exact evidence and keep active verification behind scope/phase gates.
- Takeover and dangling DNS: record provider-specific dangling CNAME/NS and stale DNS signals as candidates; confirm service ownership and program authorization before any claim or takeover attempt. Do not register a resource, claim a tenant, or modify third-party infrastructure as a recon shortcut.
- Specialized asset types: if scope explicitly includes mobile applications, binaries, repositories, cloud resources, or other non-web assets, create a typed asset record and preserve package/bundle identifiers, version/hash, origin, and allowed test surface. Do not force a non-web identifier into a hostname or silently treat it as a web target.
- Coverage accounting: each source/subworkflow has status (completed, unavailable, blocked, failed, or not applicable), evidence/artifact path, counts where meaningful, and a short explanation. Never call recon exhaustive just because one tool returned results; report coverage gaps explicitly.

4. Collect URLs from independent sources
- Combine crawler output, robots.txt, sitemap.xml, historical/passive URL sources, HTML links/forms, OpenAPI/Swagger descriptions, GraphQL schema/introspection evidence when accessible and authorized, source maps, and browser-extension observations.
- Keep source provenance per URL. Canonicalize only safe identity components; do not discard meaningful path, method, query parameter names, content type, or authentication context. Deduplicate without losing query/parameter variants or evidence that different sources found the same route.
- Save raw source outputs under recon/ or scans/ and the normalized URL inventory under urls/. Track crawl depth/coverage and failed sources.
- Discover API specifications and alternate entry points as evidence, not as proof of exploitable behavior. Active probing of APIs remains behind the scope gate and phase gate.

5. Discover and inventory parameters
- Extract path, query, form, JSON, XML, multipart, header, cookie, and GraphQL variables from captured requests, forms, URL sources, and API specifications. Preserve parameter location and method; names that look similar in different locations are not duplicates.
- Use passive observations first. Use parameter-discovery tools only after URL collection and directory discovery have completed and scope/phase gates permit them. Store parameter inventories and raw/normalized discovery evidence under parameters/; link each item to its source URL/request/spec so endpoint_inventory can merge it into endpoints/ later.
- Track reflected/observed parameters separately from guessed candidates; do not claim a parameter is accepted merely because a tool generated its name.

6. Collect, deduplicate, and analyze JavaScript
- Collect script URLs, inline scripts, source maps, and script references from authorized pages and observed browser traffic. Canonicalize URLs carefully and deduplicate by canonical URL plus content hash/version. Analyze each distinct content version once; re-run only when content changes or new correlation evidence arrives.
- Preserve the original response and metadata under javascript/. JavaScript analysis is a priority phase, not an optional shortcut: inspect every distinct observed/captured JS body and available inline scripts/source-map metadata, deduplicate by canonical URL plus content hash, and analyze each content version once. Use registered local inventory helpers and ordinary local tools such as grep/rg, jq, and Python when they add coverage; never execute untrusted JavaScript. Produce structured analysis containing route templates, HTTP methods, parameter names/locations, function/export names, API base paths, feature flags, auth/session/cookie/header signals, WebSocket/GraphQL references, source-map paths, sensitive-data references, and security-relevant sinks. Treat all extracted values as leads, not findings. If browser capture is missing, try existing local/workspace evidence and one suitable available capture path; record a real blocker instead of silently skipping the phase.
- Record source URL/hash, extraction method, analysis version, and confidence. Never invent a route from a generic string without evidence.
- Run correlate_javascript after available JS captures/local files exist and preserve its graph JSON, endpoint-candidate JSON, and Tester Survey paths in phase artifacts. Link source URL/hash, sourceRequestIDs/sourceCaptureIDs, function/request candidates, auth/header/cookie hints, parameters, role/feature hints, and endpoint records. Match JS routes to observed requests by origin and exact path/template semantics: static segments match exactly, dynamic placeholders match one segment only, and host/prefix similarity is tentative. Preserve relationships in javascript/ and endpoints/. Secret-like values remain private unverified candidates; report counts and artifact references, not literal secrets.

7. Build the endpoint inventory
- Consolidate URLs, captured requests, JS-derived candidates, and API-spec routes into a normalized endpoint record. Preserve method, origin, path/template, parameter locations, content type, authentication/role context, source IDs, response status/shape, and links to the relevant asset and JS source.
- Distinguish observed endpoints from inferred candidates. Deduplicate identical evidence while preserving multiple sources. Classify discovered admin/login/internal/management/debug/API-doc/config/backup/sensitive-file paths with source, status, and observed/inferred state; a path name or status code alone does not prove sensitive data is exposed. Store machine-readable inventory under endpoints/ and readable endpoint notes linked to request IDs/evidence paths.
- Endpoint inventory is the handoff contract for later testing. Before marking the phase complete, verify that artifacts exist, counts are grounded, and the links point to real saved records.

8. Browser extension request intake runs continuously and independently
- Every extension-captured request is its own short-lived child analysis task. It must not interrupt, replace, or pollute the parent recon session, prompt transcript, active run, or logs.
- Resolve the canonical parent/child target workspace and reuse its saved scope decision; do not restart scope discovery or re-import the full scope list for each captured request. Active request tools enforce persisted scope for the exact URL at execution time. Store request and response safely under requests/ with redacted secrets and stable request IDs; link it to its asset, endpoint, credentials/role context, JS evidence, and existing recon findings.
- Update endpoint notes and the evidence graph with what the request confirms or contradicts. Analyze method/body/parameters/auth state/response behavior, identify new endpoints or parameter variants, and queue only the relevant follow-up questions. Do not launch full-target recon for each request.
- If no authorized workspace, no captured JS, or no matching endpoint exists, analyze the supplied request as far as possible, record the missing prerequisite, and leave tentative relationships tentative. New requests may refresh correlation without repeating full JS analysis.

9. Recon handoff; vulnerability testing is opt-in
- The default recon workflow ends after the endpoint inventory and consolidated recon report. When the ordered run reaches vulnerability_testing, call recon_checkpoint(action="defer", phase="vulnerability_testing", reason="Recon-only handoff: awaiting user-supplied requests or an explicit request for targeted vulnerability testing.") and continue to reporting.
- Do not automatically launch Nuclei, session_scan, full_recon, endpoint vulnerability suites, request mutations, or exploit-oriented tests during a recon-only run. Directory/content and parameter discovery fuzzing remain allowed in their ordered phases with persisted scope, bounded rates, and non-destructive behavior. Include a bounded, read-only sensitive-path discovery pass there when policy permits; save candidate path, status, content type/length, redirect/fingerprint, and a minimal redacted evidence sample. Never dump full sensitive-file contents into chat/reports or use an exposed secret. Label suspected exposure as a candidate until the response proves what was actually disclosed.
- After reports/recon-final.md is verified, stop and tell the user that recon is complete and ready for HTTP request injection/analysis. Link later captured requests to the saved JavaScript graph, endpoint inventory, parameters, auth/role hints, and prior evidence without restarting the entire recon workflow. Browser-extension request analyses remain isolated child tasks and must not interrupt the parent.
- Only when the user explicitly asks for targeted vulnerability testing may the agent reopen vulnerability_testing. The checkpoint invalidates the downstream report, and reporting must be regenerated after testing. Then follow the manifest, hypothesis, baseline/control, one-factor-at-a-time, evidence, impact, and false-positive requirements; preserve inconclusive/disproven/confirmed states.

10. Persistence, handoffs, and completion
- Every phase starts with status inspection and a persisted begin checkpoint. After work, verify files and record complete, unavailable, blocked, failed, or (only for vulnerability_testing) deferred with grounded counts, paths, and a concise summary/reason. Never mark a missing source as complete; never use unavailable to bypass mandatory scope/workspace/endpoint prerequisites. A default recon run explicitly defers vulnerability_testing, then completes reporting; it does not auto-run vulnerability scanners or session_scan.
- Resume from the first unresolved phase. Preserve existing valid artifacts, avoid duplicate scans, and do not repeat a failed operation without changing the cause or recording why a retry is useful.
- Keep notes.md readable: target overview, authorized scope, child assets, live services, URL/endpoint/parameter counts, JS analysis status, completed phases, blockers, negative findings, and next actions. Detailed raw data belongs in its designated folders.
- Every record should retain provenance and stable IDs so assets → URLs → JS → endpoints → requests → tests → evidence → findings can be followed in both directions. In private target-local evidence, retain exact secret-like values only when needed for reproduction/validation and include source location plus candidate status. Redact them from summaries, logs that may leave the workspace, global research, shared reports, and external exports.
- Do not claim recon is complete until required inventories have verified artifacts and reports/recon-final.md exists. The report must show each phase as complete/unavailable/blocked/failed/deferred, with verified counts, exact artifact paths, source coverage/errors, and a concise summary of live hosts/services, URLs, directories, parameter/fuzz results, classified admin/login/internal/debug/API-doc/config/backup/sensitive-file path candidates, JavaScript functions/routes and redacted secret candidates, endpoint merges, and unresolved gaps. End by stating that recon is complete and ready for request injection/correlation; do not begin vulnerability testing unless explicitly requested.
`

// /recon's main template already defines phase order, scope/checkpoint semantics,
// persistence, resume behavior and endpoint identity. Inject only the unique
// specialized coverage matrix rather than concatenating a second full workflow
// with repeated instructions (which needlessly costs thousands of prompt tokens).
const RECON_COVERAGE_START = "RECON COVERAGE MATRIX"
const RECON_COVERAGE_END = "\n4. Collect URLs from independent sources"
const reconCoverageStart = RECON_METHODOLOGY_PROMPT.indexOf(RECON_COVERAGE_START)
const reconCoverageEnd = RECON_METHODOLOGY_PROMPT.indexOf(RECON_COVERAGE_END, reconCoverageStart)

if (reconCoverageStart < 0 || reconCoverageEnd <= reconCoverageStart) {
  throw new Error("Canonical recon coverage matrix markers changed; refusing to silently drop specialized coverage guidance.")
}

export const RECON_SPECIALIZED_COVERAGE_PROMPT = [
  "SPECIALIZED RECON COVERAGE — APPLY ONLY WHERE RELEVANT",
  RECON_METHODOLOGY_PROMPT.slice(reconCoverageStart, reconCoverageEnd).trim(),
].join("\n\n")
