/**
 * Canonical reconnaissance methodology.
 *
 * Recon knowledge lives here so the orchestrator does not repeatedly load overlapping
 * recon skills. This is the workflow contract; tool gates and the persisted checkpoint
 * manifest enforce the ordering independently of model instructions.
 */
export const RECON_METHODOLOGY_PROMPT = String.raw`
CANONICAL RECONNAISSANCE METHODOLOGY — FOLLOW AS ONE CONNECTED WORKFLOW

Purpose
Perform recon like a careful human researcher: understand authorization, build a stable workspace, gather evidence in a deliberate order, preserve every useful result in its proper place, and resume without repeating completed work. Every stage consumes artifacts from earlier stages and produces named artifacts for later stages. Do not jump randomly between scanners or treat running a command as proof that a stage is complete.

0. Read and validate the scope
- First identify the program/root target and read the official authorization source and exclusions. Initialize the canonical parent target workspace before doing recon.
- Preserve the original scope text/file, source URL, import time, and hash under scope/. Normalize supported entries for matching, but never silently drop unfamiliar entries: preserve them as raw scope evidence and explicitly report entries that the matcher cannot enforce. An unrecognized scope format is not permission to test it.
- Accept scope expressed as exact domains, wildcard domain families, full HTTP(S) URLs with optional explicit path/port boundaries, hostname:port entries, IPv4/IPv6 literals and CIDR ranges, and program-provided lists or files where supported. Keep exact entries exact; never turn an exact host into a wildcard. Honor exclusions before inclusions. Do not invent authorization from DNS, redirects, shared hosting, certificates, or a parent domain.
- Check every candidate host/URL against the persisted scope gate immediately before active requests. Wildcard matching must use label boundaries. Keep ports, URL paths, schemes, and hostnames distinct whenever the policy specifies them. If the official program semantics are unclear, record the ambiguity and do not broaden authorization by guesswork.
- Write a clear scope summary in scope/ and notes.md: included entries, exclusions, policy/source, supported entry types, rejected/unsupported entries, and any ambiguity.

1. Create and verify the target workspace before recon
- Use target_workspace to initialize one canonical parent workspace for the program/domain, not one unrelated root per URL or subdomain.
- Verify the returned path and the required directories: scope/, assets/, recon/, urls/, requests/, javascript/, endpoints/, testing/, findings/, evidence/, reports/, scans/, runs/, logs/, sessions/, research/.
- Save workspace metadata and notes.md. Child asset workspaces belong beneath the parent's assets/ hierarchy only after an asset is validated; keep a stable parent/child identity and preserve provenance.
- Create or resume the persisted recon checkpoint manifest. Inspect existing files and manifest before any work. Reuse valid prior outputs and record their source/time/hash; do not overwrite manual notes or make duplicate snapshots.

2. Enumerate assets and subdomains (passive first)
- Collect candidate domains/subdomains from authorized passive sources and available program data. Use multiple complementary sources where available, record which source found each asset, and deduplicate case-insensitively by normalized hostname while preserving source provenance.
- Validate candidate assets against include/exclude scope before treating them as authorized. A discovered hostname is only a candidate until checked; DNS existence does not prove program ownership.
- Store raw source outputs in recon/ or scans/, normalized unique assets in assets/, and counts/provenance in a phase summary. Record unresolved, failed, or unavailable sources honestly; do not claim exhaustive coverage from one source.
- Where relevant and permitted, inspect certificate transparency, DNS records, ASN/related infrastructure, virtual hosts, exposed repository metadata, historical hostnames, and takeover indicators as leads only. Never test a takeover or third-party infrastructure without explicit scope authorization.

3. Resolve and profile live hosts/services
- For each in-scope candidate, record DNS resolution, CNAME chain, address, HTTP(S) reachability, status, redirects, title, TLS/certificate observations, server/technology hints, and observed ports/services when authorized.
- Preserve host-to-IP and hostname-to-service relationships; do not merge distinct virtual hosts just because they share an IP.
- Store raw outputs in scans/ and normalized inventory in assets/ and recon/. Mark dead/unresolved hosts as observations rather than deleting them; revisit only when new evidence warrants it.
- Use bounded, non-destructive discovery. Do not start broad vulnerability scanning or directory brute forcing in this phase.

4. Collect URLs from independent sources
- Combine crawler output, robots.txt, sitemap.xml, historical/passive URL sources, HTML links/forms, OpenAPI/Swagger descriptions, GraphQL schema/introspection evidence when accessible and authorized, source maps, and browser-extension observations.
- Keep source provenance per URL. Canonicalize only safe identity components; do not discard meaningful path, method, query parameter names, content type, or authentication context. Deduplicate without losing query/parameter variants or evidence that different sources found the same route.
- Save raw source outputs under recon/ or scans/ and the normalized URL inventory under urls/. Track crawl depth/coverage and failed sources.
- Discover API specifications and alternate entry points as evidence, not as proof of exploitable behavior. Active probing of APIs remains behind the scope gate and phase gate.

5. Discover and inventory parameters
- Extract path, query, form, JSON, XML, multipart, header, cookie, and GraphQL variables from captured requests, forms, URL sources, and API specifications. Preserve parameter location and method; names that look similar in different locations are not duplicates.
- Use passive observations first. Use parameter-discovery tools only after URL collection has completed and scope/phase gates permit them. Store parameter inventories under endpoints/ and link each item to its source URL/request/spec.
- Track reflected/observed parameters separately from guessed candidates; do not claim a parameter is accepted merely because a tool generated its name.

6. Collect, deduplicate, and analyze JavaScript
- Collect script URLs, inline scripts, source maps, and script references from authorized pages and observed browser traffic. Canonicalize URLs carefully and deduplicate by canonical URL plus content hash/version. Analyze each distinct content version once; re-run only when content changes or new correlation evidence arrives.
- Preserve the original response and metadata under javascript/. Produce structured analysis containing discovered route templates, HTTP methods, parameter names and locations, function/export names, API base paths, feature flags, auth/session/cookie/header signals, WebSocket/GraphQL references, source-map paths, sensitive-data references, and security-relevant sinks. Treat all extracted values as leads, not findings.
- Record source URL/hash, extraction method, analysis version, and confidence. Never invent a route from a generic string without evidence.
- Match JS routes to observed requests by origin and exact path/template semantics. Static path segments must match exactly; dynamic placeholders may match one path segment only. Host-only or prefix-only similarity is tentative, never a confirmed relationship. Save the graph and relationships in javascript/ and endpoints/.

7. Build the endpoint inventory
- Consolidate URLs, captured requests, JS-derived candidates, and API-spec routes into a normalized endpoint record. Preserve method, origin, path/template, parameter locations, content type, authentication/role context, source IDs, response status/shape, and links to the relevant asset and JS source.
- Distinguish observed endpoints from inferred candidates. Deduplicate identical evidence while preserving multiple sources. Store machine-readable inventory under endpoints/ and readable endpoint notes linked to request IDs/evidence paths.
- Endpoint inventory is the handoff contract for later testing. Before marking the phase complete, verify that artifacts exist, counts are grounded, and the links point to real saved records.

8. Browser extension request intake runs continuously and independently
- Every extension-captured request is its own short-lived child analysis task. It must not interrupt, replace, or pollute the parent recon session, prompt transcript, active run, or logs.
- Resolve the canonical parent/child target workspace and re-check persisted scope. Store request and response safely under requests/ with redacted secrets and stable request IDs; link it to its asset, endpoint, credentials/role context, JS evidence, and existing recon findings.
- Update endpoint notes and the evidence graph with what the request confirms or contradicts. Analyze method/body/parameters/auth state/response behavior, identify new endpoints or parameter variants, and queue only the relevant follow-up questions. Do not launch full-target recon for each request.
- If no authorized workspace, no captured JS, or no matching endpoint exists, analyze the supplied request as far as possible, record the missing prerequisite, and leave tentative relationships tentative. New requests may refresh correlation without repeating full JS analysis.

9. Only after inventory: targeted vulnerability testing
- Check the manifest and saved evidence before each test. Form a specific hypothesis from the endpoint's behavior, parameters, authentication/role context, technology, and prior evidence.
- Choose the smallest relevant test, keep requests within authorization and rate limits, preserve a baseline, vary one factor at a time, and record exact request/response evidence. Do not run broad fuzzing/scanners as a substitute for understanding the endpoint.
- Track each test as not-tested, running, blocked, inconclusive, disproven, or confirmed. A negative result must say what was tested and what it rules out; it must not imply the entire vulnerability class is absent.
- Findings require reproducible evidence and impact reasoning. Store test plans/results in testing/, proof in evidence/, candidate/final findings in findings/, and reports in reports/.

10. Persistence, handoffs, and completion
- Every phase starts with status inspection and a persisted begin checkpoint. After work, verify files and record complete, unavailable, blocked, or failed with grounded counts, paths, and a concise summary. Never mark a missing source as complete; never use unavailable to bypass mandatory scope/workspace/endpoint prerequisites.
- Resume from the first unresolved phase. Preserve existing valid artifacts, avoid duplicate scans, and do not repeat a failed operation without changing the cause or recording why a retry is useful.
- Keep notes.md readable: target overview, authorized scope, child assets, live services, URL/endpoint/parameter counts, JS analysis status, completed phases, blockers, negative findings, and next actions. Detailed raw data belongs in its designated folders.
- Every record should retain provenance and stable IDs so assets → URLs → JS → endpoints → requests → tests → evidence → findings can be followed in both directions. Redact tokens/cookies/secrets in notes and logs.
- Do not claim recon is complete until required inventories and their artifacts have been verified. End with a concise human-readable summary of what was discovered, what was not available, what remains blocked, and the next exact phase.
`
