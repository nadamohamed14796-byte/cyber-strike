---
name: recon-master
description: "Professional scope-aware reconnaissance handbook with one workflow, conditional specialist procedures, clear evidence standards, and phase-based outputs."
category: information-gathering
version: "2.1.0"
author: "CyberStrike contributors"
tags: [recon, reconnaissance, passive-recon, active-recon, osint, subdomain, dns, asn, cidr, origin-ip, vhost, ports, services, http, tls, crawling, endpoints, cms, gitlab, email-security, visual-recon, error-logs, asset-inventory, scope, evidence, tool-selection]
tech_stack: [dns, http, tls, tcp, javascript, api, cloud, browser, git, smtp]
prerequisites: []
chains_with: [community-tool-selection, attack-javascript-analysis, attack-shadow-api, attack-subdomain-takeover, attack-api-contract-testing]
---

# Recon Master

## Purpose and operating model

This is the single entry point for reconnaissance in CyberStrike. It combines the core methodology and eleven specialist procedures into one ordered handbook. Load it after scope is accepted and persisted, and before invoking reconnaissance tools.

The handbook is **workflow-first and branch-aware**:
- Follow the core methodology for every engagement.
- Select specialist chapters only when the target shape, evidence, technology, or explicit authorization makes them relevant.
- Do not run every technique against every target merely because it exists in this file.
- Keep discovery, attribution, authorization, and vulnerability proof as separate claims.

## Contents

1. [Core reconnaissance methodology](#01-core-reconnaissance-methodology)
2. [Subdomain enumeration and validation](#02-subdomain-enumeration-and-validation)
3. [ASN and infrastructure mapping](#03-asn-and-infrastructure-mapping)
4. [Origin IP exposure assessment](#04-origin-ip-exposure-assessment)
5. [Port and service discovery](#05-port-and-service-discovery)
6. [Virtual-host enumeration](#06-virtual-host-enumeration)
7. [CMS and component fingerprinting](#07-cms-and-component-fingerprinting)
8. [Visual reconnaissance and application clustering](#08-visual-reconnaissance-and-application-clustering)
9. [Public GitLab project reconnaissance](#09-public-gitlab-project-reconnaissance)
10. [Email domain security assessment](#10-email-domain-security-assessment)
11. [Exposed error-log analysis](#11-exposed-error-log-analysis)

## Mandatory startup contract

Immediately after scope acceptance and persistence:

1. Read the program policy, exact in-scope assets, exclusions, wildcard semantics, allowed methods, rate limits, scan windows, and authentication constraints.
2. Initialize or resume the canonical target workspace and recon_checkpoint; reuse existing evidence instead of repeating completed work.
3. Load recon-master through SkillTool. This is the required reconnaissance playbook.
4. Load community-tool-selection, then read its single TOOLING_CATALOG.md using the path and base directory returned by the skill loader. Never resolve that path against the target workspace.
5. Build the engagement plan from the scope shape and evidence. Start with passive sources, then run only authorized active validation.
6. Persist evidence and checkpoint state incrementally. Report verified outputs, skipped branches with reasons, errors, coverage gaps, and next actions.

Do not ask the user to repeat information already present in the persisted scope. Ask only when authorization or a genuinely required input is missing.

## Scope and authorization gates

- An asset is eligible only when it is explicitly in scope or covered by the program's documented wildcard semantics.
- A discovered hostname, IP, ASN, CIDR, sibling domain, cloud address, repository, or mail system does not automatically become authorized.
- Shared hosting, shared CDNs, cloud-provider ranges, third-party SaaS, and infrastructure adjacency are attribution clues—not scope expansion.
- Apply exclusions before scheduling requests. Keep exclusions effective across redirects, DNS results, CNAME chains, discovered links, and related infrastructure.
- Passive collection may reveal leads outside scope; retain only the minimum attribution needed and do not actively probe those leads.
- Use GET for ordinary read-only discovery. Use HEAD only when reliable. POST requires documented read-only semantics or a safe test fixture plus explicit policy permission. Do not use PUT, PATCH, DELETE, or other state-changing methods in routine recon.
- Credential-like values, tokens, personal data, and private records must be redacted. Never validate discovered credentials by logging in or replaying them.

## Engagement workflow

| Step | Work | Required decision or output |
|---|---|---|
| 1. Establish baseline | Normalize scope, exclusions, existing inventory, prior checkpoints, and known program policy | A stable scope manifest and a resumable workspace |
| 2. Passive discovery | Collect permitted public DNS, certificate, search, code, documentation, and other relevant sources | Deduplicated candidate assets with source and timestamp |
| 3. Attribute assets | Resolve DNS, identify ownership signals, classify wildcard behavior, and separate first-party from shared infrastructure | Confidence-rated assets; no inferred scope expansion |
| 4. Validate live surfaces | Check only eligible hosts with low-impact HTTP/TLS and any explicitly permitted service checks | Live-host and service evidence with status, method, and tool provenance |
| 5. Map applications | Crawl eligible web surfaces, collect URLs and parameters, identify technologies, and cluster distinct applications | An application inventory and prioritized endpoint queue |
| 6. Run conditional chapters | Select the relevant specialist procedures from the routing matrix below | Chapter-specific evidence and an explicit applicability decision |
| 7. Reconcile and hand off | Deduplicate assets/endpoints, correlate evidence, record gaps, and checkpoint | A complete inventory, prioritized next tests, and a reproducible handoff |

## Specialist routing matrix

| Chapter | Run when | Do not run when | Main deliverable |
|---|---|---|---|
| 02. Subdomains | The scope includes a root domain or wildcard and broader host coverage is useful | Only a single exact URL is in scope and no permitted domain expansion applies | Candidate and resolved subdomains with wildcard/ownership confidence |
| 03. ASN/infrastructure | A confirmed organization domain or IP needs attributable infrastructure context | ASN membership would be used to expand active scope | Attributable prefixes, hosting context, and confidence-rated asset relationships |
| 04. Origin IP | A confirmed app is behind a CDN/reverse proxy and edge-vs-origin behavior matters | There is no evidence of an edge proxy or no permitted origin checks | Candidate origins plus controlled evidence of direct reachability and control differences |
| 05. Ports/services | Explicitly authorized hosts/IPs need service inventory | Only web-host scope exists without permission for network service discovery | Bounded port/service inventory with host attribution |
| 06. Virtual hosts | Authorized infrastructure may route multiple hostnames or tenants | Candidate IPs are shared/unattributed or host-header probes are not permitted | Vhost candidates, response clusters, and ownership confidence |
| 07. CMS | First-party CMS fingerprints appear in headers, markup, assets, or known paths | Platform identity is speculative or based on a single weak signature | Corroborated platform/component inventory and safe follow-up leads |
| 08. Visual recon | Screenshots, titles, favicons, and layout similarity can prioritize many live applications | Screenshots add no value or would expose personal/sensitive data | Reproducible visual clusters and review priorities |
| 09. GitLab | An organization namespace or project has a defensible ownership relationship | A public username/project is merely name-similar or unrelated | Public project/artifact/CI inventory with attribution and redacted disclosure leads |
| 10. Email security | A confirmed organization-owned mail domain is in scope | The domain is third-party or mail testing is excluded | SPF/DKIM/DMARC/MX/MTA-STS/TLS-RPT posture with validation limits |
| 11. Error logs | An in-scope application or public artifact exposes a plausible log/debug resource | A candidate is out of scope or collection would expose excessive personal data/secrets | Minimal redacted proof, disclosure classification, and impact assessment |

## Tool selection and runtime discipline

The community-tool-selection/TOOLING_CATALOG.md is the only shared tool catalog. This handbook defines the task and evidence requirements; the catalog defines tool candidates, installation guidance, and version/flag verification. Do not create per-phase tool inventories.

Before invoking a CLI tool, verify its actual path, installed version, platform compatibility, and the installed version's own help output. Compare with official upstream release notes/docs when current behavior matters. Record the installed version separately from the upstream version checked. Never assume a catalog version is installed, invent a flag, silently upgrade a pinned dependency, or reuse stale CLI syntax.

Flag selection must follow the evidence gap:
- All-source/all-resolver modes: use when multiple independent sources materially increase coverage and the request/rate budget supports them.
- Recursive modes: use only when nested/delegated naming or a documented recursion benefit exists.
- Wordlists/brute force: require explicit active permission, a justified list, and a bounded rate.
- All-port/full-range modes: require explicit IP/CIDR authorization and a written reason; otherwise prefer common/evidence-derived ports.
- Technology-specific flags: require a corroborated fingerprint.
- Large scopes: batch, deduplicate incrementally, checkpoint continuously, and process every eligible item without arbitrary item caps.
- Urgent or rate-limited scopes: prioritize high-signal sources and existing evidence; reduce concurrency and back off rather than forcing volume.

### HTTP method policy

GET is the default for read-only pages, headers, robots.txt, sitemap, assets, API docs, and normal crawling. HEAD is optional only when the server handles it reliably; fall back to GET when unsupported or materially different. POST is not a generic fallback: use it only when documented endpoint semantics or a normal application workflow requires it, the operation is read-only or uses a safe test fixture, and policy permits it. Preserve content type, body schema, authentication context, and provenance. Keep method-specific endpoint variants; never merge GET and POST into one operation. State-changing methods are outside routine reconnaissance.

## Evidence, inventory, and handoff contract

Every observation must retain enough context to reproduce and judge it:
- Target/asset and normalized URL or network locator.
- Observation type, source, source URL or input artifact, timestamp, and collection method.
- Tool name/version and relevant options when a tool produced the result.
- Scope/ownership status, confidence, and the reason for that confidence.
- HTTP method, status, relevant headers, and request/response artifact references when applicable.
- Errors, rate limits, exclusions, redirects, unresolved attribution, and other limitations.

Keep raw output only when it adds unique evidence, reproducibility, or diagnostic value. Prefer normalized JSON/JSONL records and a small set of canonical inventories over a pile of duplicate files. Deduplicate incrementally without discarding source provenance.

### Endpoint and JavaScript handoff

Route JavaScript and API observations to attack-javascript-analysis and the canonical endpoint inventory. Gather JS URLs from every permitted source, deduplicate URLs, fetch eligible files locally, and analyze each downloaded file; a failed or missing download must be recorded rather than silently treated as analyzed. Do not impose arbitrary file-count caps.

Merge static JS candidates and observed HTTP traffic into the same canonical endpoint identity where appropriate, but preserve their provenance and confidence. Keep separate method-specific variants (GET, POST, and so on). A method seen only in traffic is observed-only evidence; do not claim that static JavaScript declared it. Preserve route, parameters, headers, auth signals, GraphQL operations, request/response references, and the source file or captured request. Static endpoints are leads, not proof of reachability or vulnerability.

### Completion checklist

Recon is complete for the current scope window when:
- Every in-scope asset and relevant candidate has a disposition: verified, excluded, duplicate, unresolved, or deferred with reason.
- Applicable specialist branches have been run or explicitly marked not applicable with a reason.
- No arbitrary cap silently discarded eligible hosts, URLs, or files.
- Tool failures, throttling, unsupported options, and skipped sources are recorded.
- Assets, endpoints, and method variants are deduplicated without losing provenance.
- Secrets and personal data are redacted; no discovered credential was used.
- The phase matrix and recon_checkpoint reflect the final state and next action.

The canonical phase/artifact contract is [RECON_PHASE_TOOL_MATRIX.md](RECON_PHASE_TOOL_MATRIX.md). Use its phase-specific outputs and stop conditions; do not recreate a competing matrix here.

## Specialist playbooks

The following chapters retain the original specialist procedures, reorganized into a single execution-oriented order. Metadata is condensed into each chapter profile; substantive methodology, evidence, verification, tooling guidance, false-positive controls, and handoff instructions are retained.

## 01. Core reconnaissance methodology

### Reconnaissance Methodology

### Chapter profile

**Purpose:** Plan and execute evidence-led, scope-locked reconnaissance that produces a deduplicated, prioritized testing queue

**Prerequisites:** Written authorization, scope rules, exclusions, and permitted testing intensity

**Technology:** `dns`, `http`, `tls`, `javascript`, `api`, `cloud`

**Coverage tags:** `recon`, `enumeration`, `osint`, `subdomain`, `asset-inventory`, `scope`, `infrastructure-lifecycle`, `api-contracts`, `dependency-risk`

**Related security workflows:** `attack-subdomain-takeover`, `attack-idor-automation`, `attack-api-contract-testing`, `attack-dependency-cve-scanning`, `attack-triage-validation`

**Legacy source:** `recon-methodology` v"1.2.0"; credited to CyberStrike contributors; consolidated with upstream attribution.

**Source attribution:** [1](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/web2-recon/SKILL.md) · [2](https://github.com/uphiago/recon-skills/blob/main/meta/recon-playbook/SKILL.md) · [3](https://github.com/uphiago/recon-skills/blob/main/meta/pentest-playbook/SKILL.md) · [4](https://github.com/uphiago/recon-skills/blob/main/recon/subdomain-enumeration/SKILL.md) · [5](https://github.com/uphiago/recon-skills/blob/main/recon/web-enumeration/SKILL.md)

#### Mission

Turn an authorized target list into a scope-checked, deduplicated inventory and prioritized queue of hypotheses. Recon observations are leads, not findings. The goal is to identify the smallest next test likely to establish a meaningful security property while minimizing duplicate work and operational risk.

#### 1. Engagement contract

Before any active request, record:
- exact assets, wildcard rules, exclusions, third-party services, and program links;
- allowed recon methods, request rate, scan windows, and prohibited techniques;
- authentication prerequisites and test accounts;
- workspace and evidence-retention location;
- stop conditions for instability, rate limits, unexpected sensitive data, or scope ambiguity.

Public reachability does not imply authorization. Every discovered hostname, IP, API, repository, or third-party service must pass the scope resolver before active testing.

#### 2. Recon pipeline

##### A. Normalize and lock scope

Canonicalize hostnames, schemes, ports, trailing dots, IDNs, wildcard entries, and exclusions. Preserve the original candidate and the normalization decision. Resolve wildcard rules conservatively; do not treat an entire shared CDN or cloud provider as in scope. Keep scope decisions explicit: in-scope, out-of-scope, needs-owner-confirmation, or passive-only.

##### B. Passive discovery first

Use program-provided asset lists, certificate transparency, public DNS history, public code search, archived URLs, public repositories, and other permitted passive sources. Preserve provenance, timestamp, and source reliability. Do not scrape private systems, use leaked credentials, or infer permission from exposed data.

##### C. DNS and infrastructure mapping

Resolve candidates and distinguish confirmed records, aliases, wildcard DNS, parked domains, unresolved names, and stale records. Keep CNAME chains and provider fingerprints. A dangling-looking record or cloud-provider fingerprint is only a lead; verify ownership and current scope before any takeover-related check. DNS resolution is not proof that a hostname is owned or in scope.

##### D. HTTP and service validation

For in-scope hosts, record status, title, redirect chain, TLS certificate, content type, stable response fingerprints, and authentication behavior. Use bounded timeouts, conservative concurrency, and a documented request budget. Avoid broad port scans or content brute force unless explicitly permitted. Do not follow redirects to a different host without rechecking scope.

##### E. Web and API enumeration

Collect URLs from permitted crawling, application traffic, JavaScript bundles, source maps, API documentation, robots/sitemap files, and known application routes. Normalize and deduplicate while retaining parameter names, methods, auth context, source, and discovery time. Separate public routes from authenticated routes, and read-only operations from writes/destructive actions.

For JavaScript assets, retain the asset URL and hash, source-map availability, extracted endpoint/function references, and the evidence connecting each reference to an observed request. Treat strings and comments as leads until runtime traffic or documentation supports them.

##### F. Technology and ownership signals

Record framework, CDN, cloud provider, CMS, API style, authentication mechanism, and likely tenant boundaries only when evidence supports the inference. Keep confidence and evidence for each fingerprint; do not convert a banner, version string, or scanner guess into a vulnerability claim.

##### F.1 Infrastructure and dependency lifecycle

Build a small relationship map from evidence already found: first-party hosts, CNAME destinations, storage/CDN bindings, API hosts and versions, external script/service origins, mail/DNS records when relevant, and source artifacts. Record the exact source and confidence for each relationship. Do not expand into a provider's shared infrastructure or treat an external destination as in scope just because a first-party asset references it.

Classify each dependency as active, deprecated/legacy, orphan-suspected, or unknown. For an orphan-suspected hostname, use current DNS and provider-specific, read-only evidence; route to `attack-subdomain-takeover` only when the hostname is in scope. Never claim a resource, change DNS, publish content, or infer takeover from a CNAME/404 alone. For undocumented or version-drifted API surfaces, preserve version and observation context and route to `attack-shadow-api` or `attack-api-contract-testing`.

When an explicitly authorized source checkout or source artifact contains manifests/lockfiles, route it to `attack-dependency-cve-scanning`. A package name seen in a bundle is not proof of an installed version; a CVE match is not proof that vulnerable code is reachable or deployed. Keep this as an evidence-linked risk inventory, not a new mandatory phase. Merge relationships into the existing target inventory/report instead of creating one file per discovered dependency.

##### G. Authentication-aware coverage

Track which endpoints were tested anonymously and with each authorized role. Record login walls, registration requirements, MFA/OTP dependencies, session expiry, and routes unavailable because the test account lacks permission. Do not label an endpoint untested as safe merely because authentication was unavailable; mark it blocked and retain the dependency.

##### H. Queue construction

For each candidate, store:
- canonical target and scope decision;
- source/provenance and first/last-seen timestamps;
- observation and confidence;
- explicit security hypothesis and expected policy;
- required account/role and prerequisites;
- bounded next validation step and stop condition;
- priority, deduplication fingerprint, and status.

Prioritize trust boundaries, newly discovered assets, exposed APIs, cross-tenant behavior, sensitive state transitions, and changes from the previous recon wave. Avoid ranking solely by number of URLs or scanner severity.

#### 3. Delta analysis and resumability

Compare new observations with the previous verified snapshot: hosts/DNS/CNAME/provider changes, TLS/HTTP fingerprints, URL/method/parameter combinations, JavaScript content hashes, authentication state, and third-party destinations. Reuse earlier evidence only when its input, tool/settings, and source freshness/TTL remain valid. Revalidate changed or stale evidence rather than repeating a whole scan.

Persist item-level outcomes and cursors in the canonical checkpoint/source ledger. Resume unfinished work without resetting completed or rejected items. Missing credentials are a blocker, not an empty/safe result. Keep ownership/scope confidence separate from vulnerability confidence; queue only signal-matched follow-up hypotheses with required roles, baseline/control, one bounded next step, and a stop condition.

#### 4. Evidence and data hygiene

Keep raw outputs outside the source repository unless explicitly required. Store redacted evidence references, not live cookies, bearer tokens, API keys, recovery links, personal data, or secret-bearing environment values. Record the minimum evidence needed to reproduce an observation. Ensure findings can be traced back to asset, request, response, account context, and discovery source.

#### 5. Stop conditions

Stop when a target is out of scope, rate-limited, unstable, serving unexpected private data, or ownership is uncertain. Stop active testing if redirects cross scope, credentials appear in an unexpected destination, or a test triggers real-world side effects. Do not broaden testing after the security property is already demonstrated.

#### 6. Quality gates

Before handing a lead to a testing skill:
- [ ] scope is explicitly confirmed;
- [ ] observation is reproducible and provenance is recorded;
- [ ] duplicate hosts/URLs are normalized without losing method or parameter context;
- [ ] confidence and uncertainty are explicit;
- [ ] hypothesis and expected policy are written down;
- [ ] next test is bounded, authorized, and has a stop condition;
- [ ] authentication blockers are distinguished from negative results;
- [ ] lead is not mislabeled as a vulnerability;
- [ ] evidence contains no secrets or unnecessary personal data.

#### Output contract

Return normalized asset and endpoint inventories, scope decisions, provenance, delta summary, authentication coverage, deduplicated prioritized hypotheses, blockers, and next-step recommendations. Keep discovery facts separate from security conclusions.

#### Recon-specific tool guardrails

- Nuclei is not part of default reconnaissance. Use it only in a separate, explicitly requested testing phase with reviewed templates and required authorization.
- Use local `git diff` only when reviewing saved artifact changes; it does not replace evidence validation.

Reuse `recon_checkpoint` as the only phase-state ledger. Do not create a second phase manifest or per-phase runner manifest that duplicates its states. Add a small run/item record only when the existing checkpoint/source ledger lacks a necessary cursor, tool version, artifact hash, exit code, or failure detail. Keep raw evidence only when needed for provenance/debugging, normalize once into canonical inventories, and report actual commands/tools used, paths, verified counts, failures, confidence, and the next relevant specialist skill.

#### Adaptive tool selection

The canonical `/recon` prompt and `recon_checkpoint` own initialization, persisted scope, phase order, checkpoint actions, resumability, canonical outputs, and completion/reporting. The checkpoint defines **what work is current and what artifacts prove completion**, not a fixed phase-to-tool assignment. Every connected/registered tool can be considered at every active checkpoint; choose based on its actual capability, current evidence gap, verified availability, saved artifacts, and policy. Consult the single `TOOLING_CATALOG.md` reference through `community-tool-selection` and the `RECON_PHASE_TOOL_MATRIX.md` companion through this skill's returned `<skill_files>` and `Base directory`. The catalog describes candidate tools; the matrix defines phase artifacts and completion criteria. Neither is an execution allowlist.

Load specialist skills only when observed assets, technology, or evidence make their detailed procedure relevant. Select a useful combination of tools dynamically; add alternatives for distinct coverage, corroboration, or recovery, not merely because they are listed. Check schemas/versions only for candidates being considered, avoid repeated preflight/installing the entire catalog, and never reject a suitable tool only because its nominal category differs from the active checkpoint. Distinguish zero results from failure, unavailable, blocked, skipped-by-selection, not applicable, and pending work. The explicit vulnerability-testing checkpoint and all persisted scope, authorization, impact, and rate controls remain mandatory. A phase is complete only after applicable work and saved artifacts are verified, with remaining gaps stated honestly.


---

---

## 02. Subdomain enumeration and validation

### Subdomain Enumeration and Validation

### Chapter profile

**Purpose:** Build a deduplicated, attribution-aware subdomain inventory using passive sources, DNS resolution, certificate transparency, and bounded active discovery.

**Prerequisites:** A confirmed organization root domain and applicable discovery permissions

**Technology:** `DNS`, `HTTP`, `TLS`, `Linux`

**Coverage tags:** `recon`, `subdomain`, `DNS`, `certificate-transparency`, `asset-inventory`

**Related security workflows:** `attack-subdomain-takeover`

**Legacy source:** `recon-subdomain-enumeration` v"1.0.0"; credited to cyberstrike-official.

#### Objective

Produce a reliable inventory of candidate subdomains, verify which names are live and attributable, and prioritize distinct applications for later security testing. A discovered hostname is not automatically owned or authorized.

#### Testing Methodology

##### 1. Establish the root-domain set

Start with the program's canonical domains and verified subsidiaries. Normalize case, trailing dots, IDNs, wildcard entries, and duplicate records. Keep root-domain ownership evidence with the inventory.

##### 2. Collect passive candidates

Combine certificate transparency, passive DNS, search indexes, public DNS datasets, first-party links, public documentation, and organization-controlled repositories. Record source and observation time for each hostname. Passive discovery is often enough to reveal legacy and API names without active probing.

##### 3. Add bounded active discovery when permitted

Use a restrained wordlist derived from known naming conventions and the application's architecture. Keep request rate and concurrency conservative. Expand the wordlist based on evidence rather than running an unbounded dictionary against every candidate domain.

##### 4. Resolve DNS and identify wildcard behavior

Resolve A, AAAA, CNAME, MX, and relevant TXT records. Compare candidate answers with random labels under the same parent to detect wildcard DNS. Preserve full CNAME chains and TTLs; distinguish NXDOMAIN, NODATA, SERVFAIL, and transient resolver failures.

##### 5. Validate live web services

For confirmed in-scope names, collect HTTP status, final URL, title, TLS certificate/SAN, content type, and a stable body fingerprint. Compare with random-host controls to eliminate wildcard pages, parked domains, and SPA catch-alls. Record non-HTTP services separately.

##### 6. Attribute and cluster assets

Correlate DNS, certificate, HTTP, application branding, and infrastructure data. Classify third-party SaaS, shared hosting, CDN edges, and same-name collisions. Quarantine ambiguous hosts until ownership is corroborated.

##### 7. Prioritize distinct applications

Prioritize authentication, API, staging/preview, admin, upload, billing, tenant, legacy, and file-hosting surfaces. Feed confirmed hosts into virtual-host, origin, takeover, and application-specific workflows.

#### What This Produces

- A normalized hostname list with provenance and timestamps.
- DNS resolution state, wildcard status, and service metadata.
- Ownership confidence and explicit quarantine for ambiguous assets.
- A prioritized list of distinct applications rather than a raw count of names.

#### Evidence Requirements

- Source URL/tool and observation timestamp for each candidate.
- DNS chain and relevant records for live assets.
- HTTP/TLS fingerprint and random-host control.
- Clear reason for ownership attribution and scope classification.
- A vulnerability report must include separate proof of impact; subdomain discovery alone is not a finding.

#### Source coverage and count semantics

For every source family, retain an explicit outcome: `not-attempted`, `attempted`, `succeeded`, `zero-results`, `failed`, or `blocked`. Include the observation time, relevant query/configuration, exit status or response state, and a concise failure/block reason. A successful zero-result response is not a failure and does not prove that the wider asset set is empty; an unavailable or blocked source is a coverage gap, not a zero result.

Keep these counts separate:
- Raw source candidates before normalization.
- Unique normalized hostnames after deduplication.
- Scope-eligible candidates after applying inclusions and exclusions.
- DNS-resolved candidates, with wildcard and transient-resolution outcomes separated.
- HTTP/TLS-live hosts.
- Assets with corroborated first-party attribution.

Preserve the contributing source references when several sources identify the same hostname. Do not present raw candidate volume as verified asset coverage, and do not count a third-party/shared service as first-party merely because it appears in DNS, a certificate, or a shared IP range.

Continue with independent, relevant sources while they can add meaningful coverage. Do not repeat an unchanged source/query after a deterministic failure or a completed zero-result response; choose a materially different source or record the unresolved coverage gap. There is no fixed candidate-count ceiling, but scope, rate, and safety controls remain authoritative.

#### Chapter-specific implementation notes and resources

Use the `TOOLING_CATALOG.md` companion listed in `community-tool-selection`'s returned `<skill_files>` (read it using that skill's returned `Base directory`; do not resolve against the target workspace) as the only tool/API/CLI/helper catalog. Select sources adaptively; inspect registered schemas and preflight only external commands that may actually be used. The catalog lists optional helpers and the simple canonical output contract. A listed candidate is not proof of installation, suitability, or authorization.

For a candidate CLI, resolve tool_preflight.py from the installed skill/catalog root and invoke it by absolute path once per runtime/version. Do not assume `.cyberstrike/skill/scripts/` is relative to the target workspace. If the helper is unavailable, use `command -v` and the tool's documented version/help check. Review official docs and flags before use; apply program scope and rate limits independently of tool availability.

Official references: [ProjectDiscovery subfinder](https://github.com/projectdiscovery/subfinder), [OWASP Amass](https://github.com/owasp-amass/amass), [ProjectDiscovery dnsx](https://github.com/projectdiscovery/dnsx), and [Certificate Transparency](https://certificate.transparency.dev/).

#### Enumeration Coverage Matrix

| Source/phase | Strength | Typical blind spot | Validation |
|---|---|---|---|
| Certificate transparency | Names in issued certificates | Old certificates and third-party SANs | Resolve and confirm current app |
| Passive DNS | Historical and current DNS associations | Stale records and incomplete datasets | Re-resolve and preserve TTL |
| First-party links/repositories | High attribution value | Incomplete or outdated references | Check current DNS and application response |
| Search indexes | Human-discoverable pages and docs | Index lag and noisy naming collisions | Confirm live host and ownership |
| Active wordlist | Finds undocumented conventional names | Rate limits, wildcard noise, missed unusual names | Low-rate probes and random-label controls |
| DNS wildcard analysis | Detects catch-all resolution | Parent-specific and provider-specific behavior | Compare multiple random labels |
| HTTP/TLS fingerprinting | Distinguishes applications | Dynamic pages and shared certificates | Stable markers, redirect chain, repeated capture |

#### Verification and False Positives

- Use random labels to identify wildcard DNS and catch-all web responses.
- Do not equate a certificate SAN with current ownership or reachability.
- Confirm third-party SaaS tenant attribution before further testing.
- Normalize IDNs and trailing dots consistently to avoid duplicate counts.
- Treat DNS resolution as discovery evidence, not proof of vulnerability.
- Keep unresolved candidates quarantined instead of probing them automatically.

#### Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. there is no fixed hypothesis-count ceiling; continue distinct, decision-relevant hypotheses while authorized, and stop when evidence or a real safety/policy boundary resolves the branch. Prefer passive sources first, deduplicate candidates, and use active checks only when the asset and activity are explicitly in scope.

##### Evidence record and confidence

For each candidate, preserve normalized asset, source/provenance, observation time, scope proof, resolver/HTTP/tool and relevant version, corroborating source, raw-evidence location when retained, negative control, attribution confidence, next action, and related-skill trigger. Separate **asset confidence** (is it related to the organization?) from **security confidence** (is a vulnerability demonstrated?).

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. C1/C2 are not confirmed vulnerabilities.

##### Skill-specific next steps

1. Confirm the root domain is in scope, then collect passive names from certificate transparency, first-party links, approved passive providers, and installed tooling; keep provenance per hostname.
2. Normalize wildcards, case, trailing dots, IDNs, and duplicate results while preserving source attribution and observation timestamps. Retain raw source data only when it adds unique evidence, reproducibility, or diagnostic value; otherwise merge normalized observations directly into the canonical ledger and host list.
3. Resolve A/AAAA/CNAME/MX as relevant, inspect the CNAME chain and TTL, and compare multiple random labels to detect wildcard DNS. Distinguish NXDOMAIN, NODATA, SERVFAIL, and transient resolver failures.
4. Validate live HTTP/TLS hosts with conservative timeouts and stable fingerprints; use random-host and random-path controls to eliminate wildcard responses, parked domains, CDN edges, and soft-404 pages.
5. Quarantine ambiguous ownership and third-party SaaS until corroborated. Return confidence, evidence, scope decision, deduplication key, and the specific next recon/attack skill trigger; discovered names are not findings.

##### Deduplication and stop rules

Normalize case, trailing dots, scheme/port, redirects, canonical names and resolved addresses before deduplication. Detect wildcard DNS, shared hosting, CDN/edge responses, soft-404s and stale records before ranking counts. Stop on exclusions, ownership ambiguity, unexpected sensitive data, throttling, instability or boundaries requiring further permission. Never claim ownership or register dangling resources.

##### Handoff format

Return candidates with scope/provenance, confidence level, evidence path, deduplication key, negative control, priority rationale, safe next step and trigger for any linked attack skill. Promote a candidate to active testing only after scope and attribution are confirmed; promote it to a finding only after the relevant attack skill verifies the security boundary.

##### CyberStrike workspace handoff

A candidate host belongs in the existing program workspace inventory by default. Merge corroborated hosts and their source, observation time, DNS/HTTP evidence, and attribution confidence into the canonical parent files; do not create a child workspace for every subdomain.

Use `cyberstrike target attach <program-root> <asset-url> --kind <api|application|...>` only when the operator explicitly requests an independent investigation workspace for that specific in-scope asset and separate notes/evidence are genuinely needed. The command must use the persisted scope and reject excluded, third-party, ambiguous, or out-of-scope assets. Verify placement with `cyberstrike target tree <program-root>` only after an attachment is actually requested and created. Asset registration is not a vulnerability finding.

#### References

- Source merged: [uphiago/recon-skills — recon/subdomain-enumeration/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/subdomain-enumeration/SKILL.md)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Certificate Transparency](https://certificate.transparency.dev/)
- [RFC 1034 — Domain Names: Concepts and Facilities](https://www.rfc-editor.org/rfc/rfc1034)

#### Targeted quality-loop enrichment (2026-10-19)

##### Discovery provenance and wildcard handling
Keep each candidate with source, timestamp, DNS answers/CNAME chain, wildcard-DNS check, HTTP fingerprint, ownership evidence, and explicit scope decision. Deduplicate normalized hostnames while preserving their discovery sources; never discard method, port, or auth context when later joining URL inventories. Correlate passive findings with current DNS and a second independent ownership signal before active probing. A historical hostname, third-party CNAME, wildcard response, or cert-transparency entry is a lead—not proof of live ownership or permission. Delta newly observed hosts against earlier runs, and route confirmed HTTP hosts to web recon while keeping cloud/CDN/shared-hosting ambiguity passive until resolved.

#### CyberStrike output and completion

Use the canonical output contract in the `TOOLING_CATALOG.md` companion listed in `community-tool-selection`'s returned `<skill_files>` (read it using that skill's returned `Base directory`; do not resolve against the target workspace). Persist one normalized, deduplicated `subdomains.txt` in the existing target workspace. Merge useful partial results immediately and continue to live-host discovery without waiting for every source.

Do not create a second collector, a second tool inventory, or one file per provider. The agent selects and invokes suitable registered tools, reachable APIs, and available CLIs directly; `host_inventory.py` is an offline normalizer, not a source collector. Verify `subdomains.txt` exists before moving to DNS/live-host work. Report meaningful source failures in the final summary without blocking the rest of recon.


---

---

## 03. ASN and infrastructure mapping

### ASN and Infrastructure Mapping

### Chapter profile

**Purpose:** Map an organization's attributable IP infrastructure through ASN, CIDR, reverse DNS, sibling domains, and service metadata.

**Prerequisites:** A confirmed organization domain or attributable IP

**Technology:** `DNS`, `BGP`, `WHOIS`, `Linux`

**Coverage tags:** `recon`, `asn`, `cidr`, `dns`, `infrastructure`, `asset-inventory`

**Related security workflows:** `attack-subdomain-takeover`, `attack-host-header`, `attack-minio-s3`

**Legacy source:** `recon-asn-infrastructure` v"1.0.0"; credited to cyberstrike-official.

#### Objective

Expand a known organization asset into a defensible infrastructure map while avoiding the common error of treating an entire hosting provider or shared ASN as organization-owned. The output is an evidence-backed inventory, not automatic authorization to probe every adjacent address.

#### Methodology

##### 1. Establish attribution anchors

Start from domains and IPs already confirmed to belong to the organization. Collect RDAP/WHOIS organization fields, ASN origin, DNS answers, certificate transparency names, and first-party references. Record source, timestamp, confidence, and whether an address is dedicated, shared, CDN-fronted, or cloud-hosted.

##### 2. Resolve domains to IP and ASN

Use DNS resolution and ASN lookup tools to identify origin ASN and route objects. Validate results through at least two independent sources where possible; registrant names and route descriptions can be stale or generic. Handle IPv4 and IPv6 separately.

##### 3. Expand announced prefixes

Collect routed CIDR prefixes associated with confirmed ASNs, then classify them by ownership confidence. Do not automatically enumerate or scan a whole provider ASN, cloud region, or large shared prefix. For hyperscalers, use first-party DNS, certificates, service metadata, and confirmed address associations to narrow the inventory.

##### 4. Pivot through reverse DNS and service metadata

Resolve PTR records for confirmed addresses and correlate hostnames with known domains. Inspect TLS certificates, redirect targets, favicon hashes, and server metadata to cluster services. Shared IPs often indicate CDNs or multi-tenant hosting rather than common ownership.

##### 5. Expand sibling domains and subsidiaries

Generate candidate sibling TLDs or subsidiary names only as leads. Confirm each candidate through ownership evidence such as official links, corporate registration, certificate/DNS continuity, organization-controlled repositories, or known IdP/application links before active testing.

##### 6. Produce an asset graph

Represent relationships as domain → DNS record → IP → ASN/prefix → service → application. Include provenance and confidence per edge. Quarantine unresolved candidates instead of silently merging them into the owned inventory.

#### What This Produces

- A deduplicated domain/IP/service inventory with source provenance.
- Attribution confidence and explicit shared-infrastructure flags.
- Reverse-DNS and certificate-derived hostnames requiring follow-up.
- A prioritized set of verified assets for downstream testing.
- A quarantine list for same-name collisions, stale WHOIS data, and third-party hosting.

#### Evidence Requirements

- Timestamped DNS/RDAP/ASN results and URLs or commands used to obtain them.
- Specific evidence linking each candidate asset to the organization.
- Prefix size, provider/shared-hosting notes, and confidence level.
- Do not report a broad infrastructure map as a vulnerability without a demonstrated exposure or security impact.

#### Tool examples and roles (verify in the shared catalog)

- dig, whois/RDAP clients, asnmap, dnsx, httpx, mapcidr, and naabu where permitted.
- Certificate Transparency search and reputable BGP/RPKI explorers.
- jq, Python, or CSV tooling to deduplicate records and retain provenance.
- Passive sources such as BGP.tools, bgp.he.net, and organization-owned documentation.

#### Attribution and Expansion Matrix

| Pivot | Useful signal | Confidence check | Common trap |
|---|---|---|---|
| Domain → IP | A/AAAA/CNAME records | Re-resolve and record TTL/provider | CDN address mistaken for origin |
| IP → ASN | Origin ASN and route object | Cross-check RDAP and BGP data | Shared cloud ASN treated as owned |
| ASN → CIDR | Announced prefix | Confirm organization allocation and route status | Scanning huge provider ranges |
| IP → hostname | PTR and TLS SAN | Match canonical domains and app behavior | Stale PTR or generic certificate |
| Domain → sibling TLD | Similar brand/domain string | First-party or ownership evidence | Same-name unrelated company |
| Service → application | HTTP/TLS metadata | Verify consistent application identity | Default hosting page treated as target |
| Subsidiary → infrastructure | Corporate relationship | Official parent/subsidiary evidence | Guessed relationship from naming |

#### Verification and False Positives

- Confirm attribution before active requests; asset discovery does not expand the written target list.
- Reconcile IPv4 and IPv6, CNAME chains, CDN edges, and origin addresses independently.
- Remove duplicate addresses and normalize hostnames before counting coverage.
- Treat WHOIS organization strings, PTR names, and brand-name matches as weak signals unless corroborated.
- Prefer targeted service checks over high-rate scans of broad ranges.

#### Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful attribution hypotheses. Continue materially distinct, authorized passive checks while evidence can change the conclusion; deduplicate repeated sources and equivalent observations. Stop when attribution is resolved, relevant sources are exhausted, a prerequisite is unavailable, or scope/safety requires stopping. ASN membership alone never authorizes active scanning.

Track each attempt as hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired requests and controlled test identities/fixtures; save only minimal sanitized evidence.

##### Skill-specific hypothesis order

1. Anchor discovery to verified organization names, registered entities, known domains, and current RIR/ASN evidence; a matching company string or IP hostname is not sufficient ownership proof.
2. Collect passive ASN, prefix, BGP, reverse-DNS, certificate, and provider metadata first; preserve source URLs and observation timestamps for each candidate.
3. Normalize prefixes and hostnames, deduplicate shared CDN/cloud edges, and separate directly registered infrastructure from reseller, SaaS, shared hosting, and third-party service providers.
4. Promote a prefix to active testing only when written scope clearly covers it; do not sweep every IP in an ASN or infer permission from routing/WHOIS ownership.
5. Return candidate prefixes with attribution confidence, evidence provenance, explicit exclusions, validation status, and narrow next steps; hand confirmed web assets to the relevant recon/attack skill rather than claiming a vulnerability.

##### Verdict gates

- **Confirmed:** repeatable impact at an explicit in-scope boundary is demonstrated using a controlled identity/fixture and a meaningful control.
- **Likely / needs corroboration:** independent indicators support the candidate, but the consequence or root cause remains uncertain.
- **Unconfirmed:** evidence is generic, ambiguous, cached, or not tied to a security property.
- **Refuted / false positive:** a relevant negative control or valid implementation/policy explanation accounts for the observation. Document tested branches; do not claim all imaginable variants were exhausted.
- Scanner alerts, version strings, banner text, status codes, and response length alone are not proof.

##### Stop, cleanup, and handoff

Stop on scope ambiguity, unexpected user data, state changes, service degradation, secret exposure or prohibited behavior. Clean disposable test state and revoke temporary sessions/tokens where possible. Return scope proof, baseline, hypothesis, attempts used, impact, negative controls, verdict/confidence, sanitized evidence and cleanup status. Start a chained skill only when its trigger has been independently observed.

#### References

- Source merged: [uphiago/recon-skills — recon/asn-infrastructure-mapping/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/asn-infrastructure-mapping/SKILL.md)
- [RIPE NCC — IP and ASN resources](https://www.ripe.net/)
- [BGP.tools](https://bgp.tools/)
- [RFC 9082 — RDAP Query Format](https://www.rfc-editor.org/rfc/rfc9082)

#### Targeted quality-loop enrichment (2026-10-19)

##### Ownership-confidence ladder and scan boundary
For every IP/prefix/ASN pivot, retain the organization attribution source, relationship type (owned subsidiary, provider, shared cloud/CDN, stale historical link), observation date, and confidence. Corroborate with first-party asset lists, RDAP/RIR records, certificates, DNS, and product branding before assigning ownership; ASN membership alone never authorizes scanning every announced address. Keep passive-only leads separate from active-scan candidates and record why a candidate passes the target's actual program scope. Use new IPs to discover relationships, not to widen scope implicitly. Route confirmed public service exposure to service discovery and cloud-owned resource policy questions to cloud assessment.

#### Chapter-specific implementation notes and resources

##### Tools and purpose
- `asnmap` — map known organizations/domains to ASN and prefix candidates using passive/public attribution sources.
- `whois` and `dig` — inspect registration and DNS evidence locally; neither proves asset authorization.
- `jq` — parse structured ASN/prefix results while retaining source and collection time.
- `python3 .cyberstrike/skill/scripts/normalize_urls.py urls.txt` — normalize collected web URLs locally; it does not query DNS or contact targets.

##### Install and verify
Use official instructions at https://github.com/projectdiscovery/asnmap and https://docs.ripe.net/; install DNS/WHOIS utilities from trusted OS packages when needed. Verify with `asnmap -h`, `dig -v`, and `whois --help` as supported by the installed versions. If a tool is missing, record the gap and use public RIPEstat records or existing passive observations instead of claiming an active check.

##### Resources
- https://stat.ripe.net/docs/
- https://github.com/projectdiscovery/asnmap
- https://docs.ripe.net/
- https://owasp.org/www-project-web-security-testing-guide/

##### Result handling
Save ASN/prefix, source, collection time, provider attribution confidence, corroboration, and a disconfirming explanation. Treat CIDRs/IPs as infrastructure leads, not automatic scope expansion. Do not port-scan, bypass an origin, or directly access hosting infrastructure unless the program explicitly includes those assets/actions.


---

---

## 04. Origin IP exposure assessment

### Origin IP Exposure Assessment

### Chapter profile

**Purpose:** Assess whether a web origin is directly reachable behind a CDN or reverse proxy and whether origin exposure changes the security boundary.

**Prerequisites:** A confirmed domain and evidence of CDN/reverse-proxy use

**Technology:** `DNS`, `HTTP`, `TLS`, `CDN`

**Coverage tags:** `recon`, `origin-ip`, `CDN`, `reverse-proxy`, `DNS`

**Related security workflows:** `attack-host-header`, `attack-cache-poison`

**Impact qualification:** medium: A confirmed origin bypasses a security control that is demonstrably enforced only at the edge.

**Legacy source:** `recon-origin-ip-discovery` v"1.0.0"; credited to cyberstrike-official.

#### Objective

Determine whether an application origin is directly addressable and whether direct-origin access bypasses a material control such as edge authentication, WAF policy, rate limiting, or cache behavior. Discovering an IP alone is not a vulnerability.

#### Testing Methodology

##### 1. Establish the edge baseline

Resolve A/AAAA/CNAME records, record certificate and HTTP behavior, and identify likely CDN or reverse-proxy indicators. Capture a normal request's response headers, redirects, and application marker. Separate shared edge addresses from candidate origins.

##### 2. Collect passive origin candidates

Correlate historical DNS, certificate transparency, organization-owned DNS records, public service metadata, passive scan results, and attributable ASN/IP information. Treat old DNS records, mail servers, and unrelated addresses in a shared prefix as candidates until corroborated.

##### 3. Confirm candidate identity without bypass assumptions

Where testing is authorized, connect to a candidate IP while preserving the expected TLS SNI and HTTP Host for the confirmed domain. Compare certificate, redirect, body marker, and application behavior with the edge baseline. Do not treat a TLS mismatch or default virtual-host page as proof that the candidate is the origin.

##### 4. Compare security controls

Use the same benign request and controlled identity through edge and candidate origin. Compare authentication, WAF behavior, rate-limit response, cache directives, and route availability. Do not run destructive payloads or high-volume tests to establish a differential.

##### 5. Assess practical impact

A reportable issue requires a control that can be bypassed or an unintended service/data exposure at the origin. Document the precise difference and the minimum route needed to prove it. If the origin is intentionally public and enforces the same controls, record it as an inventory result only.

#### What Constitutes a Finding

- Direct origin access bypasses a material security control or exposes a private service.
- The candidate IP is attributable to the same application, not merely the same cloud provider.
- The edge/origin comparison is reproducible with identical request semantics.
- An IP address, historical DNS record, or different certificate alone is not a vulnerability.

#### Evidence Requirements

- DNS/passive-source provenance and timestamp.
- Sanitized edge and origin request/response pairs, including Host and SNI context.
- Exact control that differs and a minimal impact demonstration.
- Redact tokens and private application data.

#### Tool examples and roles (verify in the shared catalog)

- `dig` and `dnsx`: compare current DNS answers and preserve record/source metadata.
- `httpx`: collect low-volume HTTP metadata for known in-scope hosts.
- `openssl s_client`: inspect certificate/SNI behavior for an explicitly authorized host.
- RDAP/ASN CLI/API and approved passive DNS sources: corroborate attribution without probing candidate origin addresses.
- `python3 .cyberstrike/skill/scripts/normalize_urls.py urls.txt`: normalize collected URL observations locally.

Verify `dig -v`, `dnsx -version`, `httpx -version`, and `openssl version` as appropriate. Official docs: https://docs.projectdiscovery.io/, https://www.openssl.org/docs/, https://docs.securitytrails.com/, https://docs.censys.com/.

#### Origin Attribution Matrix

| Signal | Interpretation | Required corroboration |
|---|---|---|
| Historical DNS A record | Candidate historical host | Same app marker or certificate identity |
| Certificate SAN | Hostnames share certificate | Verify current application response |
| Direct IP returns app | Possible origin or shared host | Preserve SNI/Host and compare content |
| WAF differs at origin | Potential edge-only enforcement | Confirm the same request is denied at edge and materially succeeds at origin |
| Different server banner | Infrastructure clue | No impact unless a security boundary is bypassed |
| Origin responds on extra port | Additional service candidate | Confirm ownership and service sensitivity |

#### Verification and False Positives

- Account for DNS changes, CDN migration, shared hosting, and anycast addresses.
- Preserve Host and TLS SNI; otherwise the server may serve a default site.
- Compare final response semantics, not status codes alone.
- Do not scan broad cloud address ranges to find origins.
- Treat exposed origin IPs as informational unless direct access changes security posture.


#### Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. there is no fixed hypothesis-count ceiling; continue distinct, decision-relevant hypotheses while authorized, and stop when evidence or a real safety/policy boundary resolves the branch. Prefer passive sources first, deduplicate candidates, and use active checks only when the asset and activity are explicitly in scope.

##### Evidence record and confidence

For each candidate, preserve normalized asset, source/provenance, observation time, scope proof, resolver/HTTP/tool and relevant version, corroborating source, raw-evidence location when retained, negative control, attribution confidence, next action, and related-skill trigger. Separate **asset confidence** (is it related to the organization?) from **security confidence** (is a vulnerability demonstrated?).

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. C1/C2 are not confirmed vulnerabilities.

##### Skill-specific next steps

1. Start from confirmed domains and passive evidence (historical DNS, certificate data, provider records, and first-party configuration) before any network probes.
2. Correlate candidate addresses with ownership, ASN/provider, TLS/SNI certificate, application response, and current DNS. A historical A record or shared IP alone does not identify a unique origin.
3. Use only low-impact checks within explicitly scoped address ranges; do not bypass CDN/WAF controls to attack origin services, scan neighboring tenants, or change host routing.
4. Compare a candidate address with the normal CDN/front-door response using the expected Host/SNI and a random-host control. Distinguish genuine origin reachability from shared hosting or a provider edge.
5. Return each candidate with source, timestamp, ownership confidence, corroborating signals, and scope decision. Discovery is not permission to probe the address and is not itself a vulnerability.


##### Deduplication and stop rules

Normalize case, trailing dots, scheme/port, redirects, canonical names and resolved addresses before deduplication. Detect wildcard DNS, shared hosting, CDN/edge responses, soft-404s and stale records before ranking counts. Stop on exclusions, ownership ambiguity, unexpected sensitive data, throttling, instability or boundaries requiring further permission. Never claim ownership or register dangling resources.

##### Handoff format

Return candidates with scope/provenance, confidence level, evidence path, deduplication key, negative control, priority rationale, safe next step and trigger for any linked attack skill. Promote a candidate to active testing only after scope and attribution are confirmed; promote it to a finding only after the relevant attack skill verifies the security boundary.

#### References

- Source merged: [uphiago/recon-skills — recon/origin-ip-discovery/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/origin-ip-discovery/SKILL.md)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [RFC 6066: TLS Server Name Indication](https://www.rfc-editor.org/rfc/rfc6066)


#### Targeted quality-loop enrichment (2026-10-19)

##### Origin attribution versus bypass claims
Build candidate origins from historical DNS, certificate/deployment metadata, first-party configuration, and observed redirects, but score each by freshness and organization attribution. A CDN/origin relationship does not automatically permit direct-origin requests; verify the candidate is in program scope and that testing the origin is allowed. If permitted, compare one harmless public path through the normal edge and candidate origin, recording TLS, Host/routing, authentication, and applicable controls. Do not bypass a WAF to access protected content or treat an origin IP as a security bug by itself. Confirm a meaningful difference before chaining to host-header, cache, or access-control review.


#### Chapter-specific implementation notes and resources

Prefer passive DNS/certificate history and provider attribution. `dnsx`, `httpx`, and `openssl s_client` help compare records and certificate/SNI behavior for known, explicitly authorized hosts. Optional passive sources include SecurityTrails and Censys APIs where available.

##### Resources
- https://docs.projectdiscovery.io/
- https://docs.securitytrails.com/
- https://docs.censys.com/
- https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/
- https://owasp.org/www-project-web-security-testing-guide/

Treat an inferred origin IP as an attribution hypothesis, not authorization to access it. Do not bypass a CDN/WAF or scan a candidate IP unless the program explicitly includes that infrastructure and method. Record source, timestamp, corroboration, and confidence.


---

---

## 05. Port and service discovery

### Port and Service Discovery

### Chapter profile

**Purpose:** Classify services on confirmed target infrastructure and prioritize web, API, management, and unusual-port exposures using bounded probes.

**Prerequisites:** An attributable host or IP explicitly authorized for service discovery

**Technology:** `TCP`, `UDP`, `HTTP`, `TLS`, `DNS`, `Linux`

**Coverage tags:** `recon`, `ports`, `services`, `network`, `HTTP`, `TLS`

**Legacy source:** `recon-port-service-discovery` v"1.0.0"; credited to cyberstrike-official.

#### Objective

Identify reachable services and distinguish expected public application surfaces from accidental management, development, or protocol exposure. Port discovery creates an inventory; a listening port or banner alone is not a vulnerability.

#### Methodology

##### 1. Establish host attribution and scan boundaries

Use confirmed target addresses, document included ports and rate limits, and exclude shared-provider ranges unless explicitly listed. Prefer DNS-derived and first-party confirmed IPs over broad ASN expansion. Record the time window and source address of the scan.

##### 2. Start with low-impact TCP discovery

Begin with common service ports or a program-approved port list. Use conservative concurrency and timeouts. Expand only when the first pass indicates a relevant service or the engagement expressly allows a broader sweep. UDP checks should be targeted because they are less reliable and can be more intrusive.

##### 3. Fingerprint services with protocol-aware probes

For each open port, record TCP state, service response, TLS certificate/SAN, ALPN, HTTP status/title, redirect destination, and server metadata. Use a protocol-aware client rather than assuming every high port is HTTP. A banner may be masked, stale, or supplied by a proxy.

##### 4. Identify sensitive service classes

Prioritize exposed admin consoles, databases, caches, message brokers, CI/CD systems, object storage, debug endpoints, container/orchestration APIs, and alternate application ports. Confirm whether authentication is required and whether the service is intentionally public. Avoid login attempts with guessed or discovered credentials.

##### 5. Correlate services with known applications

Map port → protocol → certificate/hostname → application → owner. Compare alternate ports against the canonical web app and inspect public JavaScript/configuration for backend references. Use the dedicated API, cloud, CMS, and origin skills for service-specific validation.

##### 6. Validate one meaningful exposure

For a suspected issue, capture a single benign handshake or read-only response and verify access control with a controlled identity if required. Do not enumerate data, alter configuration, or run exploit checks against sensitive services unless the testing class is explicitly permitted.

#### What This Produces

- A deduplicated service inventory with timestamped evidence.
- Protocol and application fingerprints with confidence notes.
- A shortlist of exposed services that warrant a focused security review.
- A clear separation between an open port, a misconfiguration, and a demonstrated vulnerability.

#### Evidence Requirements

- Confirmed host attribution and scan boundary.
- Port/protocol/state, timestamp, and minimal sanitized service response.
- Service identity evidence and reason the exposure is unexpected.
- For a vulnerability, the access-control gap or sensitive impact, not just a banner.

#### Tool examples and roles (verify in the shared catalog)

- Nmap for targeted TCP/UDP service discovery where permitted.
- naabu for approved TCP port inventory.
- httpx/curl for HTTP metadata and redirect checks.
- openssl s_client for TLS handshake/certificate checks.
- dig, RDAP, and inventory scripts for host attribution and deduplication.

#### Service Discovery Matrix

| Service class | Useful signal | Follow-up | False positive |
|---|---|---|---|
| Alternate HTTP(S) | HTTP response, TLS certificate, app title | Compare auth/configuration with canonical host | Default proxy page |
| Database | Protocol handshake or service banner | Confirm public exposure and intended access policy without data extraction | Port appears open but firewall blocks protocol |
| Cache/message broker | Protocol fingerprint | Verify whether authentication/network restrictions exist | Generic TCP response |
| Admin/management | Console title or management protocol | Check authorization with controlled account | Public login page alone |
| CI/CD/registry | Build or registry API metadata | Review project visibility and permissions | Intended public artifacts |
| Container/orchestration | API or dashboard signature | Verify authentication and tenant boundary | Version/banner only |
| Object storage | Provider response and bucket metadata | Use dedicated storage skill | Public static content by design |
| Mail/remote access | Protocol greeting and TLS metadata | Review intended exposure and policy | Service is expected for the business |
| Unknown high port | Consistent protocol response | Identify service before further testing | Scanner misclassification |

#### Verification and False Positives

- Confirm the port is reachable from the same network position relevant to the finding.
- Repeat a small number of times to exclude transient firewall behavior.
- Use correct SNI and Host values for TLS/HTTP services.
- Treat service banners as hints, not definitive version evidence.
- Avoid high-rate full-range scans unless explicitly allowed; broad scanning is not a substitute for targeted validation.
- Do not infer that all addresses within a hosting provider's ASN belong to the target.

#### Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. there is no fixed hypothesis-count ceiling; continue distinct, decision-relevant hypotheses while authorized, and stop when evidence or a real safety/policy boundary resolves the branch. Prefer passive sources first, deduplicate candidates, and use active checks only when the asset and activity are explicitly in scope.

##### Evidence record and confidence

For each candidate, preserve normalized asset, source/provenance, observation time, scope proof, resolver/HTTP/tool and relevant version, corroborating source, raw-evidence location when retained, negative control, attribution confidence, next action, and related-skill trigger. Separate **asset confidence** (is it related to the organization?) from **security confidence** (is a vulnerability demonstrated?).

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. C1/C2 are not confirmed vulnerabilities.

##### Skill-specific next steps

1. Verify exact host/IP ranges and permitted scan types before starting; treat ASN membership or a discovered address as insufficient authorization.
2. Prefer passive service evidence first, then a narrow TCP/UDP port set with conservative timing, bounded retries, and explicit timeouts. Avoid wide high-rate scans and intrusive scripts.
3. Record open/closed/filtered separately and preserve tool version, flags, target list, timestamp, resolver/source, and rate settings so results can be reproduced.
4. Identify services with safe protocol handshakes or read-only banners; account for proxies, NAT, firewall filtering, rate limits, and shared-provider infrastructure before attributing a service.
5. Stop on instability, rate-limit signals, unexpected sensitive data, or an out-of-scope address. Return a deduplicated service inventory with confidence and a narrow application-specific handoff.

##### Deduplication and stop rules

Normalize case, trailing dots, scheme/port, redirects, canonical names and resolved addresses before deduplication. Detect wildcard DNS, shared hosting, CDN/edge responses, soft-404s and stale records before ranking counts. Stop on exclusions, ownership ambiguity, unexpected sensitive data, throttling, instability or boundaries requiring further permission. Never claim ownership or register dangling resources.

##### Handoff format

Return candidates with scope/provenance, confidence level, evidence path, deduplication key, negative control, priority rationale, safe next step and trigger for any linked attack skill. Promote a candidate to active testing only after scope and attribution are confirmed; promote it to a finding only after the relevant attack skill verifies the security boundary.

#### References

- Source merged: [uphiago/recon-skills — recon/port-service-discovery/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/port-service-discovery/SKILL.md)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

#### Targeted quality-loop enrichment (2026-10-19)

##### Service fingerprint and owner gate
For each host/port, record the exact resolver result, scope basis, service-detection confidence, banner source, protocol/TLS details, and whether the service is owned by the target or a shared provider. Start with low-impact connection checks and conservative timeouts; increase depth only when allowed and a clear hypothesis exists. Distinguish an open socket from an exposed administration function or vulnerable version. Validate protocol identity using service-specific evidence and vendor release notes; account for proxies and backports. Avoid exploit modules or broad UDP/TCP expansion by default. Route confirmed web interfaces to web recon, management planes to the relevant product specialist, and internal-only services to the program's explicit network-testing rules.

#### Chapter-specific implementation notes and resources

Use capabilities that produce inspectable output. Port/service checks are active network activity: confirm the target and allowed port ranges before running them, respect program rate limits, and stop if instability appears. The tool names and commands below are optional, non-exhaustive examples—not phase requirements. Search the current registry for the evidence gap and use any suitable available tool/API/CLI whose real capability and side effects fit the authorized task; do not install or require a listed candidate merely because it appears here.

##### Optional capability examples (non-exhaustive)
- `naabu` — TCP port inventory for authorized hosts; preserve scanner errors and retain raw output only when it adds unique evidence, reproducibility, or diagnostic value.
- `nmap` — targeted service/version detection for explicitly permitted hosts and ports; avoid intrusive scripts unless separately authorized.
- `tlsx` — TLS certificate and handshake metadata for discovered services.
- `httpx` — HTTP/TLS metadata for confirmed web services, not a vulnerability verdict.
- `jq` and Python — normalize JSON output while retaining source, timestamp, tool version, and errors.

##### Install and verify
For each selected external candidate, consult official installation/release guidance and verify its documented version/help output before use. Candidate references include https://github.com/projectdiscovery/naabu, https://github.com/projectdiscovery/tlsx, and https://github.com/projectdiscovery/httpx; none is required by name.
- Nmap documentation is available at https://nmap.org/download.html; select it only when it is suitable and available, and prefer an adequate existing alternative over installing it by default.
- If `jq` is selected for JSON processing, verify it with `jq --version`; otherwise use a suitable available parser. If a candidate is absent or unsupported, compare alternatives before considering installation; do not claim the phase completed without verified evidence.
- Keep scanner concurrency/rate settings aligned with the program rules and observed target stability. Do not use scanning to evade rate limits or expand beyond the approved asset set.

##### Resources
- https://github.com/projectdiscovery/naabu
- https://nmap.org/book/man.html
- https://github.com/projectdiscovery/tlsx
- https://github.com/projectdiscovery/httpx
- https://owasp.org/www-project-web-security-testing-guide/

##### Output contract and helper guidance
Normalize results into host, port, protocol, state, service, timestamp, tool/version, input artifact, and error fields. Keep scanner errors distinct from closed ports; a banner alone is not a vulnerability. Normalize routine results into the canonical port/service inventory. Retain native output only when it adds unique service evidence, improves reproducibility, or diagnoses a failure; do not silently overwrite original input evidence. If no purpose-built helper fits, use a small local parser with JSON/JSONL output and fixtures rather than adding an unrelated dependency.

##### Handoff
Return command/tool and version, input/output artifact references, observed host/port counts, failures, limitations, confidence, and the next skill. Empty output or an unavailable tool is an explicit status, not proof that the phase completed.


---

---

## 06. Virtual-host enumeration

### Virtual-Host Enumeration

### Chapter profile

**Purpose:** Identify virtual hosts and tenant-specific applications on confirmed infrastructure using DNS, TLS, HTTP Host behavior, and response clustering.

**Prerequisites:** A confirmed target domain or attributable server IP

**Technology:** `HTTP`, `TLS`, `DNS`, `reverse-proxy`

**Coverage tags:** `recon`, `virtual-host`, `HTTP`, `TLS`, `DNS`

**Related security workflows:** `attack-host-header`

**Legacy source:** `recon-vhost-enumeration` v"1.0.0"; credited to cyberstrike-official.

#### Objective

Identify hostnames routed by a shared web server or reverse proxy, then classify whether each host belongs to the target organization and is an authorized asset. A different response to a Host header is a discovery signal, not proof of a vulnerability.

#### Methodology

##### 1. Establish response fingerprints

Capture a baseline for the canonical hostname and a random nonexistent hostname. Record status, redirect, title, body hash/length, certificate names, server headers, and a stable application marker. This identifies default virtual hosts and wildcard DNS behavior.

##### 2. Generate candidate hostnames

Use passive DNS, certificate transparency, organization-owned documentation, observed links, DNS records, and a restrained wordlist derived from application roles (api, auth, staging, admin, files, assets). Normalize names and deduplicate candidates. Avoid indiscriminate brute force where the engagement prohibits it.

##### 3. Resolve and classify candidates

Resolve A/AAAA/CNAME, note wildcard responses, and compare TLS SAN/certificate behavior. A resolved hostname may be parked, delegated to a third party, or point to a shared platform; confirm application identity and ownership before active testing.

##### 4. Compare HTTP routing

For confirmed IPs, request each candidate hostname with correct TLS SNI where applicable. Compare application marker, redirects, cookies, and route behavior. If a Host header changes the destination or generates absolute URLs, use the dedicated host-header skill to test trust boundaries.

##### 5. Prioritize unusual hosts

Review staging, preview, legacy, API, upload, tenant, and administrative hosts for weaker authentication or outdated deployments. Apply the same ownership and permission checks as any other asset. Do not infer that a hostname is in scope solely because its name matches the brand.

#### What This Produces

- A deduplicated candidate hostname inventory.
- DNS/TLS/HTTP fingerprints and wildcard/default-host classifications.
- Ownership confidence and notes on third-party hosting.
- A prioritized list of confirmed applications for follow-up testing.

#### Evidence Requirements

- Candidate source and resolution timestamp.
- Baseline versus candidate fingerprints, including the random-host control.
- Evidence tying the host to the organization.
- For any vulnerability, a separate minimal proof of security impact beyond host discovery.

#### Tool examples and roles (verify in the shared catalog)

- `dig`, `dnsx`, certificate-transparency sources, `httpx`, and `curl` for scoped DNS/HTTP inventory.
- `openssl s_client` for certificate/SNI metadata on authorized hostnames.
- Python/`jq` for response fingerprints and deduplication.
- Passive DNS and RDAP sources for attribution.
- `python3 .cyberstrike/skill/scripts/normalize_urls.py urls.txt`: normalize collected candidates locally.

Verify `dig -v`, `dnsx -version`, `httpx -version`, `curl --version`, and `openssl version` as applicable. Official docs: https://docs.projectdiscovery.io/, https://curl.se/docs/, https://www.openssl.org/docs/.

#### Virtual-Host Signal Matrix

| Signal | What it may indicate | Verification |
|---|---|---|
| Wildcard DNS | Many labels resolve to one edge | Compare random-host and known-host responses |
| Unique TLS SAN | Hostname was included in a certificate | Confirm current app and ownership |
| Distinct redirect | Host-specific routing or canonicalization | Follow chain and inspect final host |
| Different body hash | Separate virtual host or dynamic response | Compare stable markers and repeat |
| Default server page | Unknown Host reached a default vhost | Not a target asset without attribution |
| Staging/preview name | Non-production deployment | Verify ownership and authorization before testing |
| Same IP, different app | Shared server routing | Preserve SNI and Host consistently |

#### Verification and False Positives

- Exclude random-host catch-all responses and wildcard DNS noise.
- Normalize dynamic values before body-hash comparison.
- Do not treat certificate presence as proof that the current host is live or owned.
- Confirm redirects do not lead to third-party SaaS or parked domains.
- Keep host discovery separate from vulnerability claims.


#### Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. there is no fixed hypothesis-count ceiling; continue distinct, decision-relevant hypotheses while authorized, and stop when evidence or a real safety/policy boundary resolves the branch. Prefer passive sources first, deduplicate candidates, and use active checks only when the asset and activity are explicitly in scope.

##### Evidence record and confidence

For each candidate, preserve normalized asset, source/provenance, observation time, scope proof, resolver/HTTP/tool and relevant version, corroborating source, raw-evidence location when retained, negative control, attribution confidence, next action, and related-skill trigger. Separate **asset confidence** (is it related to the organization?) from **security confidence** (is a vulnerability demonstrated?).

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. C1/C2 are not confirmed vulnerabilities.

##### Skill-specific next steps

1. Confirm the destination IP/host and the parent domain are in scope; capture a normal Host/SNI response and an intentionally invalid-host response as controls.
2. Build a small candidate list from first-party names, certificates, existing DNS, or documented naming patterns rather than an unbounded dictionary.
3. Vary Host header and TLS SNI separately when tooling allows; preserve status, redirects, title, body hash, certificate, and server timing so front-end defaults can be distinguished from named virtual hosts.
4. Normalize dynamic content and cluster identical fingerprints. Check for wildcard/default virtual hosts and shared CDN behavior before promoting a candidate; a different status code alone is not proof.
5. Keep request rates low and stop at instability, unexpected sensitive data, or scope uncertainty. Return each confirmed vhost with source, control comparison, attribution confidence, and a safe next-step trigger.


##### Deduplication and stop rules

Normalize case, trailing dots, scheme/port, redirects, canonical names and resolved addresses before deduplication. Detect wildcard DNS, shared hosting, CDN/edge responses, soft-404s and stale records before ranking counts. Stop on exclusions, ownership ambiguity, unexpected sensitive data, throttling, instability or boundaries requiring further permission. Never claim ownership or register dangling resources.

##### Handoff format

Return candidates with scope/provenance, confidence level, evidence path, deduplication key, negative control, priority rationale, safe next step and trigger for any linked attack skill. Promote a candidate to active testing only after scope and attribution are confirmed; promote it to a finding only after the relevant attack skill verifies the security boundary.

#### References

- Source merged: [uphiago/recon-skills — recon/vhost-enumeration/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/vhost-enumeration/SKILL.md)
- [RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)
- [RFC 6066: TLS Server Name Indication](https://www.rfc-editor.org/rfc/rfc6066)


#### Targeted quality-loop enrichment (2026-10-19)

##### Vhost baseline and soft-404 control
Establish stable fingerprints for a known host, a known-invalid host header, and a random nonexistent path. Vary only the authority/Host dimension while keeping IP, TLS SNI, path, and request headers clear in the notes. Record status, title, body hash/length, redirects, cookies, and server-selected application; a different title or 200 alone may be a default virtual host. Confirm a discovered vhost through product-specific content or a second source and re-check program scope before active tests. Route valid applications to web recon and host-derived links to host-header review; do not treat shared reverse-proxy routing as a vulnerability without a security consequence.


#### Chapter-specific implementation notes and resources

##### Tools
- `httpx` — establish a baseline for known in-scope hosts and save machine-readable status/title/technology metadata.
- `ffuf` — test evidence-based virtual-host candidates with an approved wordlist and conservative settings.
- `curl` — compare one observed host-header variation with the baseline.
- `jq` and `rg` — parse results and deduplicate candidate hosts.
- `python3 .cyberstrike/skill/scripts/normalize_urls.py urls.txt` — normalize locally collected URL candidates; it does not probe hosts.

##### Installation and verification
Use official docs: https://docs.projectdiscovery.io/tools/httpx/overview and https://github.com/ffuf/ffuf. Verify `httpx -version`, `ffuf -V`, and `curl --version` as documented by the installed versions. If unavailable, use `curl` and local response comparison; record the gap. Confirm tool names/flags with `--help` before execution.

##### Resources
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/ffuf/ffuf
- https://portswigger.net/web-security/host-header

##### Result handling
Record baseline status/body size/title, exact Host value, comparison response, source, and confidence. A different default page or CDN response alone is not proof. Only test explicitly authorized hosts and obey the program's rate rules.


---

---

## 07. CMS and component fingerprinting

### CMS and Component Fingerprinting

### Chapter profile

**Purpose:** Fingerprint CMS platforms, versions, themes, plugins, and exposed administrative surfaces using corroborated passive and low-impact signals.

**Prerequisites:** A confirmed in-scope asset and authorization for the specific procedure.

**Technology:** `HTTP`, `HTML`, `JavaScript`, `DNS`

**Coverage tags:** `recon`, `CMS`, `WordPress`, `Drupal`, `Joomla`, `fingerprinting`

**Related security workflows:** `attack-wordpress`, `attack-source-leak`, `attack-information-disclosure`

**Legacy source:** `recon-cms-detection` v"1.0.0"; credited to cyberstrike-official.

#### Objective

Identify the content-management platform and relevant extensions accurately enough to prioritize version-specific security review, while distinguishing fingerprints from confirmed vulnerabilities.

#### Scope

- Requires a confirmed, organization-owned web application (output of `recon-master` or a program-provided target list). Do not fingerprint third-party widgets, embedded SaaS login providers, or CDN infrastructure that only happens to be reachable from the target.
- Passive and low-impact active checks only: normal page loads, published readme/changelog files, and documented API endpoints. No credential guessing against login or admin routes — that belongs to a dedicated authentication-testing skill.
- Component-inventory brute forcing (large wordlists against plugin/theme directories) is a last resort; prefer passive evidence first and keep any active enumeration low-rate and clearly logged.

#### Methodology

##### 1. Collect baseline signals

Inspect HTML generator metadata, static asset paths, common CMS directories, login routes, response headers, cookies, JavaScript globals, and robots/sitemap entries. Capture a normal page and a random-path control to account for custom error pages and single-page application fallbacks.

##### 2. Corroborate platform identity

Use at least two independent indicators such as asset paths plus a CMS-specific API response. Consider reverse proxies, custom themes, removed generator tags, and headless CMS architectures. Record confidence instead of forcing a single platform label.

##### 3. Fingerprint versions cautiously

Use static asset versions, readme/changelog files where publicly served, API metadata, source maps, and known release-specific behavior. A version string can be stale or intentionally altered; confirm with a second signal before associating an application with a vulnerable release.

##### 4. Inventory extensions and integrations

Review public plugin/theme asset paths, frontend bundles, REST routes, GraphQL schemas, and references in source code. Prioritize components that are reachable and materially affect authentication, file handling, template rendering, or data access. Avoid brute forcing large extension lists when passive evidence is sufficient.

##### 5. Verify the security condition

Map a confirmed component/version to a credible advisory, then verify the vulnerable precondition and affected code path with a minimal non-destructive test. A component being outdated is not automatically a reportable exploitable issue without impact and applicable policy.

#### What This Produces

- CMS and framework fingerprint with confidence notes.
- A component inventory tied to observed evidence.
- Candidate advisories requiring applicability verification.
- A prioritized list of safe follow-up tests.

#### Evidence Requirements

- Response excerpts or asset paths that establish the fingerprint.
- Version evidence and a corroborating signal.
- Advisory identifier and exact affected-version range for any vulnerability claim.
- A minimal proof of the security condition, with secrets and user data redacted.

#### Tool examples and roles (verify in the shared catalog)

- `httpx` and `curl`: collect bounded response headers, status, title, and content fingerprints.
- `whatweb` / `webanalyze`: optional CMS/technology fingerprinting on approved hosts.
- `rg` and local HTML/JavaScript parsers: inspect assets already collected.
- Vendor advisories, changelogs, and vulnerability databases: corroborate version claims.
- Local scripts: normalize asset URLs and compare response fingerprints.

Verify each selected binary with its documented version/help command. Official docs: https://github.com/urbanadventurer/WhatWeb, https://github.com/rverton/webanalyze, https://curl.se/docs/, https://docs.projectdiscovery.io/.

#### Fingerprint Confidence Matrix

| Signal | Confidence | Caveat |
|---|---|---|
| Generator metadata | Low to medium | May be removed or spoofed |
| CMS-specific asset directory | Medium | Custom sites can reuse paths |
| CMS API response with platform schema | High | May be intentionally public |
| Multiple independent component assets | Medium to high | Assets may be cached or copied |
| Version query parameter | Low | Often stale and not authoritative |
| Public readme/changelog | Medium | May not match deployed code |
| Confirmed behavior unique to release | High | Requires careful, non-destructive verification |

#### Verification and False Positives

- Compare candidate paths with a random nonexistent path to detect catch-all responses.
- Distinguish a headless frontend from the CMS origin.
- Treat plugin names and version strings as leads until confirmed.
- Check the advisory's prerequisites and reachable code path.
- Do not claim RCE or data exposure solely from an outdated version banner.

#### Stop Conditions

- Stop active probing of a specific path if it triggers account lockouts, CAPTCHA, or visible rate-limiting; that behavior itself is evidence enough and further requests risk denial-of-service.
- Stop and confirm attribution before continuing if a discovered CMS instance appears to be a third party's staging environment, a reseller/demo install, or otherwise not clearly owned by the target organization.
- Do not proceed from "outdated version identified" to exploitation without first confirming the advisory's vulnerable code path is actually reachable; version-matching alone is not authorization to run an exploit.

#### Defensive Notes

- Removing or genericizing generator metadata, version strings, and default admin paths raises the cost of fingerprinting but does not replace patching; attackers can still corroborate version from behavior.
- Keeping CMS core, themes, and plugins current, and restricting admin/login routes by network or MFA, reduces both the fingerprinting surface and the exploitability of anything found.


#### Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. there is no fixed hypothesis-count ceiling; continue distinct, decision-relevant hypotheses while authorized, and stop when evidence or a real safety/policy boundary resolves the branch. Prefer passive sources first, deduplicate candidates, and use active checks only when the asset and activity are explicitly in scope.

##### Evidence record and confidence

For each candidate, preserve normalized asset, source/provenance, observation time, scope proof, resolver/HTTP/tool and relevant version, raw-evidence location, corroborating source, negative control, attribution confidence, next action, and related-skill trigger. Separate **asset confidence** (is it related to the organization?) from **security confidence** (is a vulnerability demonstrated?).

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. C1/C2 are not confirmed vulnerabilities.

##### Skill-specific next steps

1. Use passive fingerprints and low-impact read-only requests to identify likely CMS, theme/plugin families, version clues, and entry points; preserve each signal and confidence separately.
2. Confirm each fingerprint with at least one independent marker (such as distinctive assets, headers, generator metadata, route behavior, or source evidence) and use a random-path control to detect generic pages.
3. Account for reverse proxies, caching, custom themes, removed generator tags, and patched backports before assigning a version or risk label.
4. Consult official vendor/plugin advisories for the exact component and version; prioritize exposed login/admin, API, upload, and legacy interfaces only when in scope.
5. Return a deduplicated component inventory with evidence, confidence, timestamp, and suggested read-only checks. A CMS fingerprint or old version clue is a lead, not a confirmed finding.


##### Deduplication and stop rules

Normalize case, trailing dots, scheme/port, redirects, canonical names and resolved addresses before deduplication. Detect wildcard DNS, shared hosting, CDN/edge responses, soft-404s and stale records before ranking counts. Stop on exclusions, ownership ambiguity, unexpected sensitive data, throttling, instability or boundaries requiring further permission. Never claim ownership or register dangling resources.

##### Handoff format

Return candidates with scope/provenance, confidence level, evidence path, deduplication key, negative control, priority rationale, safe next step and trigger for any linked attack skill. Promote a candidate to active testing only after scope and attribution are confirmed; promote it to a finding only after the relevant attack skill verifies the security boundary.

#### References

- Source merged: [uphiago/recon-skills — recon/cms-detection/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/cms-detection/SKILL.md)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST National Vulnerability Database](https://nvd.nist.gov/)


#### Targeted quality-loop enrichment (2026-10-19)

##### Fingerprint-to-vulnerability gate
Maintain independent confidence for CMS identity, component identity/version, deployment ownership, and vulnerability applicability. Corroborate a fingerprint with multiple signals and account for reverse-proxy caches, custom themes, backported fixes, and misleading banners. Before invoking a version-specific skill, verify the affected component is reachable and that the preconditions are plausible; do not map a scanner's version label directly to a confirmed CVE. Use passive/GET-only probes where possible, preserve response hashes and the exact fingerprint source, and stop when no meaningful permitted observation remains. Chain to the CMS-specific skill only after identity evidence, then require that skill's independent proof gate.


#### Chapter-specific implementation notes and resources

Use agent-executable CLI tools and local scripts. Browser interfaces, browser extensions, and interactive intercepting proxies are not required dependencies. Verify tool availability/version and official installation guidance before use; inspect request impact and permissions before active testing.

##### Recommended tools
- whatweb — technology fingerprints
- wpscan — WordPress-specific checks only when applicable and authorized
- retire.js — client-side library version clues
- Trivy/Semgrep — local dependency/source checks when available

##### Resources
- https://github.com/urbanadventurer/WhatWeb
- https://wpscan.com/
- https://github.com/RetireJS/retire.js
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids; confirm maintenance, license, provenance, and exact CLI behavior from official sources.

##### Helper-script contract
Keep fingerprint evidence, version confidence, vendor advisory ID, affected component, and safe verification result. Do not infer vulnerable status from a guessed banner or outdated fingerprint alone.

Normalize routine outputs into the canonical inventory and keep provenance, timestamps, tool/version, errors, confidence, and artifact paths with each observation. Retain raw output only when it adds unique evidence, reproducibility, or diagnostic value; do not create a raw copy for every tool/run. Redact secrets, support JSON/JSONL where useful, and include local fixtures.

##### Handoff
Report commands actually executed, tool versions, input/output artifact references, deduplication counts, errors/blocked sources, confidence, limitations, and the next skill.


---

---

## 08. Visual reconnaissance and application clustering

### Visual Reconnaissance and Application Clustering

### Chapter profile

**Purpose:** Use screenshots, page titles, visual clustering, and browser-observed behavior to prioritize web assets and identify distinct applications.

**Prerequisites:** A confirmed in-scope asset and authorization for the specific procedure.

**Technology:** `HTTP`, `browser`, `TLS`

**Coverage tags:** `recon`, `screenshots`, `visual-triage`, `web-enumeration`

**Legacy source:** `recon-visual-recon` v"1.0.0"; credited to cyberstrike-official.

#### Objective

Reduce a large host inventory into distinct applications and high-value testing candidates using reproducible visual evidence. Screenshots and titles are triage signals, not vulnerability proof.

#### Scope

- Only capture URLs already confirmed as in-scope and attributable to the target organization (e.g., output of `subdomain-enumeration chapter` or a program-provided asset list). Do not expand capture to third-party SaaS, CDN, or parked infrastructure discovered incidentally.
- Automated capture is passive (GET/navigation only). Do not submit forms, accept cookie/consent prompts beyond what is needed to render the page, or interact with authentication flows during the bulk pass.
- If a captured page requires credentials the tester does not hold, or displays content suggesting it belongs to an unrelated customer/tenant, exclude it from the dataset and flag it for scope confirmation rather than clustering it.

#### Methodology

##### 1. Normalize and validate the URL set

Deduplicate URLs by canonical hostname and path, remove malformed entries, and confirm attribution before browser visits. Separate redirects, CDN errors, parked domains, and third-party login providers from actual application pages.

##### 2. Capture consistent snapshots

Use a headless browser or screenshot tool with a consistent viewport, wait condition, and timeout. Record URL, final URL, title, status, screenshot path, timestamp, and any TLS/certificate errors. Avoid submitting forms or triggering state changes during automated capture.

##### 3. Cluster applications

Group pages using normalized titles, visual similarity, favicon hashes, shared asset paths, login-provider identity, and DOM landmarks. Dynamic timestamps, personalized banners, A/B tests, and cookie notices can skew visual hashes; retain multiple signals rather than trusting one metric.

##### 4. Prioritize for manual review

Prioritize unique login portals, tenant selection screens, admin consoles, file management, billing, API documentation, legacy interfaces, and non-production-looking pages. Verify ownership and security relevance before deeper testing.

##### 5. Convert visual leads into testable hypotheses

For each cluster, record observed roles, major workflows, visible API routes, framework clues, and potential trust boundaries. Reproduce the observation in a browser or proxy before assigning a vulnerability label.

#### What This Produces

- A visual catalog of confirmed web applications.
- Clusters that reduce duplicate manual review.
- A prioritized queue of unique workflows and authentication surfaces.
- Reproducible screenshot metadata linked to each URL.

#### Evidence Requirements

- URL and final redirect destination.
- Timestamped screenshot plus status/title metadata.
- Cluster rationale and confidence.
- Separate technical evidence for any claimed vulnerability.

#### Tool examples and roles (verify in the shared catalog)

- Playwright or Chromium headless capture.
- gowitness or EyeWitness where available.
- curl/httpx for request-level follow-up; headless Playwright only when a local fixture requires rendering.
- Python scripts for URL normalization, screenshot indexing, and metadata export.

#### Visual Triage Matrix

| Signal | Triage value | Follow-up |
|---|---|---|
| Distinct login portal | Potential separate identity boundary | Map SSO, tenant, and role flows |
| Admin-like interface | High-value functionality candidate | Verify access control using test roles |
| API documentation page | Endpoint inventory | Compare declared and observed auth controls |
| Similar screenshots across hosts | Possible shared application deployment | Check hostname-specific configuration |
| Unique upload/billing/tenant workflow | Business logic surface | Build a workflow map and test invariants |
| Browser error or parked page | Usually low value | Confirm DNS and attribution before discarding |
| Different title only | Weak fingerprint | Corroborate with DOM/assets and repeat capture |

#### Verification and False Positives

- Exclude random-host catch-all pages and generic CDN error screens.
- Keep cookies and authentication state consistent when comparing pages.
- Do not infer ownership from branding alone.
- Treat screenshots as navigation evidence, not proof of server-side access.
- Re-capture dynamic pages before concluding that two deployments differ.

#### Stop Conditions

- Stop capturing a host and flag it for review if a page prompts for real payment details, displays what appears to be another customer's live data, or returns content inconsistent with program scope.
- Stop and throttle if the target shows rate-limiting, CAPTCHA challenges, or WAF block pages across multiple hosts; bulk headless capture should not be mistaken for a denial-of-service attempt.
- Stop before any authenticated or state-changing interaction; visual recon hands off to the relevant attack-* or auth skill once a testable hypothesis is formed, it does not perform the test itself.

#### Defensive Notes

- Organizations can reduce the value of this technique by consolidating default/placeholder pages, disabling framework and admin-panel banners on production hosts, and keeping staging/legacy interfaces off public DNS or behind authentication.
- Consistent, informative error pages (rather than framework-default error pages) reduce fingerprinting value from screenshots and titles alone.


#### Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. there is no fixed hypothesis-count ceiling; continue distinct, decision-relevant hypotheses while authorized, and stop when evidence or a real safety/policy boundary resolves the branch. Prefer passive evidence first and perform active checks only when explicitly in scope.

##### Evidence record and confidence

For each candidate, preserve normalized asset, provenance, capture time, scope proof, browser/tool and version, evidence location, corroborating signal, negative control, attribution confidence, next action and related-skill trigger. Separate asset confidence from security confidence.

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** a specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. Visual similarity or a distinctive screenshot alone cannot exceed C1/C2.

##### Visual signal follow-through

Normalize URLs and capture conditions; compare viewport, title, DOM landmarks, favicon, branding, application routes and login state. Separate apparent clones caused by shared templates, CDN error pages, branding reuse or default hosting pages. For each high-priority visual cluster, write a falsifiable hypothesis about a distinct application or trust boundary, then route it to the relevant framework, access-control, API or technology-fingerprinting skill.

##### Deduplication and stop rules

Deduplicate by canonical host/URL, redirect destination, title/DOM fingerprint and application identity while retaining alternate routes that can cross a different trust boundary. Stop on scope ambiguity, unexpected sensitive information, service instability, or if capture requires unapproved credentials or active behavior.

##### Handoff format

Return normalized asset, scope/provenance, capture conditions, confidence, duplicate cluster, negative control, prioritization rationale, candidate hypothesis, safe next step and trigger for any linked attack skill. A screenshot is evidence of what rendered, not proof of a vulnerability.

##### Skill-specific next steps

1. Collect screenshots only for confirmed in-scope live URLs and approved test roles; do not sign in using real customer identities or capture unrelated tenants.
2. Normalize scheme, redirects, trailing slashes, viewport, locale, and authentication state before comparing images; preserve URL and timestamp with each screenshot.
3. Deduplicate by canonical URL, page title, stable visual hash, and application identity. Treat SPA catch-alls, error pages, CDN placeholders, and generic login screens as separate clusters.
4. Redact or avoid screenshots containing personal data, session values, API keys, internal hostnames, or customer content; store evidence in a target-scoped directory with appropriate permissions.
5. Return an application inventory and visual-difference leads with provenance and confidence. Visual similarity/difference helps prioritization but never confirms a vulnerability without protocol-level verification.

#### References

- Source merged: [uphiago/recon-skills — recon/visual-recon/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/visual-recon/SKILL.md)
- [Playwright documentation](https://playwright.dev/docs/intro)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)


#### Targeted quality-loop enrichment (2026-10-19)

##### Visual clusters as testable hypotheses
Capture consistent screenshots at the same viewport and auth context, then cluster only as a navigation aid—not as proof that two apps share code or ownership. Retain URL, screenshot hash/path, title, favicon/theme fingerprint, response status, and comparison rationale. Convert each visual anomaly into one question (different tenant, admin console, old version, hidden workflow, unexpected login state) and verify with normal HTTP evidence. Avoid screenshotting personal information and redact account names/IDs. Route admin-specific paths to BFLA, tenant/object references to IDOR, and visually different auth flows to the authentication specialist only after the request behavior corroborates the visual clue.


#### Chapter-specific implementation notes and resources

Use agent-executable CLI tools and local scripts. Browser interfaces, browser extensions, and interactive intercepting proxies are not required dependencies. Verify tool availability/version and official installation guidance before use; inspect request impact and permissions before active testing.

##### Recommended tools
- gowitness — headless screenshots for validated HTTP targets
- aquatone — visual clustering and HTTP inventory where compatible
- Python/Pillow — local image metadata and grouping
- jq — correlate screenshot records with host inventory

##### Resources
- https://github.com/sensepost/gowitness
- https://github.com/michenriksen/aquatone
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids; confirm maintenance, license, provenance, and exact CLI behavior from official sources.

##### Helper-script contract
Capture only validated authorized hosts; preserve URL, timestamp, status, screenshot path/hash, title, and cluster fingerprint. Screenshot similarity is a prioritization clue, not vulnerability proof.

Normalize routine outputs into the canonical inventory and keep provenance, timestamps, tool/version, errors, confidence, and artifact paths with each observation. Retain raw output only when it adds unique evidence, reproducibility, or diagnostic value; do not create a raw copy for every tool/run. Redact secrets, support JSON/JSONL where useful, and include local fixtures.

##### Handoff
Report commands actually executed, tool versions, input/output artifact references, deduplication counts, errors/blocked sources, confidence, limitations, and the next skill.

---

## 09. Public GitLab project reconnaissance

### GitLab Public Project Reconnaissance

### Chapter profile

**Purpose:** Inventory public GitLab projects, groups, package artifacts, CI configuration, and exposed metadata with ownership verification.

**Prerequisites:** A confirmed organization namespace or public GitLab instance

**Technology:** `GitLab`, `Git`, `HTTP`, `CI/CD`

**Coverage tags:** `recon`, `GitLab`, `source-code`, `CI/CD`, `information-disclosure`

**Related security workflows:** `attack-source-leak`, `cicd-attacks`

**Impact qualification:** high: A public artifact exposes a sensitive private asset or a verified active secret, confirmed without using the secret.

**Legacy source:** `recon-gitlab-public-recon` v"1.0.0"; credited to cyberstrike-official.

#### Objective

Discover public GitLab projects and artifacts associated with an organization, then identify source/configuration exposure that materially affects security. Public project visibility is not inherently a vulnerability; attribution and data sensitivity determine relevance.

#### Methodology

##### 1. Establish the namespace

Start with the organization's official GitLab group, known project links, developer documentation, and confirmed domains. Search public namespaces using domain and organization identifiers, but treat name matches as candidates until ownership is corroborated.

##### 2. Inventory public projects and artifacts

Review project descriptions, default branches, tags/releases, package registries, container image metadata, wiki pages, issue attachments, snippets, and CI configuration. Record project URL, visibility, last activity, owner/group, and relevance. Use unauthenticated public interfaces or approved API access only.

##### 3. Inspect high-value files and history

Prioritize deployment manifests, CI variables references, Dockerfiles, infrastructure-as-code, environment templates, configuration files, backup artifacts, and scripts that reveal trust boundaries. Review commit history where public and relevant; avoid cloning huge unrelated repositories or collecting private user data.

##### 4. Analyze CI/CD trust boundaries

Look for untrusted merge-request code running with privileged runners, unsafe artifact exposure, overly broad token permissions, insecure deployment rules, and secrets printed in job logs. Configuration patterns are leads: establish whether the affected workflow is reachable and whether a real permission boundary is crossed.

##### 5. Classify secret-like strings safely

Use local secret-scanning tools on the minimum relevant repository content. Treat matches as unverified candidates; redact immediately and do not authenticate to third-party services with discovered material. Determine likely type and location from context, and ask the owner to verify/revoke through their normal process.

##### 6. Confirm impact and report

A report should identify the public asset, why it belongs to the organization, what non-public information or control gap is exposed, and the smallest sanitized proof. For a CI/CD issue, describe the trust relationship and permission consequence without triggering a deployment or modifying pipelines.

#### What Constitutes a Finding

- A public repository or artifact unintentionally exposes non-public source, internal configuration, personal data, or secret material.
- A CI/CD configuration defect allows untrusted contributors or jobs to cross a meaningful deployment or privilege boundary.
- A repository name, public README, intentionally published SDK, public client identifier, or stale placeholder secret alone is not a vulnerability.

#### Evidence Requirements

- Canonical project/group URL, public visibility evidence, and ownership rationale.
- Exact file path/commit or artifact location and a minimal redacted excerpt.
- For CI/CD, the relevant trust rule and resulting permission boundary.
- Secret values and private personal data must not be copied into the report; do not test a candidate secret.

#### Tool examples and roles (verify in the shared catalog)

- GitLab documented public API and `glab` CLI where appropriate; do not depend on the web UI.
- `git`: bounded repository/history inspection for public repositories within the task's permitted scope.
- `gitleaks` or `trufflehog` in local mode on authorized public content.
- YAML/CI linters and static review tools for pipeline configuration.
- `jq` / Python: normalize metadata and export inventory.

Verify `git --version`, `jq --version`, and `glab --version` if installed. Official docs: https://docs.gitlab.com/ee/api/, https://docs.gitlab.com/editor_extensions/gitlab_cli/, https://github.com/gitleaks/gitleaks/.

#### Public GitLab Review Matrix

| Surface | Review question | Strong evidence | False positive |
|---|---|---|---|
| Group/project | Is the project actually attributable to the target? | Official links, group ownership, matching first-party references | Same-name user or organization |
| Repository files | Is non-public configuration exposed? | Sensitive internal details or secret material in context | Example/template with placeholders |
| Commit history | Was sensitive material committed publicly? | Specific commit and affected artifact with redacted proof | Revoked sample/test string |
| CI pipeline | Can untrusted code access privileged runner/secrets? | Concrete rule path and permission consequence | Runner exists but is isolated |
| Job logs | Are secrets or private data printed? | Redacted log line with clear sensitive context | Masked placeholder or benign build output |
| Packages/artifacts | Is a private build unintentionally public? | Identifiable internal artifact and sensitive contents | Intended public release |
| Container registry | Are images/config layers exposing private assets? | Minimal image metadata/layer proof | Public base image or normal package |
| Snippets/wiki/issues | Is sensitive content accidentally public? | Specific non-public data with provenance | Public documentation by design |

#### Verification and False Positives

- Confirm ownership independently of project naming.
- Separate public source from private configuration and deploy-time secrets.
- Secret scanners produce false positives; do not validate by logging in or making privileged API calls.
- Public client-side configuration can be intended; assess what authority the value actually grants.
- Do not trigger CI pipelines, change settings, or attempt deployment as proof.


#### Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. there is no fixed hypothesis-count ceiling; continue distinct, decision-relevant hypotheses while authorized, and stop when evidence or a real safety/policy boundary resolves the branch. Prefer passive sources first, deduplicate candidates, and use active checks only when the asset and activity are explicitly in scope.

##### Evidence record and confidence

For each candidate, preserve normalized asset, source/provenance, observation time, scope proof, resolver/HTTP/tool and relevant version, raw-evidence location, corroborating source, negative control, attribution confidence, next action, and related-skill trigger. Separate **asset confidence** (is it related to the organization?) from **security confidence** (is a vulnerability demonstrated?).

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. C1/C2 are not confirmed vulnerabilities.

##### Skill-specific next steps

1. Confirm the GitLab host and organization/group attribution through first-party domains, verified group ownership, or repository metadata; a matching brand string alone is insufficient.
2. Use read-only public metadata and bounded pagination to inventory public projects, snippets, package/container registries, CI configuration, and release artifacts that are explicitly in scope.
3. Distinguish public-by-design content from accidental exposure; inspect a minimal file/commit context and avoid cloning unrelated projects or collecting private contributor data.
4. If a secret-shaped value appears, record detector type, project, path, and commit without copying it. Only verify validity through a single read-only identity call if explicit authorization allows it.
5. Return provenance, deduplication key, last-seen commit/time, ownership confidence, and safe next-step trigger. Do not treat a public project, open signup, or a code fingerprint as a vulnerability by itself.


##### Deduplication and stop rules

Normalize case, trailing dots, scheme/port, redirects, canonical names and resolved addresses before deduplication. Detect wildcard DNS, shared hosting, CDN/edge responses, soft-404s and stale records before ranking counts. Stop on exclusions, ownership ambiguity, unexpected sensitive data, throttling, instability or boundaries requiring further permission. Never claim ownership or register dangling resources.

##### Handoff format

Return candidates with scope/provenance, confidence level, evidence path, deduplication key, negative control, priority rationale, safe next step and trigger for any linked attack skill. Promote a candidate to active testing only after scope and attribution are confirmed; promote it to a finding only after the relevant attack skill verifies the security boundary.

#### References

- Source merged: [uphiago/recon-skills — recon/gitlab-public-recon/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/gitlab-public-recon/SKILL.md)
- [GitLab CI/CD Security](https://docs.gitlab.com/ci/security/)
- [GitLab REST API](https://docs.gitlab.com/api/)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)


#### Targeted quality-loop enrichment (2026-10-19)

##### Repository attribution and secret-safe handling
Confirm namespace/organization attribution and public visibility before pivoting through group projects, forks, issue attachments, packages, snippets, build artifacts, and commit history. Preserve repository URL, commit hash, path/line, observed time, and whether the content is current, deleted, forked, or generated. Secret-like matches must be recorded as type plus redacted fingerprint; do not test or reuse credentials or access projects beyond what is public and authorized. Distinguish public code disclosure from an exploitable credential or CI trust boundary. Route workflow/runner problems to CI/CD review, first-party JavaScript to JS analysis, and secret candidates to evidence-safe triage without invoking them.


#### Chapter-specific implementation notes and resources

Use agent-executable CLI tools and local scripts; browser interfaces, extensions, and interactive intercepting proxies are not dependencies. Check tool presence/version and official documentation before running it; only process data the operator is authorized to inspect.

##### Recommended tools
- gitleaks — scan local checked-out repositories
- GitHub/GitLab native CLI or API client for public metadata where authorized
- git — inspect history and repository metadata
- jq/rg — normalize matches and redact sensitive values

##### Resources
- https://github.com/gitleaks/gitleaks
- https://docs.gitlab.com/cli/
- https://git-scm.com/docs
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids; verify project maintenance, license, and supported behavior from official sources.

##### Helper-script contract
Collect repository URL, commit/hash, path, detector, and redacted fingerprint. Do not test leaked credentials or access private repositories without explicit permission.

Normalize routine results into the canonical inventory and preserve provenance, timestamp, tool/version, detector/rule, error state, confidence, redaction, and artifact path. Keep raw artifacts only when they add unique evidence, reproducibility, or diagnostic value; otherwise do not create a duplicate copy. Use JSON/JSONL when useful and test redaction on local fixtures.

##### Handoff
Return actual commands and versions, inputs/outputs, records processed, redaction status, errors, confidence, limitations, and next skill. Never include live secrets in notes or reports.


---

---

## 10. Email domain security assessment

### Email Domain Security Assessment

### Chapter profile

**Purpose:** Assess SPF, DKIM, DMARC, MX, MTA-STS, TLS-RPT, and mail transport configuration for domain spoofing and delivery risks.

**Prerequisites:** A confirmed organization-owned domain

**Technology:** `DNS`, `SMTP`, `TLS`

**Coverage tags:** `email-security`, `SPF`, `DKIM`, `DMARC`, `DNS`, `SMTP`

**Related security workflows:** `attack-information-disclosure`

**Impact qualification:** high: A controlled, non-deceptive validation proves that an unauthorized message can pass recipient-side authentication and materially impersonate the organization.

**Legacy source:** `recon-email-security` v"1.0.0"; credited to cyberstrike-official.

#### Objective

Evaluate whether DNS policy and mail authentication allow sender impersonation or expose weaknesses in mail transport. DNS posture alone does not prove that a spoofed message will reach an inbox; receiver policy, alignment, and actual message authentication results matter.

#### Methodology

##### 1. Inventory mail identity and routing

Collect MX records, SPF TXT records, the _dmarc policy, DKIM selectors known from legitimate messages or provider documentation, and MTA-STS/TLS-RPT records. Record DNS TTLs and delegated subdomains. Assess the organizational domain and mail-sending subdomains separately.

##### 2. Evaluate SPF correctly

Check for one valid SPF record, syntax errors, excessive DNS lookups, unintended broad mechanisms, and the terminal qualifier. The qualifiers -all, ~all, ?all, and +all have materially different semantics. SPF authorizes sending hosts for the SMTP envelope domain; it does not alone authenticate the visible From header and must be interpreted with DMARC alignment.

##### 3. Evaluate DKIM coverage

Review DKIM signatures from legitimate organization mail and verify selector DNS records, key strength, and signing-domain alignment. A missing guessed selector is not proof DKIM is absent; selectors are sender-specific. A published key proves configuration, not that every mail stream is signed.

##### 4. Evaluate DMARC policy and alignment

Parse p, sp, pct, adkim, aspf, rua, and ruf. Determine whether the visible From domain aligns with SPF and/or DKIM. Assess root-domain and subdomain policy. p=none requests monitoring rather than enforcement, but does not automatically prove successful impersonation or total lack of receiver-side protection.

##### 5. Evaluate transport controls

Inspect MTA-STS policy and TLS-RPT reporting configuration where published. Check MX host TLS behavior with a normal protocol-aware client, certificate validity, and support for modern TLS. Separate transport encryption posture from sender identity authentication.

##### 6. Validate practical impact carefully

Prefer passive DNS and analysis of legitimate test messages. If active spoofing validation is explicitly approved, use a controlled mailbox and a clearly labeled non-deceptive test message; do not target employees, customers, or third parties. Preserve the recipient's Authentication-Results and relevant message headers, then stop.

#### What Constitutes a Finding

- A reproducible policy gap creates a meaningful impersonation risk, supported by alignment analysis or a permitted controlled test.
- SPF/DKIM/DMARC syntax or policy weaknesses are described accurately with domain and subdomain scope.
- A weak DNS record alone should be rated by practical impact and recipient behavior, not by a simplistic "spoofable" label.
- MX presence, a missing guessed DKIM selector, or p=none without impact context is not by itself proof of compromise.

#### Evidence Requirements

- Sanitized DNS outputs with timestamps and TTLs.
- Parsed SPF/DMARC values and lookup-count analysis.
- If approved, a controlled test message's sanitized Authentication-Results, From, Return-Path, DKIM d=, and DMARC alignment result.
- Never include recipient personal data, session material, or deceptive-message content in reusable artifacts.

#### Tool examples and roles (verify in the shared catalog)

- `dig` / `host`: inspect SPF, DKIM selector, DMARC, MTA-STS, and TLS-RPT DNS records.
- `openssl s_client`: inspect SMTP TLS negotiation where explicitly permitted.
- Python DNS/HTTP libraries: validate published policy syntax and HTTPS policy retrieval.
- Mail-testing API or test inbox controlled by the tester: validate only approved test messages.
- SPF/DMARC parsers and MTA-STS policy checkers: corroborate syntax and policy behavior.

Verify `dig -v` and `openssl version`. Official docs: https://www.openssl.org/docs/, https://datatracker.ietf.org/doc/html/rfc7208, https://datatracker.ietf.org/doc/html/rfc7489, https://datatracker.ietf.org/doc/html/rfc8461/.

#### Email Control Matrix

| Control | Strong posture | Weak signal | Interpretation caveat |
|---|---|---|---|
| SPF | One valid record, narrow senders, deliberate terminal policy | Permissive +all, invalid record, excessive lookups | SPF authenticates envelope sender, not visible From alone |
| DKIM | Relevant streams signed with aligned domain and adequate key | Unsigned stream or misaligned signature | Unknown selector does not mean no DKIM |
| DMARC | p=reject after monitoring, correct alignment and subdomain policy | p=none, partial rollout, weak alignment | Receiver handling can differ; policy is not delivery proof |
| MX | Expected mail providers only | Stale/unexpected MX | MX is routing metadata, not spoofing proof |
| MTA-STS | Valid policy with enforce mode where appropriate | Missing/expired policy or testing mode | Applies to SMTP transport, not sender identity |
| TLS-RPT | Reports configured and reviewed | No reporting visibility | Reporting absence is usually hardening, not direct exploit |
| Subdomains | Explicit sending and DMARC strategy | Unmanaged subdomain mail | Parent policy and sp behavior must be checked |

#### Verification and False Positives

- Re-query DNS from independent resolvers and account for TTL/propagation.
- Check for duplicate SPF records and parse nested includes rather than judging one TXT string.
- Evaluate SPF and DKIM alignment with the exact visible From domain.
- Distinguish transport TLS findings from spoofing findings.
- Do not infer that any third-party service allowed by SPF can freely send as the domain; provider-side account/domain verification controls matter.
- Avoid claims of complete spoofing without a controlled recipient-side result or strong technical proof.


#### Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. there is no fixed hypothesis-count ceiling; continue distinct, decision-relevant hypotheses while authorized, and stop when evidence or a real safety/policy boundary resolves the branch. Prefer passive sources first, deduplicate candidates, and use active checks only when the asset and activity are explicitly in scope.

##### Evidence record and confidence

For each candidate, preserve normalized asset, source/provenance, observation time, scope proof, resolver/HTTP/tool and relevant version, raw-evidence location, corroborating source, negative control, attribution confidence, next action, and related-skill trigger. Separate **asset confidence** (is it related to the organization?) from **security confidence** (is a vulnerability demonstrated?).

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. C1/C2 are not confirmed vulnerabilities.

##### Skill-specific next steps

1. Anchor checks to the verified organizational domain and query SPF, DMARC, MX, and observed DKIM selectors using DNS-only requests; save raw answers, resolver, and timestamp.
2. Parse SPF includes/redirects and the 10-DNS-lookup limit, and inspect DMARC policy, alignment, reporting destinations, and subdomain policy. A record's existence does not prove correct enforcement.
3. Do not infer absence of DKIM from a short list of guessed selectors; use selector evidence from authorized sample mail or first-party configuration when available.
4. Treat p=none, missing records, and weak alignment as posture observations whose reportability depends on program scope and impact. Do not send spoofed mail or claim successful spoofing from DNS records alone.
5. Return normalized records, parsing result, provenance, confidence, and specific safe remediation (SPF mechanism cleanup, DKIM key lifecycle, DMARC alignment/enforcement and reporting) without collecting message content or recipient data.


##### Deduplication and stop rules

Normalize case, trailing dots, scheme/port, redirects, canonical names and resolved addresses before deduplication. Detect wildcard DNS, shared hosting, CDN/edge responses, soft-404s and stale records before ranking counts. Stop on exclusions, ownership ambiguity, unexpected sensitive data, throttling, instability or boundaries requiring further permission. Never claim ownership or register dangling resources.

##### Handoff format

Return candidates with scope/provenance, confidence level, evidence path, deduplication key, negative control, priority rationale, safe next step and trigger for any linked attack skill. Promote a candidate to active testing only after scope and attribution are confirmed; promote it to a finding only after the relevant attack skill verifies the security boundary.

#### References

- Source merged: [uphiago/recon-skills — recon/email-security/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/email-security/SKILL.md)
- [RFC 7208 — SPF](https://www.rfc-editor.org/rfc/rfc7208)
- [RFC 6376 — DKIM](https://www.rfc-editor.org/rfc/rfc6376)
- [RFC 7489 — DMARC](https://www.rfc-editor.org/rfc/rfc7489)
- [RFC 8461 — MTA-STS](https://www.rfc-editor.org/rfc/rfc8461)
- [RFC 8460 — TLS Reporting](https://www.rfc-editor.org/rfc/rfc8460)


#### Targeted quality-loop enrichment (2026-10-19)

##### Mail-domain evidence and impact boundary
For each sending domain/subdomain, map MX, SPF, DKIM selectors, DMARC policy/alignment, TLS reporting/MTA-STS where relevant, and vendor delegation. Preserve DNS observation time and distinguish no record, lookup failure, stale cache, and misconfiguration. A permissive SPF or DMARC policy is a configuration weakness, not proof of spoofing impact; validate with an authorized synthetic recipient/domain and do not send deceptive mail to real users. Keep third-party SaaS sending sources separate from organizational ownership. Route exposed webmail/Autodiscover to the mail-product review and identity-federation signals to OAuth/SAML only when the actual flow is observed.


#### Chapter-specific implementation notes and resources

Use agent-executable CLI tools and local scripts. Browser interfaces, browser extensions, and interactive intercepting proxies are not required dependencies. Verify tool availability/version and official installation guidance before use; inspect request impact and permissions before active testing.

##### Recommended tools
- dig/drill — DNS record checks
- testssl.sh or tlsx — TLS configuration metadata
- swaks — controlled SMTP protocol checks where permitted
- Python/jq — parse DNS, TLS, and mail security records

##### Resources
- https://github.com/drwetter/testssl.sh
- https://github.com/projectdiscovery/tlsx
- https://www.rfc-editor.org/
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids; confirm maintenance, license, provenance, and exact CLI behavior from official sources.

##### Helper-script contract
Record SPF/DKIM/DMARC observations, DNS provenance, TLS protocol/certificate metadata, and timestamp. Distinguish missing policy from demonstrated exploitability and avoid sending unsolicited mail.

Normalize routine outputs into the canonical inventory and keep provenance, timestamps, tool/version, errors, confidence, and artifact paths with each observation. Retain raw output only when it adds unique evidence, reproducibility, or diagnostic value; do not create a raw copy for every tool/run. Redact secrets, support JSON/JSONL where useful, and include local fixtures.

##### Handoff
Report commands actually executed, tool versions, input/output artifact references, deduplication counts, errors/blocked sources, confidence, limitations, and the next skill.


---

---

## 11. Exposed error-log analysis

### Exposed Error-Log Analysis

### Chapter profile

**Purpose:** Discover exposed application error logs and evaluate disclosure of internal paths, stack traces, queries, and secret-like material with minimal evidence.

**Prerequisites:** A confirmed in-scope web application

**Technology:** `HTTP`, `PHP`, `WordPress`, `Linux`

**Coverage tags:** `information-disclosure`, `error-logs`, `debug`, `secrets-hygiene`, `PHP`

**Related security workflows:** `attack-information-disclosure`, `attack-source-leak`, `attack-phpinfo-exposure`

**Relevant weakness classes:** `CWE-200`, `CWE-532`

**Impact qualification:** high: An exposed log contains a demonstrably active secret or sensitive user data with material impact, verified without using the secret.

**Legacy source:** `recon-error-log-mining` v"1.0.0"; credited to cyberstrike-official.

#### Objective

Find publicly retrievable error/debug logs and determine whether they disclose meaningful internal information. Prioritize classification and minimal proof over bulk downloading or harvesting sensitive records.

#### Testing Methodology

##### 1. Discover likely log locations

Use passive source references, robots/sitemap entries, repository paths, framework conventions, and a small set of likely public paths. Common patterns include error_log, debug.log, framework log directories, and CMS debug outputs. Treat a 200 response only as a candidate.

##### 2. Confirm the response is a real log

Compare a small bounded byte range with a random nonexistent path. Check for repeated timestamps, recognizable error prefixes, stack-trace structure, log-level labels, and consistent content-type behavior. Exclude SPA fallback pages, generic error templates, and CDN cache artifacts.

##### 3. Bound collection

Use HEAD or range requests when supported, impose strict byte/time limits, and avoid downloading large files. Preserve a short sanitized excerpt sufficient to establish the issue. Do not bulk-ingest or index customer records, credentials, or personal data.

##### 4. Classify disclosed material

Classify findings into internal filesystem paths and deployment layout; stack traces, framework versions, and component names; SQL statements or schema names; internal hostnames/IPs; email addresses and user identifiers; secret-like strings, tokens, cookies, database connection strings, or signing material; and user-submitted data accidentally logged.

Treat pattern matches as candidates only. Never test a discovered credential against a service; confirm validity through an owner-provided verification channel or metadata that does not expose or use the secret.

##### 5. Determine reachability and impact

Establish whether unauthenticated users can retrieve the log, whether it is current, and whether the content reveals a meaningful attack path. A path or version disclosure may be informational; a live secret or sensitive record can raise severity, but must be handled with minimal evidence and immediate redaction.

##### 6. Identify root cause

Check production debug settings, web-server deny rules, deployment packaging, log rotation and permissions, public static-file mappings, backup/sync jobs, and CMS plugin/theme behavior. Recommend removing logs from web roots and preventing future writes to publicly served locations.

#### What Constitutes a Finding

- A real log is retrievable by an unauthorized user and contains non-public information.
- Impact is based on the exact disclosed content and its sensitivity, not the file name or byte size.
- A valid secret should not be copied into a report; identify the secret type, location, and minimal redacted fingerprint instead.
- A generic error page, empty log, public sample log, or stale benign stack trace may not justify a security finding.

#### Evidence Requirements

- URL, retrieval timestamp, response status/content type, and bounded byte range.
- Sanitized excerpt showing log structure and one representative disclosure.
- Random-path/soft-404 control.
- Secret values, personal data, cookies, tokens, and customer content must be redacted.
- Note whether the file is current and whether sensitive material was validated without using it.

#### Tool examples and roles (verify in the shared catalog)

- `curl` with explicit timeouts, byte ranges, and output-size limits for an observed authorized resource.
- `file`, `grep`, `rg`, and Python parsers for log-format classification.
- Local secret scanners on reviewed excerpts; do not upload target logs to third-party scanning services.
- `python3 .cyberstrike/skill/scripts/validate_evidence_manifest.py evidence/manifest.json`: validate artifact metadata.

Verify `curl --version`, `file --version`, and the selected parser/scanner. Official docs: https://curl.se/docs/, https://github.com/gitleaks/gitleaks/.

#### Log Disclosure Matrix

| Data class | Example signal | Potential impact | Safe proof |
|---|---|---|---|
| Internal paths | Absolute application/deployment paths | Supports targeted follow-on analysis | One sanitized path |
| Stack traces | Framework call stack and source line | Reveals code paths and versions | Short redacted stack excerpt |
| SQL details | Query template/table names | Schema disclosure or query behavior insight | Redacted query fragment |
| Internal network metadata | Private hostnames/IPs | Architecture disclosure | One address with context |
| Secret-like values | Token/password/API-key pattern | Potential unauthorized access | Type, location, redacted fingerprint only |
| Personal/customer data | Emails, IDs, request bodies | Privacy/confidentiality exposure | Minimal redacted sample |
| Debug configuration | Verbose errors, environment values | Increases information leakage | Exact setting/output with secrets removed |

#### Verification and False Positives

- Compare the candidate to a random path on the same host.
- Confirm the body is a log, not a cached page or generic SPA shell.
- Check timestamps and repetition before claiming current exposure.
- Pattern-matched tokens can be placeholders, expired, or synthetic; do not assert validity without safe corroboration.
- Do not download whole multi-gigabyte logs or validate credentials by attempting login.
- If evidence contains secrets, stop collection, redact immediately, and follow the engagement's sensitive-data handling process.


#### Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. there is no fixed hypothesis-count ceiling; continue distinct, decision-relevant hypotheses while authorized, and stop when evidence or a real safety/policy boundary resolves the branch. Prefer passive sources first, deduplicate candidates, and use active checks only when the asset and activity are explicitly in scope.

##### Evidence record and confidence

For each candidate, preserve normalized asset, source/provenance, observation time, scope proof, resolver/HTTP/tool and relevant version, corroborating source, raw-evidence location when retained, negative control, attribution confidence, next action, and related-skill trigger. Separate **asset confidence** (is it related to the organization?) from **security confidence** (is a vulnerability demonstrated?).

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. C1/C2 are not confirmed vulnerabilities.

##### Skill-specific next steps

1. Confirm the candidate log/debug artifact is publicly reachable and in scope; request a random-path or equivalent inaccessible-resource control to detect generic error pages.
2. Identify log type, time range, and application ownership from minimal metadata first. Distinguish harmless stack traces from live session material, credentials, personal data, or internal-only request details.
3. Collect only a few sanitized lines necessary to prove exposure. Do not download full logs, test credentials found in logs, or follow tokens into other services.
4. Check whether output is cached, generated per request, intentionally public, or requires an authenticated role; verify the access boundary using your own test session if applicable.
5. Report exact URL/role, sensitive categories, minimal redacted proof, and remediation for access control, secret rotation, log redaction, and cache invalidation.


##### Deduplication and stop rules

Normalize case, trailing dots, scheme/port, redirects, canonical names and resolved addresses before deduplication. Detect wildcard DNS, shared hosting, CDN/edge responses, soft-404s and stale records before ranking counts. Stop on exclusions, ownership ambiguity, unexpected sensitive data, throttling, instability or boundaries requiring further permission. Never claim ownership or register dangling resources.

##### Handoff format

Return candidates with scope/provenance, confidence level, evidence path, deduplication key, negative control, priority rationale, safe next step and trigger for any linked attack skill. Promote a candidate to active testing only after scope and attribution are confirmed; promote it to a finding only after the relevant attack skill verifies the security boundary.

#### References

- Source merged: [uphiago/recon-skills — recon/error-log-mining/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/error-log-mining/SKILL.md)
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)


#### Targeted quality-loop enrichment (2026-10-19)

##### Log validation without collecting secrets
First confirm the response is a real log artifact rather than a generic debug page or synthetic sample. Inspect a small, bounded excerpt and immediately redact access tokens, session IDs, email addresses, internal URLs, query data, and personal information. Record file/source, exposure path, timestamp, response access policy, and the minimum sensitive marker needed to establish the boundary. Do not recursively crawl or download all logs. Separate a stack trace from a log containing secrets or customer records; a discovered secret must not be tested or used. Route source/build paths to source-leak, metrics data to metrics exposure, and detailed exception disclosure to triage with a specific demonstrated impact statement.


#### Chapter-specific implementation notes and resources

Use agent-executable CLI tools and local scripts; browser interfaces, extensions, and interactive intercepting proxies are not dependencies. Check tool presence/version and official documentation before running it; only process data the operator is authorized to inspect.

##### Recommended tools
- rg — search locally supplied logs for high-signal error patterns
- jq — parse JSON logs
- Python — redact tokens/PII and aggregate repeated stack signatures
- Semgrep only for related local source analysis

##### Resources
- https://owasp.org/www-project-web-security-testing-guide/
- https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids; verify project maintenance, license, and supported behavior from official sources.

##### Helper-script contract
Process only logs the user is authorized to inspect. Redact tokens, cookies, personal data, and internal secrets before storing output; preserve source file/line and a stable redacted fingerprint.

Normalize routine results into concise, redacted findings and keep provenance, timestamp, tool/version, detector/rule, error state, confidence, redaction, and artifact path. Retain source excerpts or raw artifacts only when they add unique evidence, reproducibility, or diagnostic value; preserve a minimal redacted proof and do not duplicate entire logs.

##### Handoff
Return actual commands and versions, inputs/outputs, records processed, redaction status, errors, confidence, limitations, and next skill. Never include live secrets in notes or reports.


---
