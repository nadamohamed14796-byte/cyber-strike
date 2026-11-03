# Recon Technique Chapters

This is the detailed procedure reference for the single canonical `recon-master` skill. It is not a second skill, run orchestrator, tool catalog, or phase artifact matrix.

Read only the chapter selected by the routing table in `SKILL.md`. Use the returned skill `Base directory` and exact companion path `RECON_CHAPTERS.md`; never resolve it against the target workspace. Do not load this entire file for ordinary reconnaissance.

The shared scope, attribution-confidence, coverage-status, evidence-record, deduplication, stopping, and handoff contracts live once in `SKILL.md`. Canonical phase artifacts live in `RECON_PHASE_TOOL_MATRIX.md`. Shared tools, APIs, CLIs, helpers, and preflight rules live in `community-tool-selection/TOOLING_CATALOG.md`.

## Chapter index

| # | Procedure |
|---:|---|
| 01 | [Cross-asset attribution and delta analysis](#01-cross-asset-attribution-and-delta-analysis) |
| 02 | [Subdomain enumeration and validation](#02-subdomain-enumeration-and-validation) |
| 03 | [ASN and infrastructure mapping](#03-asn-and-infrastructure-mapping) |
| 04 | [Origin IP exposure assessment](#04-origin-ip-exposure-assessment) |
| 05 | [Port and service discovery](#05-port-and-service-discovery) |
| 06 | [Virtual-host enumeration](#06-virtual-host-enumeration) |
| 07 | [CMS and component fingerprinting](#07-cms-and-component-fingerprinting) |
| 08 | [Visual reconnaissance and application clustering](#08-visual-reconnaissance-and-application-clustering) |
| 09 | [Public GitLab project reconnaissance](#09-public-gitlab-project-reconnaissance) |
| 10 | [Email domain security assessment](#10-email-domain-security-assessment) |
| 11 | [Exposed error-log analysis](#11-exposed-error-log-analysis) |

## Procedures

## 01. Cross-asset attribution and delta analysis

### Purpose

Interpret relationships between discovered assets without confusing technical association, ownership, current scope, liveness, and security impact. Use this chapter when several sources disagree, infrastructure is shared, or a prior recon snapshot is available.

### Attribution

- Correlate only observed relationships: DNS A/AAAA/CNAME/PTR chains, TLS CN/SAN values, certificate-transparency names, HTTP/TLS fingerprints, redirects, first-party links, script/API origins, and documented organization assets.
- Classify each relationship as first-party-supported, shared-provider/CDN, third-party service, alias/dependency, historical-only, ambiguous, or unresolved. Preserve the source, observation time, and confidence; a shared IP, certificate SAN, CNAME, or first-party reference does not prove ownership.
- Keep attribution confidence separate from the persisted scope decision and from vulnerability confidence. An out-of-scope or unresolved lead must not enter active target inventories or be probed.
- For dependencies, record evidence-backed lifecycle state such as active, deprecated/legacy, orphan-suspected, or unknown. Route suspected takeover or shadow-API work to its dedicated skill only when scope and the required evidence support that handoff.

### Delta and freshness

- Compare the current verified snapshot with prior observations for DNS/CNAME/provider changes, TLS/HTTP fingerprints, URLs and method/parameter variants, JS content hashes, authentication coverage, and third-party destinations.
- Preserve `first_seen`, `last_seen`, and `last_checked` where available. Classify changes as new, changed, stale, removed-from-current-observation, or unresolved; absence from a later collection is not proof that an asset was deleted.
- Reuse old evidence only while its input, tool/settings, and freshness remain valid. Revalidate changed or stale observations without rerunning unrelated completed collection.
- Track anonymous and each authorized-role observation separately. A login wall, unavailable test account, or missing role is blocked coverage—not proof that the endpoint is safe.

### Persistence and handoff

Update the existing canonical asset/endpoint records and evidence graph through `target-workspace-workflow` and `attack-finding-correlation`. Do not create a second recon queue, candidate register, delta manifest, or per-host report. Keep the original source evidence and link any candidate to its asset, request/response, method, identity context, confidence, blocker, and next evidence-driven action.
#### Output contract
Update canonical asset relationship records with relationship type, source, observation time, attribution confidence, lifecycle state, and scope disposition. For each snapshot comparison, preserve the change class (`new`, `changed`, `stale`, `removed-from-current-observation`, or `unresolved`) and the evidence version that supports it.

#### Evidence Requirements
Every relationship must point to an actual DNS, TLS, HTTP, repository, first-party-link, or documented-ownership observation. Keep ownership confidence, current liveness, saved scope decision, and security impact as separate fields.

#### Verification and False Positives
A shared IP, CDN, certificate SAN, CNAME, redirect, matching brand string, or historical record does not independently prove ownership. Absence from a new snapshot does not prove deletion. Keep third-party, shared-provider, and unresolved relationships quarantined from active target inventories.

---

## 02. Subdomain enumeration and validation


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

Use a restrained wordlist derived from observed naming conventions and the application's architecture. Generate optional permutations only from labels and patterns already observed on an in-scope root (for example, a confirmed `api` label suggesting `api-staging`); scope-check each generated hostname before any request. Keep request rate and concurrency conservative, and expand based on evidence rather than running an unbounded dictionary. Alternate-TLD expansion is not part of default Recon: each different registrable domain needs its own explicit scope basis.

##### 4. Resolve DNS and identify wildcard behavior

Resolve A, AAAA, CNAME, MX, and relevant TXT records. Compare candidate answers with random labels under the same parent to detect wildcard DNS. Preserve full CNAME chains and TTLs; distinguish NXDOMAIN, NODATA, SERVFAIL, and transient resolver failures.

##### 5. Validate live web services

For confirmed in-scope names, collect HTTP status, final URL, title, TLS certificate/SAN, content type, and a stable body fingerprint. Compare with random-host controls to eliminate wildcard pages, parked domains, and SPA catch-alls. Record non-HTTP services separately.

##### 6. Attribute and cluster assets

Correlate DNS, certificate, HTTP, application branding, and infrastructure data. Classify third-party SaaS, shared hosting, CDN edges, and same-name collisions. Quarantine ambiguous hosts until ownership is corroborated.

##### 7. Prioritize distinct applications

Prioritize authentication, API, staging/preview, admin, upload, billing, tenant, legacy, and file-hosting surfaces. Feed confirmed hosts into virtual-host, origin, takeover, and application-specific workflows.

#### Output contract

- A normalized hostname list with provenance and timestamps.
- DNS resolution state, wildcard status, and service metadata.
- Ownership confidence and explicit quarantine for ambiguous assets.
- A prioritized list of distinct applications rather than a raw count of names.

#### Verification and False Positives

- Compare multiple random labels beneath the same parent to identify wildcard DNS; do not treat one random response as conclusive.
- Re-resolve candidates and preserve TTLs; distinguish NXDOMAIN, NODATA, SERVFAIL, and transient failures.
- Compare HTTP/TLS behavior with random-host and random-path controls to filter parked domains, CDN defaults, and SPA/soft-404 responses.
- Treat certificate SANs, historical DNS, shared IPs, provider CNAMEs, and name similarity as leads rather than ownership proof.
- Keep ambiguous, third-party, and out-of-scope candidates out of active inventories until attribution and scope are independently established.

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



#### References

- https://github.com/projectdiscovery/subfinder
- https://github.com/owasp-amass/amass
- https://github.com/projectdiscovery/dnsx
- https://certificate.transparency.dev/
- https://github.com/uphiago/recon-skills/blob/main/recon/subdomain-enumeration/SKILL.md
- https://owasp.org/www-project-web-security-testing-guide/
- https://www.rfc-editor.org/rfc/rfc1034

## 03. ASN and infrastructure mapping


### Chapter profile

**Purpose:** Map an organization's attributable IP infrastructure through ASN, CIDR, reverse DNS, sibling domains, and service metadata.

**Prerequisites:** A confirmed organization domain or attributable IP

**Technology:** `DNS`, `BGP`, `WHOIS`, `Linux`

**Coverage tags:** `recon`, `asn`, `cidr`, `dns`, `infrastructure`, `asset-inventory`

**Conditional handoffs only when independently observed:** `attack-subdomain-takeover` for a first-party CNAME to an orphaned provider resource; `attack-host-header` for attributable web-host routing evidence; `attack-minio-s3` for a first-party object-storage endpoint.

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

#### Output contract

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

#### Attribution and scope gate

Use this chapter to establish whether infrastructure is related to the organization, not to validate vulnerabilities. Continue materially distinct passive attribution checks while they can change the ownership conclusion; deduplicate repeated sources and equivalent observations. Stop when attribution is resolved, relevant sources are exhausted, a prerequisite is unavailable, or scope/safety requires stopping. ASN membership alone never authorizes active scanning.

##### Evidence-driven attribution order

1. Anchor discovery to verified organization names, registered entities, known domains, and current RIR/ASN evidence; a matching company string or IP hostname is not sufficient ownership proof.
2. Collect passive ASN, prefix, BGP, reverse-DNS, certificate, and provider metadata first; preserve source URLs and observation timestamps for each candidate.
3. Normalize prefixes and hostnames, deduplicate shared CDN/cloud edges, and separate directly registered infrastructure from reseller, SaaS, shared hosting, and third-party service providers.
4. Keep candidate prefixes passive unless the written scope explicitly includes the exact network range and the requested network-discovery method. Do not sweep every IP in an ASN or infer permission from routing/WHOIS ownership.
5. Return candidate prefixes with attribution confidence, evidence provenance, explicit exclusions, and narrow next steps. Send confirmed organization-owned web assets to the relevant recon chapter; do not claim a vulnerability.

##### Attribution outcomes

- **Corroborated first-party:** current first-party ownership evidence plus an independent technical or corporate relationship.
- **Strong candidate:** multiple independent indicators exist, but current ownership or scope is not yet established.
- **Shared provider / third party:** evidence indicates a CDN, cloud, reseller, SaaS, or multi-tenant service; keep it separate from first-party assets.
- **Historical / unresolved:** stale, indirect, or conflicting evidence; retain as a passive lead only.
- **Unrelated / refuted:** reliable evidence identifies a different organization or service owner.

These are asset-attribution outcomes, not vulnerability verdicts. Vulnerability validation belongs to the authorized specialist lifecycle.

##### Stop and handoff

Stop on scope ambiguity, unexpected user data, service degradation, secret exposure, or prohibited behavior. Return the exact relationship, source/time, attribution class, confidence, explicit scope decision, exclusions, and the next evidence needed. Start a chained skill only when its trigger has been independently observed.


#### References

- Source merged: [uphiago/recon-skills — recon/asn-infrastructure-mapping/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/asn-infrastructure-mapping/SKILL.md)
- [RIPE NCC — IP and ASN resources](https://www.ripe.net/)
- [BGP.tools](https://bgp.tools/)
- [RFC 9082 — RDAP Query Format](https://www.rfc-editor.org/rfc/rfc9082)
- https://github.com/projectdiscovery/asnmap
- https://docs.ripe.net/
- https://stat.ripe.net/docs/
- https://owasp.org/www-project-web-security-testing-guide/

IP exposure assessment


### Chapter profile

**Purpose:** Assess whether a web origin is directly reachable behind a CDN or reverse proxy and whether origin exposure changes the security boundary.

**Prerequisites:** A confirmed domain and evidence of CDN/reverse-proxy use

**Technology:** `DNS`, `HTTP`, `TLS`, `CDN`

**Coverage tags:** `recon`, `origin-ip`, `CDN`, `reverse-proxy`, `DNS`

**Conditional handoffs only when independently observed:** `attack-host-header` when the origin/Host authority changes application routing or trust decisions; `attack-cache-poison` only when a separate cache-key or cache-trust-boundary signal exists.

**Potential significance:** an attributable origin may expose a control difference from the normal edge. This chapter records a candidate differential; it does not confirm a bypass or finding.

**Legacy source:** `recon-origin-ip-discovery` v"1.0.0"; credited to cyberstrike-official.

#### Objective

Determine whether a candidate origin is attributable to the application and directly reachable. Record any observable difference from the normal edge as a lead for separately authorized validation; discovering an IP alone is not a vulnerability.

#### Testing Methodology

##### 1. Establish the edge baseline

Resolve A/AAAA/CNAME records, record certificate and HTTP behavior, and identify likely CDN or reverse-proxy indicators. Capture a normal request's response headers, redirects, and application marker. Separate shared edge addresses from candidate origins.

##### 2. Collect passive origin candidates

Correlate historical DNS, certificate transparency, organization-owned DNS records, first-party deployment/configuration references, observed redirects, public service metadata, passive scan results, favicon fingerprints, and attributable ASN/IP information. Analytics identifiers may be used only as weak search pivots when already observed in first-party content; shared IDs and favicon matches are not ownership proof. Treat old DNS records, mail servers, and unrelated addresses in a shared prefix as candidates until independently corroborated.

##### 3. Confirm candidate identity without bypass assumptions

Only when the exact candidate address and method are explicitly in scope, make a low-volume, benign request with the expected TLS SNI and HTTP Host. Compare certificate, redirect, and stable application marker with the edge baseline. Do not use the candidate to bypass access controls or treat a TLS mismatch/default virtual-host page as proof of origin identity.

##### 4. Compare security controls

If policy permits a read-only comparison, preserve the same benign request semantics and the same owner-provided test identity on both paths. Record differences in authentication response, routing, cache directives, or service behavior as candidate signals only. Do not attempt to evade a WAF, send exploit payloads, or use high-volume requests.

##### 5. Assess practical impact

A potential issue exists only when evidence suggests that a material control or unintended service exposure differs at the origin. Record the exact differential and hand it to the relevant specialist for independent validation. If the origin is intentionally public and appears to enforce the same controls, retain it as inventory context only.

#### Security significance and handoff triggers

- A candidate origin must be attributable to the same application, not merely the same cloud provider.
- An observed edge/origin difference is a lead for a specialist; this Recon chapter does not confirm a security-control bypass.
- An IP address, historical DNS record, different certificate, or default virtual-host page alone is not a vulnerability.

#### Output contract
Return each origin candidate with its source, freshness, ownership confidence, scope decision, and reachability status. Where comparison is permitted, preserve paired edge/origin request and response references with the same path, method, Host, TLS SNI, identity, and relevant headers. Classify the result as inventory-only, control-difference verified, blocked, or inconclusive; state the exact control and observed difference.

#### Evidence Requirements

- DNS/passive-source provenance and timestamp.
- Sanitized edge and origin request/response pairs, including Host and SNI context.
- Exact observed difference, paired request context, and the specialist validation still required; do not claim impact from the recon comparison alone.
- Redact tokens and private application data.

#### Origin Attribution Matrix

| Signal | Interpretation | Required corroboration |
|---|---|---|
| Historical DNS A record | Candidate historical host | Same app marker or certificate identity |
| Certificate SAN | Hostnames share certificate | Verify current application response |
| Direct IP returns app | Possible origin or shared host | Preserve SNI/Host and compare content |
| Edge/origin response differs | Possible control or routing differential | Preserve the paired benign response; a specialist independently validates any control-boundary claim under separate authorization |
| Different server banner | Infrastructure clue | No impact unless a security boundary is bypassed |
| Origin responds on extra port | Additional service candidate | Confirm ownership and service sensitivity |

#### Verification and False Positives

- Account for DNS changes, CDN migration, shared hosting, and anycast addresses.
- Preserve Host and TLS SNI; otherwise the server may serve a default site.
- Compare final response semantics, not status codes alone.
- Do not scan broad cloud address ranges to find origins.
- Treat exposed origin IPs as informational unless direct access changes security posture.




#### References

- Source merged: [uphiago/recon-skills — recon/origin-ip-discovery/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/origin-ip-discovery/SKILL.md)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [RFC 6066: TLS Server Name Indication](https://www.rfc-editor.org/rfc/rfc6066)
- https://docs.projectdiscovery.io/
- https://docs.securitytrails.com/
- https://docs.censys.com/
- https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/
- https://owasp.org/www-project-web-security-testing-guide/

#### Objective

Identify reachable services and distinguish expected public application surfaces from accidental management, development, or protocol exposure. Port discovery creates an inventory; a listening port or banner alone is not a vulnerability.

#### Methodology

##### 1. Establish host attribution and scan boundaries

For each candidate, retain the exact DNS/resolver result, attribution source, scope basis, ownership class, and service-discovery confidence. Use only confirmed target addresses and explicitly authorized ports; document rate/concurrency limits and scan vantage point. Exclude shared-provider ranges unless explicitly listed, and prefer DNS-derived/first-party confirmed IPs over broad ASN expansion.

##### 2. Start with low-impact TCP discovery

Begin with common service ports or a program-approved port list. Use conservative concurrency and timeouts. Expand only when the first pass indicates a relevant service or the engagement expressly allows a broader sweep. UDP checks should be targeted because they are less reliable and can be more intrusive.

##### 3. Fingerprint services with protocol-aware probes

For each open port, record TCP state, service response, TLS certificate/SAN, ALPN, HTTP status/title, redirect destination, and server metadata. Use a protocol-aware client rather than assuming every high port is HTTP. A banner may be masked, stale, or supplied by a proxy.

##### 4. Identify sensitive service classes

Prioritize exposed admin consoles, databases, caches, message brokers, CI/CD systems, object storage, debug endpoints, container/orchestration APIs, and alternate application ports. Confirm whether authentication is required and whether the service is intentionally public. Avoid login attempts with guessed or discovered credentials.

##### 5. Correlate services with known applications

Map port → protocol → certificate/hostname → application → owner. Compare alternate ports against the canonical web app and inspect public JavaScript/configuration for backend references. Use the dedicated API, cloud, CMS, and origin skills for service-specific validation.

##### 6. Prepare a specialist handoff

For a suspected issue, preserve one benign handshake or read-only response and record the exact access-control question, expected policy, and owner-provided test identity required for separate validation. Do not verify privilege boundaries, enumerate data, alter configuration, or run exploit checks from this Recon procedure.

#### Output contract

- A deduplicated service inventory with timestamped evidence.
- Protocol and application fingerprints with confidence notes.
- A shortlist of exposed services that warrant a focused security review.
- A clear separation between an open port, a misconfiguration, and a demonstrated vulnerability.

#### Evidence Requirements

- Confirmed host attribution and scan boundary.
- Port/protocol/state, timestamp, and minimal sanitized service response.
- Service identity evidence and reason the exposure is unexpected.
- For a candidate requiring security validation, record the exact access-control question and minimum additional evidence required; a banner or open port is not proof.

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



#### References

- Source merged: [uphiago/recon-skills — recon/port-service-discovery/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/port-service-discovery/SKILL.md)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- https://github.com/projectdiscovery/naabu
- https://github.com/projectdiscovery/tlsx
- https://github.com/projectdiscovery/httpx
- https://nmap.org/download.html
- https://nmap.org/book/man.html
- https://owasp.org/www-project-web-security-testing-guide/

#### Objective

Identify hostnames routed by a shared web server or reverse proxy, then classify whether each host belongs to the target organization and is an authorized asset. A different response to a Host header is a discovery signal, not proof of a vulnerability.

#### Methodology

##### 1. Establish response fingerprints

Capture a baseline for the canonical hostname, a known-invalid Host value, and a random nonexistent path. Keep IP, TLS SNI, path, and request headers constant while varying only the authority/Host dimension. Record status, redirect, title, body hash/length, certificate names, server headers, cookies, and a stable application marker. This identifies default virtual hosts, wildcard DNS, and soft-404 behavior.

##### 2. Generate candidate hostnames

Use passive DNS, certificate transparency, organization-owned documentation, observed links, DNS records, and a restrained wordlist derived from application roles (api, auth, staging, admin, files, assets). Normalize names and deduplicate candidates. Avoid indiscriminate brute force where the engagement prohibits it.

##### 3. Resolve and classify candidates

Resolve A/AAAA/CNAME, note wildcard responses, and compare TLS SAN/certificate behavior. A resolved hostname may be parked, delegated to a third party, or point to a shared platform; confirm application identity and ownership before active testing.

##### 4. Compare HTTP routing

For confirmed IPs, request each candidate hostname with correct TLS SNI where applicable. Compare application marker, redirects, cookies, and route behavior. If a Host header changes the destination or generates absolute URLs, use the dedicated host-header skill to test trust boundaries.

##### 5. Prioritize unusual hosts

Review staging, preview, legacy, API, upload, tenant, and administrative hosts for weaker authentication or outdated deployments. Apply the same ownership and permission checks as any other asset. Do not infer that a hostname is in scope solely because its name matches the brand.

#### Output contract

- A deduplicated candidate hostname inventory.
- DNS/TLS/HTTP fingerprints and wildcard/default-host classifications.
- Ownership confidence and notes on third-party hosting.
- A prioritized list of confirmed applications for follow-up testing.

#### Evidence Requirements

- Candidate source and resolution timestamp.
- Baseline versus candidate fingerprints, including the random-host control.
- Evidence tying the host to the organization.
- Any security impact must be validated by the relevant specialist under its own authorization; this chapter records host-routing evidence and the validation question only.

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




#### References

- Source merged: [uphiago/recon-skills — recon/vhost-enumeration/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/vhost-enumeration/SKILL.md)
- [RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)
- [RFC 6066: TLS Server Name Indication](https://www.rfc-editor.org/rfc/rfc6066)
- https://docs.projectdiscovery.io/tools/httpx/overview
- https://github.com/ffuf/ffuf
- https://owasp.org/www-project-web-security-testing-guide/
- https://portswigger.net/web-security/host-header

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

##### 5. Prepare the specialist handoff

Maintain separate confidence for CMS identity, component identity/version, deployment ownership, and advisory applicability. Map a corroborated component/version to a credible advisory and record the affected-version range, prerequisites, and evidence that the component/path is present. Do not run a proof-of-concept or exploit from this Recon chapter. A version match is a lead, not proof that the vulnerable code path is reachable or that the application is exploitable; the specialist must independently verify the affected code path.

#### Output contract

- CMS and framework fingerprint with confidence notes.
- A component inventory tied to observed evidence.
- Candidate advisories requiring applicability verification.
- A prioritized list of safe follow-up tests.

#### Evidence Requirements

- Response excerpts or asset paths that establish the fingerprint.
- Version evidence and a corroborating signal.
- Advisory identifier, exact affected-version range, and evidence that the affected component/path is present.
- State explicitly that applicability/impact validation remains pending with the relevant specialist; redact secrets and user data.

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




#### References

- Source merged: [uphiago/recon-skills — recon/cms-detection/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/cms-detection/SKILL.md)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST National Vulnerability Database](https://nvd.nist.gov/)
- https://github.com/urbanadventurer/WhatWeb
- https://wpscan.com/
- https://github.com/RetireJS/retire.js
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/vavkamil/awesome-bugbounty-tools

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

Use a headless browser or screenshot tool with a consistent viewport, wait condition, timeout, and auth context. Record URL, final URL, title, status, screenshot path and content hash, timestamp, and any TLS/certificate errors. Avoid submitting forms or triggering state changes during automated capture.

##### 3. Cluster applications

Group pages using normalized titles, visual similarity, favicon hashes, shared asset paths, login-provider identity, and DOM landmarks. Dynamic timestamps, personalized banners, A/B tests, and cookie notices can skew visual hashes; retain multiple signals rather than trusting one metric.

##### 4. Prioritize for manual review

Prioritize unique login portals, tenant selection screens, admin consoles, file management, billing, API documentation, legacy interfaces, and non-production-looking pages. Verify ownership and security relevance before deeper testing.

##### 5. Convert visual leads into testable hypotheses

For each cluster, record observed roles, major workflows, visible API routes, framework clues, and potential trust boundaries. Reproduce the observation in a browser or proxy before assigning a vulnerability label.

#### Output contract

- A visual catalog of confirmed web applications.
- Clusters that reduce duplicate manual review.
- A prioritized queue of unique workflows and authentication surfaces.
- Reproducible screenshot metadata linked to each URL.

#### Evidence Requirements

- URL and final redirect destination.
- Timestamped screenshot plus status/title metadata.
- Cluster rationale and confidence.
- Separate technical evidence for any claimed vulnerability.

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

#### References

- Source merged: [uphiago/recon-skills — recon/visual-recon/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/visual-recon/SKILL.md)
- [Playwright documentation](https://playwright.dev/docs/intro)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)


#### Additional validation refinements

##### Visual clusters as testable hypotheses
Capture consistent screenshots at the same viewport and auth context, then cluster only as a navigation aid—not as proof that two apps share code or ownership. Retain URL, screenshot hash/path, title, favicon/theme fingerprint, response status, and comparison rationale. Convert each visual anomaly into one question (different tenant, admin console, old version, hidden workflow, unexpected login state) and verify with normal HTTP evidence. Avoid screenshotting personal information and redact account names/IDs. Route admin-specific paths to BFLA, tenant/object references to IDOR, and visually different auth flows to the authentication specialist only after the request behavior corroborates the visual clue.




#### References

- https://github.com/sensepost/gowitness
- https://github.com/michenriksen/aquatone
- https://github.com/vavkamil/awesome-bugbounty-tools

#### Objective

Discover public GitLab projects and artifacts associated with an organization, then identify source/configuration exposure that materially affects security. Public project visibility is not inherently a vulnerability; attribution and data sensitivity determine relevance.

#### Methodology

##### 1. Establish the namespace

Start with the organization's official GitLab group, known project links, developer documentation, and confirmed domains. Search public namespaces using domain and organization identifiers, but treat name matches as candidates until ownership is corroborated.

##### 2. Inventory public projects and artifacts

Review project descriptions, default branches, tags/releases, package registries, container image metadata, wiki pages, issue attachments, snippets, and CI configuration. Record project URL, visibility, last activity, owner/group, and relevance. Use unauthenticated public interfaces or approved API access only.

##### 3. Inspect high-value files and history

Prioritize deployment manifests, CI variables references, Dockerfiles, infrastructure-as-code, environment templates, configuration files, backup artifacts, and scripts that reveal trust boundaries. Review commit history where public and relevant; record repository URL, commit hash, path/line, observed time, and whether the content is current, deleted, forked, or generated. Avoid cloning huge unrelated repositories or collecting private user data.

##### 4. Analyze CI/CD trust boundaries

Look for untrusted merge-request code running with privileged runners, unsafe artifact exposure, overly broad token permissions, insecure deployment rules, and secrets printed in job logs. Configuration patterns are leads: establish whether the affected workflow is reachable and whether a real permission boundary is crossed.

##### 5. Classify secret-like strings safely

Use local secret-scanning tools on the minimum relevant repository content. Treat matches as unverified candidates; redact immediately and do not authenticate to third-party services with discovered material. Determine likely type and location from context, and ask the owner to verify/revoke through their normal process.

##### 6. Prepare a specialist handoff

Record the public asset, ownership evidence, affected file/commit/artifact, and the suspected non-public information or CI/CD trust boundary. For a CI/CD concern, describe the observed trust relationship and the permission question without triggering a deployment, modifying pipelines, or claiming a privilege boundary was crossed.

#### Security significance and handoff triggers

- An attributable public repository/artifact contains material that appears non-public, or its CI/CD configuration raises a concrete trust-boundary question.
- Public visibility alone, a repository name, public README, intentionally published SDK, client identifier, or stale placeholder secret is not a vulnerability.
- This chapter records read-only evidence and a candidate; the relevant source-leak/CI specialist must validate the boundary and impact independently.

#### Output contract
Persist a read-only inventory of attributable GitLab groups/projects, project identifiers, public visibility, relevant files/commits, release or package artifacts, and CI configuration references. Record source URL, observed time, project ownership confidence, and last-seen revision. For secret-shaped material, retain only type, location, detector, and a redacted fingerprint—never the value. Link each candidate to the canonical asset/evidence record and a concrete safe next step.

#### Evidence Requirements

- Canonical project/group URL, public visibility evidence, and ownership rationale.
- Exact file path/commit or artifact location and a minimal redacted excerpt.
- For CI/CD, the relevant trust rule and resulting permission boundary.
- Secret values and private personal data must not be copied into the report; do not test a candidate secret.

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


#### References

- Source merged: [uphiago/recon-skills — recon/gitlab-public-recon/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/gitlab-public-recon/SKILL.md)
- [GitLab CI/CD Security](https://docs.gitlab.com/ci/security/)
- [GitLab REST API](https://docs.gitlab.com/api/)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)


#### Additional validation refinements

##### Repository attribution and secret-safe handling
Confirm namespace/organization attribution and public visibility before pivoting through group projects, forks, issue attachments, packages, snippets, build artifacts, and commit history. Preserve repository URL, commit hash, path/line, observed time, and whether the content is current, deleted, forked, or generated. Secret-like matches must be recorded as type plus redacted fingerprint; do not test or reuse credentials or access projects beyond what is public and authorized. Distinguish public code disclosure from an exploitable credential or CI trust boundary. Route workflow/runner problems to CI/CD review, first-party JavaScript to JS analysis, and secret candidates to evidence-safe triage without invoking them.




#### References

- https://github.com/gitleaks/gitleaks
- https://docs.gitlab.com/cli/
- https://git-scm.com/docs
- https://github.com/vavkamil/awesome-bugbounty-tools
- Source merged: [uphiago/recon-skills — recon/email-security/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/email-security/SKILL.md)
- [RFC 7208 — SPF](https://www.rfc-editor.org/rfc/rfc7208)
- [RFC 6376 — DKIM](https://www.rfc-editor.org/rfc/rfc6376)
- [RFC 7489 — DMARC](https://www.rfc-editor.org/rfc/rfc7489)
- [RFC 8461 — MTA-STS](https://www.rfc-editor.org/rfc/rfc8461)
- [RFC 8460 — TLS Reporting](https://www.rfc-editor.org/rfc/rfc8460)

#### Additional validation refinements

##### Mail-domain evidence and impact boundary
For each sending domain/subdomain, map MX, SPF, DKIM selectors, DMARC policy/alignment, TLS reporting/MTA-STS where relevant, and vendor delegation. Preserve DNS observation time and distinguish no record, lookup failure, stale cache, and misconfiguration. A permissive SPF or DMARC policy is a configuration weakness, not proof of spoofing impact. If recipient-side validation is required, hand the test plan to the authorized mail specialist for a separately approved synthetic recipient/domain; this Recon chapter sends no test mail. Keep third-party SaaS sending sources separate from organizational ownership. Route exposed webmail/Autodiscover to the mail-product review and identity-federation signals to OAuth/SAML only when the actual flow is observed.


#### Additional references

- https://github.com/drwetter/testssl.sh
- https://github.com/projectdiscovery/tlsx
- https://www.rfc-editor.org/
- https://github.com/vavkamil/awesome-bugbounty-tools

---

## 11. Exposed error-log analysis


### Chapter profile

**Purpose:** Discover exposed application error logs and evaluate disclosure of internal paths, stack traces, queries, and secret-like material with minimal evidence.

**Prerequisites:** A confirmed in-scope web application

**Technology:** `HTTP`, `PHP`, `WordPress`, `Linux`

**Coverage tags:** `information-disclosure`, `error-logs`, `debug`, `secrets-hygiene`, `PHP`

**Related security workflows:** `attack-information-disclosure`, `attack-source-leak`, `attack-phpinfo-exposure`, `attack-metrics-exposure`

**Relevant weakness classes:** `CWE-200`, `CWE-532`

**Specialist validation threshold:** an exposed log may contain secret-like material or sensitive user data with material impact. This chapter records only bounded, redacted evidence; a specialist independently assesses impact without using the secret.

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

Classify candidate disclosures into internal filesystem paths and deployment layout; stack traces, framework versions, and component names; SQL statements or schema names; internal hostnames/IPs; email addresses and user identifiers; secret-like strings, tokens, cookies, database connection strings, or signing material; and user-submitted data accidentally logged. Immediately redact internal URLs, query values, personal data, cookies, tokens, and secret contents; preserve only the data category, location, and minimal redacted fingerprint.

Treat pattern matches as candidates only. Never test a discovered credential against a service; confirm validity through an owner-provided verification channel or metadata that does not expose or use the secret.

##### 5. Classify reachability and sensitivity

Record whether an unauthenticated request can retrieve the resource, whether it appears current, and which information categories are exposed. Treat paths, versions, stack traces, and secret-like patterns as candidate signals only. Do not test any secret or infer severity without separate authorized validation and impact review.

##### 6. Identify root cause

Check production debug settings, web-server deny rules, deployment packaging, log rotation and permissions, public static-file mappings, backup/sync jobs, and CMS plugin/theme behavior. Recommend removing logs from web roots and preventing future writes to publicly served locations.

#### Security significance and handoff triggers

- A real log/debug artifact appears retrievable outside its intended access boundary and contains non-public information.
- Describe the exact data category and sensitivity; do not infer impact from the file name, byte size, or pattern match alone.
- A secret must never be copied into notes/reports or tested; retain only the secret type, location, and minimal redacted fingerprint.
- A generic error page, empty log, public sample, or stale benign stack trace is not a confirmed finding. Route a meaningful exposure candidate to the information-disclosure specialist for independent triage.

#### Output contract
For each candidate, record the in-scope URL/resource, response/access context, timestamp, content classification, minimal redacted proof reference, random-path or equivalent control, exposure status, sensitivity category, and safe next action. Preserve only the minimum sanitized evidence needed to establish the access boundary; do not retain full logs, credentials, tokens, session IDs, or customer data.

#### Evidence Requirements

- URL, retrieval timestamp, response status/content type, and bounded byte range.
- Sanitized excerpt showing log structure and one representative disclosure.
- Random-path/soft-404 control.
- Secret values, personal data, cookies, tokens, and customer content must be redacted.
- Note whether the file is current and whether sensitive material was validated without using it.

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




#### References

- Source merged: [uphiago/recon-skills — recon/error-log-mining/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/error-log-mining/SKILL.md)
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- https://owasp.org/www-project-web-security-testing-guide/
- https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- https://github.com/vavkamil/awesome-bugbounty-tools

