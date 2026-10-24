/**
 * Phase-specialized coverage guidance appended to the canonical `/recon` prompt.
 *
 * The main command owns phase order, scope, checkpointing, persistence, resumption,
 * artifact layout, and reporting. This module contains only the extra coverage matrix,
 * so the general workflow is not duplicated or allowed to drift across prompts.
 */

export const RECON_SPECIALIZED_COVERAGE_PROMPT = `SPECIALIZED RECON COVERAGE — USE ONLY TO CLOSE RELEVANT GAPS

The canonical /recon orchestrator remains the single source of truth for scope, phase order, checkpoint state, persistence, resumption, canonical outputs, and reporting. This supplement adds only missing coverage. Load specialist skills when the asset or evidence warrants them; do not reload general methodology merely to repeat the workflow. Record each applicable area as completed, not applicable, unavailable, blocked, or failed, with evidence paths and meaningful counts.

- **DNS and subdomains:** Combine permitted passive datasets, certificate transparency, relevant DNS records, official documentation, and historical sources. Use active wordlists only when allowed. Normalize hostnames/IDNs; retain source timestamps, wildcard evidence, and CNAME chains. A dangling indicator is not a confirmed takeover.
- **Infrastructure, ASN, and origin leads:** Correlate observed IPs with ASN/provider data, related ranges, historical DNS, and certificates. Treat results as leads. Never bypass a CDN/WAF or probe a discovered IP/service unless explicitly authorized; save the evidence and scope rationale.
- **Ports and services:** Check only permitted addresses/ports and rates. Preserve service/banner/TLS evidence and hostname-to-IP-to-port relationships. A shared IP does not authorize every service or virtual host.
- **Virtual hosts and topology:** Derive candidate names from certificates, redirects, headers, application links, and permitted vhost discovery. Apply include/exclude rules before requests; a common IP, SAN, or redirect does not prove ownership or scope.
- **Technology and application profiling:** Correlate framework/CMS/library versions, API style, auth provider, CDN/WAF, and deployment signals. Record confidence; fingerprints and banners are observations, not vulnerabilities.
- **Web content and routes:** Include robots.txt, nested sitemaps, links/forms, OpenAPI/Swagger, GraphQL references, well-known files, error pages, redirects, historical URLs, archived assets, and permitted content discovery at its appropriate checkpoint. Normalize into canonical inventories and retain raw output only when it adds evidence.
- **JavaScript/client-side surfaces:** Collect external/inline scripts, source maps, runtime chunks and lazy modules. Hash bodies and analyze each unique version once as inert text. Extract API bases, route templates, parameter names/locations, auth/session clues, feature flags, GraphQL/WebSocket references, and client-side sinks; retain evidence paths, extraction version, and confidence.
- **Visual reconnaissance:** When browser tooling is available and permitted, capture title, screenshots, major routes, and visible login/registration/admin flows. Link captures to host/route evidence. Visual similarity alone does not prove ownership.
- **Exposure/configuration leads:** Where permitted, inspect public repository metadata, source maps, debug/status endpoints, directory listings, backups, verbose errors, cloud-storage references, headers, TLS, CORS, and public documentation. Record exact evidence; active verification still follows scope and phase controls.
- **Takeover/dangling DNS:** Record provider-specific CNAME/NS and stale-DNS signals as candidates. Confirm ownership and authorization before any takeover attempt. Never register resources, claim tenants, or modify third-party infrastructure.
- **Specialized asset types:** For explicitly in-scope mobile apps, binaries, repositories, cloud resources, or other non-web assets, retain a typed asset record with identifier, version/hash, origin, and permitted test surface. Do not force these into hostname records or infer web authorization.
- **Coverage accounting:** Track status, evidence path, counts where useful, and the reason for every relevant area. Do not call recon exhaustive because one tool returned results; report missing coverage and genuine blockers.`
