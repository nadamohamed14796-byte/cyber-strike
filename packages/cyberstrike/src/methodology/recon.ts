/**
 * Phase-specialized coverage guidance appended to the canonical `/recon` prompt.
 *
 * The main command owns phase order, scope, checkpointing, persistence, resumption,
 * artifact layout, and reporting. This module contains only the extra coverage matrix,
 * so the general workflow is not duplicated or allowed to drift across prompts.
 */

export const RECON_SPECIALIZED_COVERAGE_PROMPT = `SPECIALIZED RECON COVERAGE — APPLY ONLY WHEN RELEVANT

Use this supplement only for coverage dimensions not already addressed by the canonical /recon orchestrator. The orchestrator remains the single source of truth for authorization, phase order, checkpoint actions, persistence, resume, canonical outputs, and completion reporting.

RECON COVERAGE MATRIX — APPLY THESE SUBWORKFLOWS AND LOAD RELEVANT SPECIALIZED SKILLS

The canonical /recon orchestrator owns phase order and completion criteria. Load a specialist skill only when the observed asset type or evidence makes its detailed procedure useful; do not load the general recon-methodology skill merely to repeat the orchestrator. Avoid duplicate/unrelated loads, and record each applicable, not-applicable, unavailable, or blocked coverage area in the phase summary.

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
- Coverage accounting: each source/subworkflow has status (completed, unavailable, blocked, failed, or not applicable), evidence/artifact path, counts where meaningful, and a short explanation. Never call recon exhaustive just because one tool returned results; report coverage gaps explicitly.`
