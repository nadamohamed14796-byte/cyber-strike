---
name: recon-master
description: "Unified scope-aware reconnaissance playbook; automatically loaded after scope acceptance and before recon execution."
category: information-gathering
version: "2.0.0"
author: "CyberStrike contributors"
tags: [recon, reconnaissance, passive-recon, active-recon, osint, subdomain, dns, asn, cidr, origin-ip, vhost, ports, services, http, tls, crawling, endpoints, cms, gitlab, email-security, visual-recon, error-logs, asset-inventory, scope, tool-selection]
tech_stack: [dns, http, tls, tcp, javascript, api, cloud, browser, git, smtp]
prerequisites: ["Persisted authorization, scope rules, exclusions, and permitted testing intensity"]
chains_with: [community-tool-selection, attack-web-recon, attack-javascript-analysis, attack-shadow-api, attack-subdomain-takeover, attack-api-contract-testing]
---

# Recon Master

## Startup contract

Load this skill automatically immediately after scope is accepted and before any recon tool is invoked. This is the single orchestration entry point for the eleven dedicated recon skills incorporated below. Original specialist files remain unchanged for traceability; do not load all specialists blindly. Select relevant procedures from scope shape, observed evidence, technology, policy, and runtime capability.

On scope entry: read persisted program policy, exact assets, exclusions, wildcard semantics, allowed methods, rate limits, scan windows, and authentication constraints; initialize/resume the canonical workspace and recon_checkpoint; load this skill; load community-tool-selection and its TOOLING_CATALOG.md from the returned skill base directory; plan passive-first branches; execute applicable branches automatically; persist evidence incrementally; verify artifacts and report coverage, gaps, errors, and next steps. Ask only when authorization or a genuinely required input is missing.

## Scope-driven branch selection

- Single hostname/application: prioritize passive context, DNS/TLS/HTTP validation, crawl/URL collection, JS/API extraction, technology/CMS fingerprinting, and visual clustering. Do not run broad ASN/CIDR discovery without attribution need.
- Wildcard/root domain: enumerate subdomains from independent passive sources, resolve and de-wildcard, identify distinct applications, then selectively perform permitted active DNS/HTTP, vhost, and port/service checks.
- Large wildcard/multi-root: batch by root/source, checkpoint continuously, deduplicate incrementally, and process every eligible item without arbitrary caps. Broad coverage options require verified flag semantics and a documented request/rate budget.
- CIDR/IP: verify exact prefix boundaries and exclusions; use passive ASN/RDAP/BGP context; actively check only explicitly permitted IPs/services. ASN membership and shared cloud ranges never expand scope.
- Repository/source artifact: review only authorized public/source artifacts; inspect deployment/config/CI signals locally; redact secret-like matches immediately and never test discovered credentials.
- Mail domain: DNS-only SPF/DKIM/DMARC/MX/MTA-STS/TLS-RPT discovery by default; SMTP transport checks only if explicitly permitted.
- Mobile-only: route to mobile methodology; use this skill only for associated, explicitly in-scope web/API assets.

## Conditional specialist branches

Use ASN/CIDR mapping when a confirmed organization domain/IP makes attribution research useful; origin-IP discovery when an in-scope CDN/proxy-fronted app creates meaningful origin uncertainty; vhost enumeration when an authorized IP/origin and host-header context exist; port/service discovery only when policy permits; CMS detection only with first-party CMS indicators; visual recon only when screenshots/clustering add value; GitLab/public-repository review only with organization ownership evidence; email-security only for confirmed organization mail domains; error/log mining only on authorized public artifacts and ordinary responses. API/JS discoveries go to dedicated JS/API skills and the canonical endpoint inventory. None is mandatory for every target.

## Tool versions and flags

Use the single shared TOOLING_CATALOG.md under community-tool-selection; never create another tool catalog. Inspect live registered tool schemas and installed executables. Verify binary path, installed version, platform, and that version's own help output. Compare with official upstream releases/docs at execution time. Catalog versions are reference metadata, not proof the local binary is current. Record installed version and upstream version checked; do not silently upgrade pinned dependencies.

Choose flags from the installed version's help, never memory. Do not invent flags or combine conflicting options. Prefer machine-readable output, explicit input files, bounded timeout/rate/concurrency, and canonical workspace output. Broad all-source/all-resolver modes are appropriate only when documented, useful for the actual evidence gap, and within the scope/rate budget. Recursive modes require evidence of nested/delegated naming or a clear documented recursion benefit. Brute-force/wordlist modes require explicit active permission, a justified wordlist, and bounded rate. All-port/full-range modes require explicit IP/CIDR authorization and a reason; prefer top/common/evidence-derived ports for web-host scope. Technology-specific flags require a supporting fingerprint.

Urgent/time-limited: prioritize high-signal passive sources, live-host validation, JS/API endpoints, auth/admin/staging/legacy surfaces, and deltas; defer low-yield broad scans with a reason. Rate-limited/fragile: reduce concurrency, back off, reuse fresh evidence, and stop on repeated throttling or instability. Broad authorized scope: maximize independent passive-source coverage, checkpoint, then perform policy-approved active validation. Exhaust useful sources, not rate limits.

### HTTP method selection

GET is the default for passive/read-only pages, headers, robots.txt, sitemap, assets, API docs, and ordinary crawling. HEAD is a low-cost metadata option only when reliable; fall back to GET when unsupported or materially different. POST is not a generic recon substitute: use only when documented endpoint semantics or a normal workflow require it, the operation is read-only or uses a safe test fixture, and policy permits it. Preserve content type, body schema, auth context, and provenance. PUT/PATCH/DELETE and other state-changing methods are excluded from routine recon; use only in a separately requested authorized test with a controlled object and cleanup/stop plan. Keep method-specific endpoint variants; never merge GET and POST into one operation.

## Evidence and completion

Use recon_checkpoint and recon-methodology/RECON_PHASE_TOOL_MATRIX.md as authoritative state/artifact contracts. Normal flow: scope validation → workspace setup → passive asset discovery → DNS/ownership attribution → live host/permitted service checks → URL/crawl/history collection → parameter discovery → JS/source-map analysis → canonical endpoint/operation inventory → optional targeted fuzzing → evidence-linked handoff/report. Do not create duplicate phase manifests or endpoint inventories.

Each record retains canonical identity, scope decision, source/provenance, first/last seen, observation, confidence, method/auth context, deduplication key, tool/version, sanitized options, timestamp, status/exit code, errors, and artifact location. Separate asset confidence from security confidence: C0 unverified string; C1 one passive source; C2 independently corroborated attribution/service response; C3 specific configuration/exposure verified with a control; C4 impact reproduced within scope. C1/C2 are not findings.

Stop on out-of-scope redirects, uncertain ownership, unexpected sensitive/customer data, repeated rate limits, instability, lockouts, CAPTCHA/WAF signals, or side effects. Do not exploit, register, modify, publish, authenticate with leaked credentials, or run vulnerability templates during default recon. Nuclei belongs to a separately requested testing phase. Redact secrets and personal data immediately.

Completion requires applicable work to have run or have a justified non-applicable/blocked/skipped state and a verified canonical artifact. Report exact asset counts and state breakdowns, source coverage, method-specific endpoint counts, actual tools/versions/flags, errors, unresolved questions, evidence paths, and next specialist skill. Never silently truncate large outputs; report processed, pending, failed, skipped, not-applicable, blocked, and out-of-scope separately.

## Full source procedures — preserved verbatim

All substantive content from the original eleven specialist skills is included below. Original frontmatter is preserved as metadata; the original files remain untouched.