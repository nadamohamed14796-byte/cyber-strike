---
name: recon-methodology
description: "Plan and execute evidence-led, scope-locked reconnaissance that produces a deduplicated, prioritized testing queue"
version: "1.2.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [recon, enumeration, osint, subdomain, asset-inventory, scope]
tech_stack: [dns, http, tls, javascript, api, cloud]
prerequisites:
  - "Written authorization, scope rules, exclusions, and permitted testing intensity"
chains_with: [attack-subdomain-takeover, attack-idor-automation, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/web2-recon/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/meta/recon-playbook/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/meta/pentest-playbook/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/recon/subdomain-enumeration/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/recon/web-enumeration/SKILL.md"
---

# Reconnaissance Methodology

## Mission

Turn an authorized target list into a scope-checked, deduplicated inventory and prioritized queue of hypotheses. Recon observations are leads, not findings. The goal is to identify the smallest next test likely to establish a meaningful security property while minimizing duplicate work and operational risk.

## 1. Engagement contract

Before any active request, record:
- exact assets, wildcard rules, exclusions, third-party services, and program links;
- allowed recon methods, request rate, scan windows, and prohibited techniques;
- authentication prerequisites and test accounts;
- workspace and evidence-retention location;
- stop conditions for instability, rate limits, unexpected sensitive data, or scope ambiguity.

Public reachability does not imply authorization. Every discovered hostname, IP, API, repository, or third-party service must pass the scope resolver before active testing.

## 2. Recon pipeline

### A. Normalize and lock scope

Canonicalize hostnames, schemes, ports, trailing dots, IDNs, wildcard entries, and exclusions. Preserve the original candidate and the normalization decision. Resolve wildcard rules conservatively; do not treat an entire shared CDN or cloud provider as in scope. Keep scope decisions explicit: in-scope, out-of-scope, needs-owner-confirmation, or passive-only.

### B. Passive discovery first

Use program-provided asset lists, certificate transparency, public DNS history, public code search, archived URLs, public repositories, and other permitted passive sources. Preserve provenance, timestamp, and source reliability. Do not scrape private systems, use leaked credentials, or infer permission from exposed data.

### C. DNS and infrastructure mapping

Resolve candidates and distinguish confirmed records, aliases, wildcard DNS, parked domains, unresolved names, and stale records. Keep CNAME chains and provider fingerprints. A dangling-looking record or cloud-provider fingerprint is only a lead; verify ownership and current scope before any takeover-related check. DNS resolution is not proof that a hostname is owned or in scope.

### D. HTTP and service validation

For in-scope hosts, record status, title, redirect chain, TLS certificate, content type, stable response fingerprints, and authentication behavior. Use bounded timeouts, conservative concurrency, and a documented request budget. Avoid broad port scans or content brute force unless explicitly permitted. Do not follow redirects to a different host without rechecking scope.

### E. Web and API enumeration

Collect URLs from permitted crawling, application traffic, JavaScript bundles, source maps, API documentation, robots/sitemap files, and known application routes. Normalize and deduplicate while retaining parameter names, methods, auth context, source, and discovery time. Separate public routes from authenticated routes, and read-only operations from writes/destructive actions.

For JavaScript assets, retain the asset URL and hash, source-map availability, extracted endpoint/function references, and the evidence connecting each reference to an observed request. Treat strings and comments as leads until runtime traffic or documentation supports them.

### F. Technology and ownership signals

Record framework, CDN, cloud provider, CMS, API style, authentication mechanism, and likely tenant boundaries only when evidence supports the inference. Keep confidence and evidence for each fingerprint; do not convert a banner, version string, or scanner guess into a vulnerability claim.

### G. Authentication-aware coverage

Track which endpoints were tested anonymously and with each authorized role. Record login walls, registration requirements, MFA/OTP dependencies, session expiry, and routes unavailable because the test account lacks permission. Do not label an endpoint untested as safe merely because authentication was unavailable; mark it blocked and retain the dependency.

### H. Queue construction

For each candidate, store:
- canonical target and scope decision;
- source/provenance and first/last-seen timestamps;
- observation and confidence;
- explicit security hypothesis and expected policy;
- required account/role and prerequisites;
- bounded next validation step and stop condition;
- priority, deduplication fingerprint, and status.

Prioritize trust boundaries, newly discovered assets, exposed APIs, cross-tenant behavior, sensitive state transitions, and changes from the previous recon wave. Avoid ranking solely by number of URLs or scanner severity.

## 3. Delta analysis and resumability

Compare each recon run with the prior snapshot. Highlight new hosts, changed technologies, newly exposed endpoints, changed authentication behavior, new JavaScript assets, and DNS/provider changes. Reuse stable results where their TTL and source permit it. Do not repeat expensive scans if the delta does not justify them.

Persist run state and per-target progress so an interrupted scan can resume from pending work rather than restart completed discovery. Use stable IDs or fingerprints for deduplication; keep status transitions explicit and never silently reset a completed or rejected item. When a source requires login, record the blocked state and resume after authorized credentials are configured instead of treating the page as empty.

## 4. Evidence and data hygiene

Keep raw outputs outside the source repository unless explicitly required. Store redacted evidence references, not live cookies, bearer tokens, API keys, recovery links, personal data, or secret-bearing environment values. Record the minimum evidence needed to reproduce an observation. Ensure findings can be traced back to asset, request, response, account context, and discovery source.

## 5. Stop conditions

Stop when a target is out of scope, rate-limited, unstable, serving unexpected private data, or ownership is uncertain. Stop active testing if redirects cross scope, credentials appear in an unexpected destination, or a test triggers real-world side effects. Do not broaden testing after the security property is already demonstrated.

## 6. Quality gates

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

## Output contract

Return normalized asset and endpoint inventories, scope decisions, provenance, delta summary, authentication coverage, deduplicated prioritized hypotheses, blockers, and next-step recommendations. Keep discovery facts separate from security conclusions.

## Targeted quality-loop enrichment (2026-10-19)

### Delta-driven prioritization and handoff
Every recon wave should diff hosts, DNS/CNAME/provider changes, TLS/HTTP fingerprints, new API paths, methods/parameters, JavaScript hashes, authentication state, and third-party destinations against the previous snapshot. Reuse observations only while their source freshness/TTL remains credible; revalidate changes and stale evidence rather than repeating a whole scan. Keep asset ownership confidence separate from vulnerability confidence. Each queue item must state the security property, expected policy, prerequisites, baseline needed, exact next observation, and stopping condition. A candidate with missing credentials stays blocked, not safe. Hand off only signal-matched cases to specialist skills and preserve the source/provenance for later audit.

## Agent-executable CLI tooling, resources, and helper scripts

Use agent-executable CLI tools and local scripts. Browser interfaces, browser extensions, and interactive intercepting proxies are not required dependencies. Verify tool availability/version and official installation guidance before use; inspect request impact and permissions before active testing.

### Recommended tools
- jq/Python — machine-readable phase manifests
- subfinder, dnsx, httpx, katana — only for the corresponding phase and target permissions
- nuclei — selected templates after reviewing requests and impact
- git diff — audit artifact changes

### Resources
- https://github.com/vavkamil/awesome-bugbounty-tools
- https://owasp.org/www-project-web-security-testing-guide/
- https://owasp.org/API-Security/
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids; confirm maintenance, license, provenance, and exact CLI behavior from official sources.

### Helper-script contract
Create a phase runner manifest mapping each phase to prerequisites, primary tool, optional alternatives, expected artifacts, validation command, failure states, and downstream consumers. Do not treat missing tooling as a clean scan.

Preserve raw outputs and normalize a separate copy. Helpers should retain provenance, timestamps, tool/version, errors, confidence, and output paths; redact secrets; support JSON/JSONL where useful; and include local fixtures.

### Handoff
Report commands actually executed, tool versions, input/output artifact references, deduplication counts, errors/blocked sources, confidence, limitations, and the next skill.
