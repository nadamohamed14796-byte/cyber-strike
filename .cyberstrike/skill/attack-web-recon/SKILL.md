---
name: attack-web-recon
description: "Map an authorized web attack surface into a deduplicated, evidence-backed testing queue"
category: "recon"
version: "1.0.0"
author: "CyberStrike contributors; adapted with upstream attribution"
tags: [recon, subdomains, endpoints, javascript, api]
tech_stack: [dns, http, web, api]
prerequisites:
  - "Explicit authorization and in-scope asset boundaries"
  - "Approved tools, rate limits, and output location"
chains_with: [attack-bb-methodology, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/web2-recon/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
---

# Web Attack-Surface Reconnaissance

## 1. Objective

Produce a prioritized inventory of in-scope hosts, web apps, URLs, APIs, technologies, and trust boundaries. Recon outputs are leads, not vulnerabilities; each lead needs a scope check and focused validation.

## 2. Scope and safety gates

1. Resolve authorized root domains, wildcard rules, exclusions, and permitted scan intensity.
2. Keep third-party SaaS, shared hosting, CDNs, and unrelated tenants out unless explicitly included.
3. Start with passive sources. Run DNS, HTTP, crawling, port discovery, or content discovery only within policy.
4. Set request timeouts, concurrency, and rate limits. Never run broad scans against an unverified asset list.
5. Store outputs in the designated workspace. Do not commit target-specific data or credentials.

## 3. Pipeline

### Step 1 — Normalize scope
Create a canonical scope list. Normalize case, schemes, trailing dots, ports, wildcard rules, and exclusions. Keep source and reason for every candidate.

### Step 2 — Passive discovery
Use approved sources such as certificate transparency, DNS history, archives, public code search, and program-provided asset lists. Deduplicate hostnames while retaining provenance.

### Step 3 — DNS and host validation
Resolve candidate names in batches. Separate unresolved names, aliases, wildcard DNS, parked domains, and confirmed records. DNS resolution alone does not prove ownership or scope eligibility.

### Step 4 — HTTP probing
For eligible hosts, record status, title, redirects, content type, technology hints, TLS metadata, and response fingerprint. A status code or banner is not proof of a vulnerability.

### Step 5 — URL and API mapping
Combine in-scope crawl results, archives, app navigation, API specifications, permitted GraphQL schema information, JavaScript bundles, source maps, and mobile/API observations. Preserve method and content-type distinctions during deduplication.

#### JavaScript code review and request correlation
After `hackbrowser` has finished capturing relevant responses, invoke `correlate_javascript` with the already-authorized `target_url` before detailed endpoint testing. It reads captured JavaScript response bodies and existing files in the target workspace's `javascript/` directory; it does not download or execute scripts. Review its persisted attack-surface JSON and target notes for function candidates, URL templates, path/query/body parameters, header names, auth/cookie signals, secret-like candidates (fingerprint only), and role/feature hints.

Treat source-derived relationships as hypotheses. An absent token/cookie signal does not prove an endpoint is public, a role name does not prove server-side authorization, and a secret-like candidate does not authorize use. Prefer a captured baseline request; test one controlled mutation at a time with `http_replay` inside scope, then review the saved redacted observation and its manual-review flag. A response difference is a lead, not a vulnerability verdict.

### Step 6 — Focused enumeration
Only after validating scope and policy, use bounded directory or parameter discovery. Start with a small justified wordlist and increase coverage only when results warrant it.

### Step 7 — Prioritize
Rank routes by authentication context, identifiers/tenant references, sensitive workflows, input sinks, undocumented API versions, and file/state handling. Route only signal-matched candidates to specialist skills: object IDs to IDOR/BOLA, URL fetches to SSRF, user-controlled markup to XSS, OAuth flow anomalies to OAuth, and multi-step transactions to business-logic review.

## 4. Output contract

Record asset/URL, method, scope decision and source, discovery timestamp, response hints, auth context, parameters/object identifiers, confidence, deduplication key, and next check. Never persist cookies, bearer tokens, API keys, or unredacted personal data.

## 5. Verification

- Recheck ownership and scope before active requests.
- Confirm URLs belong to the target rather than analytics or third-party links.
- Distinguish wildcard DNS and catch-all hosting from real services.
- Check for soft-404s and login redirects before treating a route as live.
- Keep ambiguous assets out of automated active queues.

## 6. Pitfalls

- Treating every subdomain or CNAME as in scope.
- Confusing shared infrastructure with target-owned services.
- Assuming HTTP 200 means a route exists.
- Losing meaningful methods or parameters during deduplication.
- Treating technology detection as vulnerability confirmation.
- Running aggressive scans without policy approval.
- Treating a discovered secret as permission to use it.

## 7. CyberStrike integration contract

Verify actual scope resolution, inventory, HTTP probing, crawling, normalization, deduplication, evidence persistence, and skill-routing APIs before connecting automation. Do not reference hypothetical commands as implemented tools. The orchestrator remains responsible for scope enforcement.

## References

- Claude-BugHunter web recon: https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/web2-recon/SKILL.md
- Recon Skills: https://github.com/uphiago/recon-skills
- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/


## Targeted quality-loop enrichment (2026-10-19)

### Recon-to-hunt handoff contract
For every asset/endpoint, separate asset attribution confidence from security confidence. Preserve source, timestamp, normalization, DNS chain, HTTP fingerprint, first-party vs third-party attribution, authentication observation, method/parameters, and a canonical deduplication key. Delta each new recon run against the previous snapshot and enqueue only new or materially changed observations; never label a route vulnerable because it is live or appears in JavaScript. Use the following signal routes: object IDs/tenant hints → IDOR; new role-only routes → BFLA; URL-consuming features → SSRF; sensitive fields → API property authorization; host/cache differences → header/cache skills. correlate_javascript and http_replay are runtime calls only where registered; verify tool availability before claiming execution.
