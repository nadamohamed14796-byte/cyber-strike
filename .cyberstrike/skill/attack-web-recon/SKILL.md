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

## Durable recon loop and phase gates

Treat recon as a resumable workflow, not a one-shot scan. Before each phase, load the target workspace's existing notes and artifacts, compare against the last completed run, and reuse valid results. Never create a second workspace root for the same canonical target.

| Phase | Required input | Completion evidence | Next phase gate |
|---|---|---|---|
| Scope/attribution | Program rules, root domains, exclusions, asset evidence | Canonical scope snapshot with provenance and unresolved cases | Active work only on resolved in-scope assets |
| Passive discovery | Scope snapshot and source list | Candidate hosts with source/time/confidence | DNS validation |
| DNS/alias | Candidate hosts | A/AAAA/CNAME/NS/TXT observations, wildcard and parked-domain notes | HTTP only for eligible hosts |
| HTTP/service | Eligible resolved hosts | Status/redirect/TLS/title/fingerprint with timestamps | Crawl/API mapping |
| URL/API | Live app, approved archives/specs, captured requests | Normalized method + route + content-type + parameter-shape inventory | JS correlation and focused review |
| JavaScript | Captured first-party assets and hashes | Candidate routes/sinks/auth hints with source offsets and redaction | Correlate with actual requests |
| Triage | All phase artifacts | Deduplicated queue with evidence, confidence, next skill, and blocked reason | Testing only when a concrete signal exists |

A phase can be complete with zero findings if the evidence supports that conclusion. It must not be marked complete if a tool failed, input was missing, or output was not persisted; use blocked/partial and record the reason.

## Normalization and deduplication contract

- Host identity: canonical lowercase hostname with trailing dot removed, while preserving scheme/port and source provenance where those change the service boundary.
- URL identity: method + normalized path template + content type + parameter shape + auth context. Do not merge GET and POST, different API versions, or distinct nested object relationships.
- Endpoint parameters: one endpoint record may carry many parameter observations. Never create duplicate endpoint records solely because several IDs/parameters exist.
- Asset attribution: keep CNAME target, hosting provider, certificate evidence, and first-party confidence separate from scope eligibility.
- Time: preserve first_seen, last_seen, source timestamp, and last_checked so stale archive results are not presented as live.
- Diffs: report new, removed, changed, stale, and unresolved assets separately. Do not delete old notes simply because a current run did not rediscover them.

## Source reliability and coverage

For each discovery source, track whether it was attempted, succeeded, returned zero results, failed, or was blocked. A zero-result response is not proof that no assets exist. Record source coverage by source family (program data, certificate transparency, DNS, archives, code, browser traffic, API schema, JS bundles, and service probes) and avoid claiming exhaustive coverage unless the actual run supports it.

## Tool execution and failure handling

Before using a tool, verify its registered name, argument schema, output path, and side effects. Capture exit status and stderr separately from findings. Retry only when a transient failure is plausible and policy permits; do not silently replace a failed source with a guessed command. If an asset resolves to shared hosting, a third-party service, or an ambiguous tenant, preserve the lead and block active testing until attribution is resolved.

## Handoff record

Each queued item should include canonical_asset, scope_evidence, attribution_confidence, discovery_source, first_seen, last_seen, last_checked, route_key, method, parameter_locations, auth_context, observed_signal, hypothesis, negative_control_needed, candidate_skill, active_test_allowed, evidence_refs, status, blocked_reason, and next_action. Never store credentials or raw secrets in the queue.

## Agent-executable CLI tooling, resources, and helper scripts

Use agent-executable CLI tools and local scripts. Browser interfaces, browser extensions, and interactive intercepting proxies are not required dependencies. Verify tool availability/version and official installation guidance before use; inspect request impact and permissions before active testing.

### Recommended tools
- katana — authorized crawling and endpoint discovery
- gau/waymore — passive historical URL sources
- httpx — service metadata and response status
- ffuf or feroxbuster — focused content discovery with approved rates
- uro/unfurl/jq — URL cleanup and component extraction

### Resources
- https://github.com/projectdiscovery/katana
- https://github.com/lc/gau
- https://github.com/projectdiscovery/httpx
- https://github.com/ffuf/ffuf
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids; confirm maintenance, license, provenance, and exact CLI behavior from official sources.

### Helper-script contract
Merge URL sources while retaining provenance, method, parameter names, and observation time. Keep one endpoint record with multiple parameter observations and distinguish passive discoveries from active probes.

Preserve raw outputs and normalize a separate copy. Helpers should retain provenance, timestamps, tool/version, errors, confidence, and output paths; redact secrets; support JSON/JSONL where useful; and include local fixtures.

### Handoff
Report commands actually executed, tool versions, input/output artifact references, deduplication counts, errors/blocked sources, confidence, limitations, and the next skill.
