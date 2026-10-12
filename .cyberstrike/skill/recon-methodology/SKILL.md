---
name: recon-methodology
description: "Plan and execute evidence-led, scope-locked reconnaissance that produces a deduplicated, prioritized testing queue"
version: "1.1.0"
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

Turn an authorized target list into a scope-checked, deduplicated inventory and a prioritized queue of hypotheses. Recon observations are leads, not findings. The goal is to identify the smallest next test likely to establish a meaningful security property.

## 1. Engagement contract

Before any active request, record:
- exact assets, wildcard rules, exclusions, third-party services, and program links;
- allowed recon methods, request rate, scan windows, and prohibited techniques;
- workspace and evidence-retention location;
- stop conditions for instability, rate limits, unexpected sensitive data, or scope ambiguity.

Public reachability does not imply authorization. Every discovered hostname, IP, API, repository, or third-party service must pass the scope resolver before active testing.

## 2. Recon pipeline

### A. Normalize and lock scope

Canonicalize hostnames, schemes, ports, trailing dots, IDNs, wildcard entries, and exclusions. Keep the original source and reason for every candidate. Resolve wildcard rules conservatively; do not treat an entire shared CDN or cloud provider as in scope.

### B. Passive discovery first

Use program-provided asset lists, certificate transparency, public DNS history, public code search, archived URLs, and other permitted passive sources. Preserve provenance and timestamps. Do not scrape private systems or use leaked credentials.

### C. DNS and infrastructure mapping

Resolve candidates and distinguish confirmed records, aliases, wildcard DNS, parked domains, unresolved names, and stale records. Keep CNAME chains and provider fingerprints. DNS resolution is not proof that a hostname is owned or in scope.

### D. HTTP and service validation

For in-scope hosts, record status, title, redirect chain, TLS certificate, server hints, content type, and stable response fingerprints. Use bounded timeouts and concurrency. Avoid broad port scans or content brute force unless explicitly permitted.

### E. Web and API enumeration

Collect URLs from permitted crawling, application traffic, JavaScript bundles, source maps, API documentation, robots/sitemap files, and known application routes. Normalize URLs and deduplicate while retaining parameter names, methods, auth context, source, and discovery time. Separate public routes from authenticated routes and write operations.

### F. Technology and ownership signals

Record framework, CDN, cloud provider, CMS, API style, authentication mechanism, and likely tenant boundaries only when evidence supports the inference. Keep confidence and evidence for each fingerprint; do not convert a banner into a vulnerability claim.

### G. Queue construction

For each candidate, store target, scope decision, source/provenance, signal, hypothesis, expected security property, required account/role, safe validation step, priority, and status. Prioritize high-value trust boundaries, newly discovered assets, exposed APIs, cross-tenant behavior, and changes from the previous recon wave.

## 3. Delta analysis

Compare each recon run with the prior snapshot. Highlight new hosts, changed technologies, newly exposed endpoints, changed authentication behavior, new JavaScript assets, and DNS/provider changes. Avoid rerunning expensive scans if the delta does not justify them.

## 4. Stop conditions and hygiene

Stop when a target is out of scope, rate-limited, unstable, serving unexpected private data, or ownership is uncertain. Do not store tokens, personal data, or target-specific secrets in committed files. Keep raw outputs outside the source repository and attach redacted evidence references.

## 5. Quality gates

Before handing a lead to a testing skill:
- [ ] scope is explicitly confirmed;
- [ ] the observation is reproducible;
- [ ] duplicate URLs/hosts are normalized;
- [ ] provenance and timestamp are recorded;
- [ ] hypothesis and expected policy are explicit;
- [ ] the next test is bounded and authorized;
- [ ] the lead is not mislabeled as a vulnerability.

## Output contract

Return a normalized asset inventory, endpoint inventory, scope decisions, evidence/provenance, delta summary, prioritized hypotheses, and next-step recommendations. Keep discovery facts separate from security conclusions.
