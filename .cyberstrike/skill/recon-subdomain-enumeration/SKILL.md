---
name: recon-subdomain-enumeration
description: "Build a deduplicated, attribution-aware subdomain inventory using passive sources, DNS resolution, certificate transparency, and bounded active discovery."
category: "recon"
version: "1.0.0"
author: "cyberstrike-official"
tags: [recon, subdomain, DNS, certificate-transparency, asset-inventory]
tech_stack: [DNS, HTTP, TLS, Linux]
chains_with: [recon-methodology, recon-vhost-enumeration, recon-asn-infrastructure, attack-subdomain-takeover]
prerequisites:
  - "A confirmed organization root domain and applicable discovery permissions"
severity_boost: {}
---

# Subdomain Enumeration and Validation

## Objective

Produce a reliable inventory of candidate subdomains, verify which names are live and attributable, and prioritize distinct applications for later security testing. A discovered hostname is not automatically owned or authorized.

## Testing Methodology

### 1. Establish the root-domain set

Start with the program's canonical domains and verified subsidiaries. Normalize case, trailing dots, IDNs, wildcard entries, and duplicate records. Keep root-domain ownership evidence with the inventory.

### 2. Collect passive candidates

Combine certificate transparency, passive DNS, search indexes, public DNS datasets, first-party links, public documentation, and organization-controlled repositories. Record source and observation time for each hostname. Passive discovery is often enough to reveal legacy and API names without active probing.

### 3. Add bounded active discovery when permitted

Use a restrained wordlist derived from known naming conventions and the application's architecture. Keep request rate and concurrency conservative. Expand the wordlist based on evidence rather than running an unbounded dictionary against every candidate domain.

### 4. Resolve DNS and identify wildcard behavior

Resolve A, AAAA, CNAME, MX, and relevant TXT records. Compare candidate answers with random labels under the same parent to detect wildcard DNS. Preserve full CNAME chains and TTLs; distinguish NXDOMAIN, NODATA, SERVFAIL, and transient resolver failures.

### 5. Validate live web services

For confirmed in-scope names, collect HTTP status, final URL, title, TLS certificate/SAN, content type, and a stable body fingerprint. Compare with random-host controls to eliminate wildcard pages, parked domains, and SPA catch-alls. Record non-HTTP services separately.

### 6. Attribute and cluster assets

Correlate DNS, certificate, HTTP, application branding, and infrastructure data. Classify third-party SaaS, shared hosting, CDN edges, and same-name collisions. Quarantine ambiguous hosts until ownership is corroborated.

### 7. Prioritize distinct applications

Prioritize authentication, API, staging/preview, admin, upload, billing, tenant, legacy, and file-hosting surfaces. Feed confirmed hosts into virtual-host, origin, takeover, and application-specific workflows.

## What This Produces

- A normalized hostname list with provenance and timestamps.
- DNS resolution state, wildcard status, and service metadata.
- Ownership confidence and explicit quarantine for ambiguous assets.
- A prioritized list of distinct applications rather than a raw count of names.

## Evidence Requirements

- Source URL/tool and observation timestamp for each candidate.
- DNS chain and relevant records for live assets.
- HTTP/TLS fingerprint and random-host control.
- Clear reason for ownership attribution and scope classification.
- A vulnerability report must include separate proof of impact; subdomain discovery alone is not a finding.

## Tools

- subfinder, amass, dnsx, puredns, httpx, and certificate-transparency search.
- dig/drill for DNS troubleshooting.
- Python/jq for normalization, deduplication, provenance, and confidence scoring.
- `python3 .cyberstrike/skill/scripts/host_inventory.py observations.jsonl -o hosts.jsonl --errors invalid.jsonl` to normalize hostname observations while preserving all source records; this helper makes no network requests.
- gowitness or browser automation for visual clustering after live-host validation.

## Enumeration Coverage Matrix

| Source/phase | Strength | Typical blind spot | Validation |
|---|---|---|---|
| Certificate transparency | Names in issued certificates | Old certificates and third-party SANs | Resolve and confirm current app |
| Passive DNS | Historical and current DNS associations | Stale records and incomplete datasets | Re-resolve and preserve TTL |
| First-party links/repositories | High attribution value | Incomplete or outdated references | Check current DNS and application response |
| Search indexes | Human-discoverable pages and docs | Index lag and noisy naming collisions | Confirm live host and ownership |
| Active wordlist | Finds undocumented conventional names | Rate limits, wildcard noise, missed unusual names | Low-rate probes and random-label controls |
| DNS wildcard analysis | Detects catch-all resolution | Parent-specific and provider-specific behavior | Compare multiple random labels |
| HTTP/TLS fingerprinting | Distinguishes applications | Dynamic pages and shared certificates | Stable markers, redirect chain, repeated capture |

## Verification and False Positives

- Use random labels to identify wildcard DNS and catch-all web responses.
- Do not equate a certificate SAN with current ownership or reachability.
- Confirm third-party SaaS tenant attribution before further testing.
- Normalize IDNs and trailing dots consistently to avoid duplicate counts.
- Treat DNS resolution as discovery evidence, not proof of vulnerability.
- Keep unresolved candidates quarantined instead of probing them automatically.

## Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. there is no fixed hypothesis-count ceiling; continue distinct, decision-relevant hypotheses while authorized, and stop when evidence or a real safety/policy boundary resolves the branch. Prefer passive sources first, deduplicate candidates, and use active checks only when the asset and activity are explicitly in scope.

### Evidence record and confidence

For each candidate, preserve normalized asset, source/provenance, observation time, scope proof, resolver/HTTP/tool and relevant version, raw-evidence location, corroborating source, negative control, attribution confidence, next action, and related-skill trigger. Separate **asset confidence** (is it related to the organization?) from **security confidence** (is a vulnerability demonstrated?).

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. C1/C2 are not confirmed vulnerabilities.

### Skill-specific next steps

1. Confirm the root domain is in scope, then collect passive names from certificate transparency, first-party links, approved passive providers, and installed tooling; keep provenance per hostname.
2. Normalize wildcards, case, trailing dots, IDNs, and duplicate results. Preserve raw input and timestamps before creating a deduplicated candidate list.
3. Resolve A/AAAA/CNAME/MX as relevant, inspect the CNAME chain and TTL, and compare multiple random labels to detect wildcard DNS. Distinguish NXDOMAIN, NODATA, SERVFAIL, and transient resolver failures.
4. Validate live HTTP/TLS hosts with conservative timeouts and stable fingerprints; use random-host and random-path controls to eliminate wildcard responses, parked domains, CDN edges, and soft-404 pages.
5. Quarantine ambiguous ownership and third-party SaaS until corroborated. Return confidence, evidence, scope decision, deduplication key, and the specific next recon/attack skill trigger; discovered names are not findings.

### Deduplication and stop rules

Normalize case, trailing dots, scheme/port, redirects, canonical names and resolved addresses before deduplication. Detect wildcard DNS, shared hosting, CDN/edge responses, soft-404s and stale records before ranking counts. Stop on exclusions, ownership ambiguity, unexpected sensitive data, throttling, instability or boundaries requiring further permission. Never claim ownership or register dangling resources.

### Handoff format

Return candidates with scope/provenance, confidence level, evidence path, deduplication key, negative control, priority rationale, safe next step and trigger for any linked attack skill. Promote a candidate to active testing only after scope and attribution are confirmed; promote it to a finding only after the relevant attack skill verifies the security boundary.

### CyberStrike workspace handoff

A candidate list is not yet the target workspace inventory. After attribution, DNS/HTTP checks, and the saved program-scope review, register each corroborated authorized child host so future runs can find its notes and evidence:

- `cyberstrike target attach https://example.com https://api.example.com --kind api`
- `cyberstrike target attach https://example.com https://app.example.com --kind application`

Replace both example hosts with the actual authorized program and child. Never attach third-party SaaS tenants, excluded hosts, uncertain candidates, or out-of-scope names. The command uses the persisted scope and refuses ambiguous parent matches. Run `cyberstrike target tree https://example.com` to verify placement. Store source URL, observation time, DNS/HTTP evidence, and attribution confidence in the child target's notes; do not treat an asset registration as a vulnerability finding.

## References

- Source merged: [uphiago/recon-skills — recon/subdomain-enumeration/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/subdomain-enumeration/SKILL.md)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Certificate Transparency](https://certificate.transparency.dev/)
- [RFC 1034 — Domain Names: Concepts and Facilities](https://www.rfc-editor.org/rfc/rfc1034)

## Targeted quality-loop enrichment (2026-10-19)

### Discovery provenance and wildcard handling
Keep each candidate with source, timestamp, DNS answers/CNAME chain, wildcard-DNS check, HTTP fingerprint, ownership evidence, and explicit scope decision. Deduplicate normalized hostnames while preserving their discovery sources; never discard method, port, or auth context when later joining URL inventories. Correlate passive findings with current DNS and a second independent ownership signal before active probing. A historical hostname, third-party CNAME, wildcard response, or cert-transparency entry is a lead—not proof of live ownership or permission. Delta newly observed hosts against earlier runs, and route confirmed HTTP hosts to web recon while keeping cloud/CDN/shared-hosting ambiguity passive until resolved.

## Agent-executable CLI tooling, resources, and helper scripts

Use tools the agent can invoke directly. Browser interfaces, browser extensions, and interactive intercepting proxies are not dependencies for this skill. Check availability/version before use; if missing, verify official installation instructions, license, dependencies, and platform compatibility before proposing installation. Never claim a tool ran unless its command completed and output was inspected.

### Recommended tools
- subfinder — passive subdomain discovery
- amass — asset relationship mapping
- dnsx — DNS resolution and record checks
- puredns — wildcard-aware resolution when active discovery is authorized
- httpx — HTTP/TLS metadata
- jq and Python — normalization and provenance-preserving deduplication

### Installation and verification
- Follow official installation instructions for [subfinder](https://github.com/projectdiscovery/subfinder), [Amass](https://github.com/owasp-amass/amass), [dnsx](https://github.com/projectdiscovery/dnsx), [puredns](https://github.com/d3mondev/puredns), and [httpx](https://github.com/projectdiscovery/httpx); do not copy installation commands from untrusted write-ups.
- Verify each installed binary with its documented version/help option (for example, `subfinder -version`, `dnsx -h`, and `httpx -version`; flags can vary by release, so check upstream docs).
- Start with passive sources and existing DNS observations. Run active resolution only when allowed. If a dependency is unavailable, retain passive findings and record the limitation rather than reporting an empty successful run.

### Official resources
- https://github.com/projectdiscovery/subfinder
- https://github.com/owasp-amass/amass
- https://github.com/projectdiscovery/dnsx
- https://github.com/projectdiscovery/httpx
- https://github.com/vavkamil/awesome-bugbounty-tools

Treat community lists as discovery aids, not proof that a project is maintained or safe. Prefer official docs for installation, flags, output formats, and limitations.

### Helper script and output contract
Create a JSONL host normalizer that retains every source observation, timestamps, DNS answers/TTL, wildcard-control results, and attribution confidence. Do not collapse provenance when deduplicating hostnames.

Preserve native output; write normalized output separately. Keep provenance, timestamp, tool/version, errors, confidence, and evidence references. Redact secrets and avoid silently overwriting source evidence. Emit machine-readable JSON/JSONL where practical and test helpers against local fixtures.

### Handoff
Return the command/tool and version, input/output artifact references, accepted/deduplicated/rejected/failed counts where applicable, limitations, confidence, and next skill. A missing tool or blocked source is an explicit status, not a successful empty result.
### CyberStrike source orchestration

When working inside this repository/runtime, prefer the shared passive source runner instead of creating one script/output per source:

```bash
# CyberStrike tool call (conceptual args; substitute actual workspace path):
attack_script(script="passive_subdomain_sources", args=[
  "example.com",
  "--output", "<canonical-workspace-root>/subdomain-sources.json",
  "--hosts-output", "<canonical-workspace-root>/subdomains.txt",
], timeout_seconds=<adequate aggregate timeout>)
```

The JSON output records each root/source pair as success, zero-results, failed, blocked, or unavailable, with counts/errors and source attribution on each normalized hostname. It queries crt.sh and installed supported CLIs only; it does not resolve or probe discovered hosts. Verify the saved JSON and counts before moving to DNS/live-host checks. Replace `example.com` and the output path with the actual root and path returned by the canonical workspace tool. If the helper is absent in an installed build, use available registered APIs/CLIs and record the missing-helper limitation rather than claiming source coverage.
