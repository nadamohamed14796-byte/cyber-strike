---
name: recon-origin-ip-discovery
description: "Assess whether a web origin is directly reachable behind a CDN or reverse proxy and whether origin exposure changes the security boundary."
category: "recon"
version: "1.0.0"
author: "cyberstrike-official"
tags: [recon, origin-ip, CDN, reverse-proxy, DNS]
tech_stack: [DNS, HTTP, TLS, CDN]
chains_with: [recon-asn-infrastructure, attack-host-header, attack-cache-poison]
prerequisites:
  - "A confirmed domain and evidence of CDN/reverse-proxy use"
severity_boost:
  medium: "A confirmed origin bypasses a security control that is demonstrably enforced only at the edge."
---

# Origin IP Exposure Assessment

## Objective

Determine whether an application origin is directly addressable and whether direct-origin access bypasses a material control such as edge authentication, WAF policy, rate limiting, or cache behavior. Discovering an IP alone is not a vulnerability.

## Testing Methodology

### 1. Establish the edge baseline

Resolve A/AAAA/CNAME records, record certificate and HTTP behavior, and identify likely CDN or reverse-proxy indicators. Capture a normal request's response headers, redirects, and application marker. Separate shared edge addresses from candidate origins.

### 2. Collect passive origin candidates

Correlate historical DNS, certificate transparency, organization-owned DNS records, public service metadata, passive scan results, and attributable ASN/IP information. Treat old DNS records, mail servers, and unrelated addresses in a shared prefix as candidates until corroborated.

### 3. Confirm candidate identity without bypass assumptions

Where testing is authorized, connect to a candidate IP while preserving the expected TLS SNI and HTTP Host for the confirmed domain. Compare certificate, redirect, body marker, and application behavior with the edge baseline. Do not treat a TLS mismatch or default virtual-host page as proof that the candidate is the origin.

### 4. Compare security controls

Use the same benign request and controlled identity through edge and candidate origin. Compare authentication, WAF behavior, rate-limit response, cache directives, and route availability. Do not run destructive payloads or high-volume tests to establish a differential.

### 5. Assess practical impact

A reportable issue requires a control that can be bypassed or an unintended service/data exposure at the origin. Document the precise difference and the minimum route needed to prove it. If the origin is intentionally public and enforces the same controls, record it as an inventory result only.

## What Constitutes a Finding

- Direct origin access bypasses a material security control or exposes a private service.
- The candidate IP is attributable to the same application, not merely the same cloud provider.
- The edge/origin comparison is reproducible with identical request semantics.
- An IP address, historical DNS record, or different certificate alone is not a vulnerability.

## Evidence Requirements

- DNS/passive-source provenance and timestamp.
- Sanitized edge and origin request/response pairs, including Host and SNI context.
- Exact control that differs and a minimal impact demonstration.
- Redact tokens and private application data.

## Tools

- dig, passive DNS, certificate-transparency search, RDAP/ASN tools.
- curl with explicit resolve/SNI behavior, openssl s_client, and Burp Repeater.
- httpx for low-volume fingerprint comparison.
- CDN/provider documentation to understand intended origin protections.

## Origin Attribution Matrix

| Signal | Interpretation | Required corroboration |
|---|---|---|
| Historical DNS A record | Candidate historical host | Same app marker or certificate identity |
| Certificate SAN | Hostnames share certificate | Verify current application response |
| Direct IP returns app | Possible origin or shared host | Preserve SNI/Host and compare content |
| WAF differs at origin | Potential edge-only enforcement | Confirm the same request is denied at edge and materially succeeds at origin |
| Different server banner | Infrastructure clue | No impact unless a security boundary is bypassed |
| Origin responds on extra port | Additional service candidate | Confirm ownership and service sensitivity |

## Verification and False Positives

- Account for DNS changes, CDN migration, shared hosting, and anycast addresses.
- Preserve Host and TLS SNI; otherwise the server may serve a default site.
- Compare final response semantics, not status codes alone.
- Do not scan broad cloud address ranges to find origins.
- Treat exposed origin IPs as informational unless direct access changes security posture.


## Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. there is no fixed hypothesis-count ceiling; continue distinct, decision-relevant hypotheses while authorized, and stop when evidence or a real safety/policy boundary resolves the branch. Prefer passive sources first, deduplicate candidates, and use active checks only when the asset and activity are explicitly in scope.

### Evidence record and confidence

For each candidate, preserve normalized asset, source/provenance, observation time, scope proof, resolver/HTTP/tool and relevant version, raw-evidence location, corroborating source, negative control, attribution confidence, next action, and related-skill trigger. Separate **asset confidence** (is it related to the organization?) from **security confidence** (is a vulnerability demonstrated?).

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. C1/C2 are not confirmed vulnerabilities.

### Skill-specific next steps

1. Start from confirmed domains and passive evidence (historical DNS, certificate data, provider records, and first-party configuration) before any network probes.
2. Correlate candidate addresses with ownership, ASN/provider, TLS/SNI certificate, application response, and current DNS. A historical A record or shared IP alone does not identify a unique origin.
3. Use only low-impact checks within explicitly scoped address ranges; do not bypass CDN/WAF controls to attack origin services, scan neighboring tenants, or change host routing.
4. Compare a candidate address with the normal CDN/front-door response using the expected Host/SNI and a random-host control. Distinguish genuine origin reachability from shared hosting or a provider edge.
5. Return each candidate with source, timestamp, ownership confidence, corroborating signals, and scope decision. Discovery is not permission to probe the address and is not itself a vulnerability.


### Deduplication and stop rules

Normalize case, trailing dots, scheme/port, redirects, canonical names and resolved addresses before deduplication. Detect wildcard DNS, shared hosting, CDN/edge responses, soft-404s and stale records before ranking counts. Stop on exclusions, ownership ambiguity, unexpected sensitive data, throttling, instability or boundaries requiring further permission. Never claim ownership or register dangling resources.

### Handoff format

Return candidates with scope/provenance, confidence level, evidence path, deduplication key, negative control, priority rationale, safe next step and trigger for any linked attack skill. Promote a candidate to active testing only after scope and attribution are confirmed; promote it to a finding only after the relevant attack skill verifies the security boundary.

## References

- Source merged: [uphiago/recon-skills — recon/origin-ip-discovery/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/origin-ip-discovery/SKILL.md)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [RFC 6066: TLS Server Name Indication](https://www.rfc-editor.org/rfc/rfc6066)


## Targeted quality-loop enrichment (2026-10-19)

### Origin attribution versus bypass claims
Build candidate origins from historical DNS, certificate/deployment metadata, first-party configuration, and observed redirects, but score each by freshness and organization attribution. A CDN/origin relationship does not automatically permit direct-origin requests; verify the candidate is in program scope and that testing the origin is allowed. If permitted, compare one harmless public path through the normal edge and candidate origin, recording TLS, Host/routing, authentication, and applicable controls. Do not bypass a WAF to access protected content or treat an origin IP as a security bug by itself. Confirm a meaningful difference before chaining to host-header, cache, or access-control review.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Prefer passive DNS/certificate history and provider attribution. ProjectDiscovery dnsx and cdncheck can help inspect DNS/CDN signals; public services such as SecurityTrails or Censys may corroborate historical records, subject to their data and disclosure policies.

### Installation and setup
- [ProjectDiscovery documentation](https://docs.projectdiscovery.io/) — official tool installation and options.
- [SecurityTrails API docs](https://docs.securitytrails.com/) — optional passive DNS source.
- [Censys docs](https://docs.censys.com/) — optional public Internet asset data.
Treat a guessed origin IP as an attribution hypothesis, not authorization to access it. Do not bypass a CDN/WAF to reach an origin or scan the IP unless the program expressly includes that infrastructure and testing method.

### Primary resources
- [ProjectDiscovery docs](https://docs.projectdiscovery.io/) — DNS/CDN tool behavior.
- [Cloudflare origin protection](https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/) — example CDN/origin relationship.
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) — recon context.

### Reusable helper
Run python3 .cyberstrike/skill/scripts/normalize_urls.py urls.txt to deduplicate collected host/URL observations where a URL form is available; it does not resolve names or contact the origin.

### Result handling
Record DNS source, timestamp, CDN/provider evidence, independent corroboration, and confidence. Keep original target host distinct from any inferred backend address.
