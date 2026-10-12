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

## References

- Source merged: [uphiago/recon-skills — recon/subdomain-enumeration/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/subdomain-enumeration/SKILL.md)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Certificate Transparency](https://certificate.transparency.dev/)
- [RFC 1034 — Domain Names: Concepts and Facilities](https://www.rfc-editor.org/rfc/rfc1034)
