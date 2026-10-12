---
name: recon-asn-infrastructure
description: "Map an organization's attributable IP infrastructure through ASN, CIDR, reverse DNS, sibling domains, and service metadata."
category: "recon"
version: "1.0.0"
author: "cyberstrike-official"
tags: [recon, asn, cidr, dns, infrastructure, asset-inventory]
tech_stack: [DNS, BGP, WHOIS, Linux]
chains_with: [recon-methodology, attack-subdomain-takeover, attack-host-header, attack-minio-s3]
prerequisites:
  - "A confirmed organization domain or attributable IP"
severity_boost: {}
---

# ASN and Infrastructure Mapping

## Objective

Expand a known organization asset into a defensible infrastructure map while avoiding the common error of treating an entire hosting provider or shared ASN as organization-owned. The output is an evidence-backed inventory, not automatic authorization to probe every adjacent address.

## Methodology

### 1. Establish attribution anchors

Start from domains and IPs already confirmed to belong to the organization. Collect RDAP/WHOIS organization fields, ASN origin, DNS answers, certificate transparency names, and first-party references. Record source, timestamp, confidence, and whether an address is dedicated, shared, CDN-fronted, or cloud-hosted.

### 2. Resolve domains to IP and ASN

Use DNS resolution and ASN lookup tools to identify origin ASN and route objects. Validate results through at least two independent sources where possible; registrant names and route descriptions can be stale or generic. Handle IPv4 and IPv6 separately.

### 3. Expand announced prefixes

Collect routed CIDR prefixes associated with confirmed ASNs, then classify them by ownership confidence. Do not automatically enumerate or scan a whole provider ASN, cloud region, or large shared prefix. For hyperscalers, use first-party DNS, certificates, service metadata, and confirmed address associations to narrow the inventory.

### 4. Pivot through reverse DNS and service metadata

Resolve PTR records for confirmed addresses and correlate hostnames with known domains. Inspect TLS certificates, redirect targets, favicon hashes, and server metadata to cluster services. Shared IPs often indicate CDNs or multi-tenant hosting rather than common ownership.

### 5. Expand sibling domains and subsidiaries

Generate candidate sibling TLDs or subsidiary names only as leads. Confirm each candidate through ownership evidence such as official links, corporate registration, certificate/DNS continuity, organization-controlled repositories, or known IdP/application links before active testing.

### 6. Produce an asset graph

Represent relationships as domain → DNS record → IP → ASN/prefix → service → application. Include provenance and confidence per edge. Quarantine unresolved candidates instead of silently merging them into the owned inventory.

## What This Produces

- A deduplicated domain/IP/service inventory with source provenance.
- Attribution confidence and explicit shared-infrastructure flags.
- Reverse-DNS and certificate-derived hostnames requiring follow-up.
- A prioritized set of verified assets for downstream testing.
- A quarantine list for same-name collisions, stale WHOIS data, and third-party hosting.

## Evidence Requirements

- Timestamped DNS/RDAP/ASN results and URLs or commands used to obtain them.
- Specific evidence linking each candidate asset to the organization.
- Prefix size, provider/shared-hosting notes, and confidence level.
- Do not report a broad infrastructure map as a vulnerability without a demonstrated exposure or security impact.

## Tools

- dig, whois/RDAP clients, asnmap, dnsx, httpx, mapcidr, and naabu where permitted.
- Certificate Transparency search and reputable BGP/RPKI explorers.
- jq, Python, or CSV tooling to deduplicate records and retain provenance.
- Passive sources such as BGP.tools, bgp.he.net, and organization-owned documentation.

## Attribution and Expansion Matrix

| Pivot | Useful signal | Confidence check | Common trap |
|---|---|---|---|
| Domain → IP | A/AAAA/CNAME records | Re-resolve and record TTL/provider | CDN address mistaken for origin |
| IP → ASN | Origin ASN and route object | Cross-check RDAP and BGP data | Shared cloud ASN treated as owned |
| ASN → CIDR | Announced prefix | Confirm organization allocation and route status | Scanning huge provider ranges |
| IP → hostname | PTR and TLS SAN | Match canonical domains and app behavior | Stale PTR or generic certificate |
| Domain → sibling TLD | Similar brand/domain string | First-party or ownership evidence | Same-name unrelated company |
| Service → application | HTTP/TLS metadata | Verify consistent application identity | Default hosting page treated as target |
| Subsidiary → infrastructure | Corporate relationship | Official parent/subsidiary evidence | Guessed relationship from naming |

## Verification and False Positives

- Confirm attribution before active requests; asset discovery does not expand the written target list.
- Reconcile IPv4 and IPv6, CNAME chains, CDN edges, and origin addresses independently.
- Remove duplicate addresses and normalize hostnames before counting coverage.
- Treat WHOIS organization strings, PTR names, and brand-name matches as weak signals unless corroborated.
- Prefer targeted service checks over high-rate scans of broad ranges.


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Use the 20-attempt budget as a ceiling for independent evidence-producing hypotheses, not as a quota for payload mutations. Follow relevant signal-led branches only while the candidate remains plausible; stop early on decisive evidence, scope/safety limits, or when no meaningful branch remains. Cosmetic variants are not separate hypotheses.

Track each attempt as hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired requests and controlled test identities/fixtures; save only minimal sanitized evidence.

### Skill-specific hypothesis order

1. Anchor discovery to verified organization names, registered entities, known domains, and current RIR/ASN evidence; a matching company string or IP hostname is not sufficient ownership proof.
2. Collect passive ASN, prefix, BGP, reverse-DNS, certificate, and provider metadata first; preserve source URLs and observation timestamps for each candidate.
3. Normalize prefixes and hostnames, deduplicate shared CDN/cloud edges, and separate directly registered infrastructure from reseller, SaaS, shared hosting, and third-party service providers.
4. Promote a prefix to active testing only when written scope clearly covers it; do not sweep every IP in an ASN or infer permission from routing/WHOIS ownership.
5. Return candidate prefixes with attribution confidence, evidence provenance, explicit exclusions, validation status, and narrow next steps; hand confirmed web assets to the relevant recon/attack skill rather than claiming a vulnerability.


### Verdict gates

- **Confirmed:** repeatable impact at an explicit in-scope boundary is demonstrated using a controlled identity/fixture and a meaningful control.
- **Likely / needs corroboration:** independent indicators support the candidate, but the consequence or root cause remains uncertain.
- **Unconfirmed:** evidence is generic, ambiguous, cached, or not tied to a security property.
- **Refuted / false positive:** a relevant negative control or valid implementation/policy explanation accounts for the observation. Document tested branches; do not claim all imaginable variants were exhausted.
- Scanner alerts, version strings, banner text, status codes, and response length alone are not proof.

### Stop, cleanup, and handoff

Stop on scope ambiguity, unexpected user data, state changes, service degradation, secret exposure or prohibited behavior. Clean disposable test state and revoke temporary sessions/tokens where possible. Return scope proof, baseline, hypothesis, attempts used, impact, negative controls, verdict/confidence, sanitized evidence and cleanup status. Start a chained skill only when its trigger has been independently observed.

## References

- Source merged: [uphiago/recon-skills — recon/asn-infrastructure-mapping/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/asn-infrastructure-mapping/SKILL.md)
- [RIPE NCC — IP and ASN resources](https://www.ripe.net/)
- [BGP.tools](https://bgp.tools/)
- [RFC 9082 — RDAP Query Format](https://www.rfc-editor.org/rfc/rfc9082)
