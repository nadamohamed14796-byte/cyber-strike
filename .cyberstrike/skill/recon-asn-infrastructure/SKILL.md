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

## References

- Source merged: [uphiago/recon-skills — recon/asn-infrastructure-mapping/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/asn-infrastructure-mapping/SKILL.md)
- [RIPE NCC — IP and ASN resources](https://www.ripe.net/)
- [BGP.tools](https://bgp.tools/)
- [RFC 9082 — RDAP Query Format](https://www.rfc-editor.org/rfc/rfc9082)
