---
name: recon-vhost-enumeration
description: "Identify virtual hosts and tenant-specific applications on confirmed infrastructure using DNS, TLS, HTTP Host behavior, and response clustering."
category: "recon"
version: "1.0.0"
author: "cyberstrike-official"
tags: [recon, virtual-host, HTTP, TLS, DNS]
tech_stack: [HTTP, TLS, DNS, reverse-proxy]
chains_with: [recon-asn-infrastructure, recon-origin-ip-discovery, attack-host-header, recon-methodology]
prerequisites:
  - "A confirmed target domain or attributable server IP"
severity_boost: {}
---

# Virtual-Host Enumeration

## Objective

Identify hostnames routed by a shared web server or reverse proxy, then classify whether each host belongs to the target organization and is an authorized asset. A different response to a Host header is a discovery signal, not proof of a vulnerability.

## Methodology

### 1. Establish response fingerprints

Capture a baseline for the canonical hostname and a random nonexistent hostname. Record status, redirect, title, body hash/length, certificate names, server headers, and a stable application marker. This identifies default virtual hosts and wildcard DNS behavior.

### 2. Generate candidate hostnames

Use passive DNS, certificate transparency, organization-owned documentation, observed links, DNS records, and a restrained wordlist derived from application roles (api, auth, staging, admin, files, assets). Normalize names and deduplicate candidates. Avoid indiscriminate brute force where the engagement prohibits it.

### 3. Resolve and classify candidates

Resolve A/AAAA/CNAME, note wildcard responses, and compare TLS SAN/certificate behavior. A resolved hostname may be parked, delegated to a third party, or point to a shared platform; confirm application identity and ownership before active testing.

### 4. Compare HTTP routing

For confirmed IPs, request each candidate hostname with correct TLS SNI where applicable. Compare application marker, redirects, cookies, and route behavior. If a Host header changes the destination or generates absolute URLs, use the dedicated host-header skill to test trust boundaries.

### 5. Prioritize unusual hosts

Review staging, preview, legacy, API, upload, tenant, and administrative hosts for weaker authentication or outdated deployments. Apply the same ownership and permission checks as any other asset. Do not infer that a hostname is in scope solely because its name matches the brand.

## What This Produces

- A deduplicated candidate hostname inventory.
- DNS/TLS/HTTP fingerprints and wildcard/default-host classifications.
- Ownership confidence and notes on third-party hosting.
- A prioritized list of confirmed applications for follow-up testing.

## Evidence Requirements

- Candidate source and resolution timestamp.
- Baseline versus candidate fingerprints, including the random-host control.
- Evidence tying the host to the organization.
- For any vulnerability, a separate minimal proof of security impact beyond host discovery.

## Tools

- dig, dnsx, certificate-transparency search, httpx, and curl.
- Burp Repeater for controlled Host/SNI comparisons.
- Python/jq for response fingerprints and deduplication.
- Passive DNS and RDAP sources for attribution.

## Virtual-Host Signal Matrix

| Signal | What it may indicate | Verification |
|---|---|---|
| Wildcard DNS | Many labels resolve to one edge | Compare random-host and known-host responses |
| Unique TLS SAN | Hostname was included in a certificate | Confirm current app and ownership |
| Distinct redirect | Host-specific routing or canonicalization | Follow chain and inspect final host |
| Different body hash | Separate virtual host or dynamic response | Compare stable markers and repeat |
| Default server page | Unknown Host reached a default vhost | Not a target asset without attribution |
| Staging/preview name | Non-production deployment | Verify ownership and authorization before testing |
| Same IP, different app | Shared server routing | Preserve SNI and Host consistently |

## Verification and False Positives

- Exclude random-host catch-all responses and wildcard DNS noise.
- Normalize dynamic values before body-hash comparison.
- Do not treat certificate presence as proof that the current host is live or owned.
- Confirm redirects do not lead to third-party SaaS or parked domains.
- Keep host discovery separate from vulnerability claims.


## Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. The validation budget is at most 20 distinct hypotheses per candidate asset; it is not permission for 20 scans or repeated probes. Prefer passive sources first, deduplicate candidates, and use active checks only when the asset and activity are explicitly in scope.

### Evidence record and confidence

For each candidate, preserve normalized asset, source/provenance, observation time, scope proof, resolver/HTTP/tool and relevant version, raw-evidence location, corroborating source, negative control, attribution confidence, next action, and related-skill trigger. Separate **asset confidence** (is it related to the organization?) from **security confidence** (is a vulnerability demonstrated?).

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. C1/C2 are not confirmed vulnerabilities.

### Skill-specific next steps

undefined

### Deduplication and stop rules

Normalize case, trailing dots, scheme/port, redirects, canonical names and resolved addresses before deduplication. Detect wildcard DNS, shared hosting, CDN/edge responses, soft-404s and stale records before ranking counts. Stop on exclusions, ownership ambiguity, unexpected sensitive data, throttling, instability or boundaries requiring further permission. Never claim ownership or register dangling resources.

### Handoff format

Return candidates with scope/provenance, confidence level, evidence path, deduplication key, negative control, priority rationale, safe next step and trigger for any linked attack skill. Promote a candidate to active testing only after scope and attribution are confirmed; promote it to a finding only after the relevant attack skill verifies the security boundary.

## References

- Source merged: [uphiago/recon-skills — recon/vhost-enumeration/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/vhost-enumeration/SKILL.md)
- [RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)
- [RFC 6066: TLS Server Name Indication](https://www.rfc-editor.org/rfc/rfc6066)
