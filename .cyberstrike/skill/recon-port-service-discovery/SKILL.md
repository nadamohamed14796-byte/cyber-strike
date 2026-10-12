---
name: recon-port-service-discovery
description: "Classify services on confirmed target infrastructure and prioritize web, API, management, and unusual-port exposures using bounded probes."
category: "recon"
version: "1.0.0"
author: "cyberstrike-official"
tags: [recon, ports, services, network, HTTP, TLS]
tech_stack: [TCP, UDP, HTTP, TLS, DNS, Linux]
chains_with: [recon-methodology, recon-asn-infrastructure, recon-origin-ip-discovery, recon-vhost-enumeration]
prerequisites:
  - "An attributable host or IP explicitly authorized for service discovery"
severity_boost: {}
---

# Port and Service Discovery

## Objective

Identify reachable services and distinguish expected public application surfaces from accidental management, development, or protocol exposure. Port discovery creates an inventory; a listening port or banner alone is not a vulnerability.

## Methodology

### 1. Establish host attribution and scan boundaries

Use confirmed target addresses, document included ports and rate limits, and exclude shared-provider ranges unless explicitly listed. Prefer DNS-derived and first-party confirmed IPs over broad ASN expansion. Record the time window and source address of the scan.

### 2. Start with low-impact TCP discovery

Begin with common service ports or a program-approved port list. Use conservative concurrency and timeouts. Expand only when the first pass indicates a relevant service or the engagement expressly allows a broader sweep. UDP checks should be targeted because they are less reliable and can be more intrusive.

### 3. Fingerprint services with protocol-aware probes

For each open port, record TCP state, service response, TLS certificate/SAN, ALPN, HTTP status/title, redirect destination, and server metadata. Use a protocol-aware client rather than assuming every high port is HTTP. A banner may be masked, stale, or supplied by a proxy.

### 4. Identify sensitive service classes

Prioritize exposed admin consoles, databases, caches, message brokers, CI/CD systems, object storage, debug endpoints, container/orchestration APIs, and alternate application ports. Confirm whether authentication is required and whether the service is intentionally public. Avoid login attempts with guessed or discovered credentials.

### 5. Correlate services with known applications

Map port → protocol → certificate/hostname → application → owner. Compare alternate ports against the canonical web app and inspect public JavaScript/configuration for backend references. Use the dedicated API, cloud, CMS, and origin skills for service-specific validation.

### 6. Validate one meaningful exposure

For a suspected issue, capture a single benign handshake or read-only response and verify access control with a controlled identity if required. Do not enumerate data, alter configuration, or run exploit checks against sensitive services unless the testing class is explicitly permitted.

## What This Produces

- A deduplicated service inventory with timestamped evidence.
- Protocol and application fingerprints with confidence notes.
- A shortlist of exposed services that warrant a focused security review.
- A clear separation between an open port, a misconfiguration, and a demonstrated vulnerability.

## Evidence Requirements

- Confirmed host attribution and scan boundary.
- Port/protocol/state, timestamp, and minimal sanitized service response.
- Service identity evidence and reason the exposure is unexpected.
- For a vulnerability, the access-control gap or sensitive impact, not just a banner.

## Tools

- Nmap for targeted TCP/UDP service discovery where permitted.
- naabu for approved TCP port inventory.
- httpx/curl for HTTP metadata and redirect checks.
- openssl s_client for TLS handshake/certificate checks.
- dig, RDAP, and inventory scripts for host attribution and deduplication.

## Service Discovery Matrix

| Service class | Useful signal | Follow-up | False positive |
|---|---|---|---|
| Alternate HTTP(S) | HTTP response, TLS certificate, app title | Compare auth/configuration with canonical host | Default proxy page |
| Database | Protocol handshake or service banner | Confirm public exposure and intended access policy without data extraction | Port appears open but firewall blocks protocol |
| Cache/message broker | Protocol fingerprint | Verify whether authentication/network restrictions exist | Generic TCP response |
| Admin/management | Console title or management protocol | Check authorization with controlled account | Public login page alone |
| CI/CD/registry | Build or registry API metadata | Review project visibility and permissions | Intended public artifacts |
| Container/orchestration | API or dashboard signature | Verify authentication and tenant boundary | Version/banner only |
| Object storage | Provider response and bucket metadata | Use dedicated storage skill | Public static content by design |
| Mail/remote access | Protocol greeting and TLS metadata | Review intended exposure and policy | Service is expected for the business |
| Unknown high port | Consistent protocol response | Identify service before further testing | Scanner misclassification |

## Verification and False Positives

- Confirm the port is reachable from the same network position relevant to the finding.
- Repeat a small number of times to exclude transient firewall behavior.
- Use correct SNI and Host values for TLS/HTTP services.
- Treat service banners as hints, not definitive version evidence.
- Avoid high-rate full-range scans unless explicitly allowed; broad scanning is not a substitute for targeted validation.
- Do not infer that all addresses within a hosting provider's ASN belong to the target.


## Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. The validation budget is at most 20 distinct hypotheses per candidate asset; it is not permission for 20 scans or repeated probes. Prefer passive sources first, deduplicate candidates, and use active checks only when the asset and activity are explicitly in scope.

### Evidence record and confidence

For each candidate, preserve normalized asset, source/provenance, observation time, scope proof, resolver/HTTP/tool and relevant version, raw-evidence location, corroborating source, negative control, attribution confidence, next action, and related-skill trigger. Separate **asset confidence** (is it related to the organization?) from **security confidence** (is a vulnerability demonstrated?).

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. C1/C2 are not confirmed vulnerabilities.

### Skill-specific next steps

1. Verify exact host/IP ranges and permitted scan types before starting; treat ASN membership or a discovered address as insufficient authorization.
2. Prefer passive service evidence first, then a narrow TCP/UDP port set with conservative timing, bounded retries, and explicit timeouts. Avoid wide high-rate scans and intrusive scripts.
3. Record open/closed/filtered separately and preserve tool version, flags, target list, timestamp, resolver/source, and rate settings so results can be reproduced.
4. Identify services with safe protocol handshakes or read-only banners; account for proxies, NAT, firewall filtering, rate limits, and shared-provider infrastructure before attributing a service.
5. Stop on instability, rate-limit signals, unexpected sensitive data, or an out-of-scope address. Return a deduplicated service inventory with confidence and a narrow application-specific handoff.


### Deduplication and stop rules

Normalize case, trailing dots, scheme/port, redirects, canonical names and resolved addresses before deduplication. Detect wildcard DNS, shared hosting, CDN/edge responses, soft-404s and stale records before ranking counts. Stop on exclusions, ownership ambiguity, unexpected sensitive data, throttling, instability or boundaries requiring further permission. Never claim ownership or register dangling resources.

### Handoff format

Return candidates with scope/provenance, confidence level, evidence path, deduplication key, negative control, priority rationale, safe next step and trigger for any linked attack skill. Promote a candidate to active testing only after scope and attribution are confirmed; promote it to a finding only after the relevant attack skill verifies the security boundary.

## References

- Source merged: [uphiago/recon-skills — recon/port-service-discovery/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/port-service-discovery/SKILL.md)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
