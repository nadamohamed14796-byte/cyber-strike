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

## References

- Source merged: [uphiago/recon-skills — recon/origin-ip-discovery/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/origin-ip-discovery/SKILL.md)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [RFC 6066: TLS Server Name Indication](https://www.rfc-editor.org/rfc/rfc6066)
