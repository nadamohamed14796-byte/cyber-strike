---
name: attack-zimbra
description: "Assess Zimbra collaboration endpoints, version disclosure, SOAP behavior, proxy boundaries, and known-vulnerability prerequisites without user enumeration or unauthorized writes."
category: "infrastructure"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - zimbra
  - soap
  - email
  - ssrf
  - cve
  - admin-console
tech_stack:
  - zimbra-collaboration
  - soap
  - java
  - nginx
  - webmail
cwe_ids:
  - CWE-200
  - CWE-918
  - CWE-22
chains_with:
  - attack-ssrf
  - attack-information-disclosure
  - attack-rce
prerequisites: []
severity_boost:
  attack-ssrf: "A Zimbra proxy issue has SSRF impact only when a controlled callback or harmless approved test service confirms a server-side request."
---

# Zimbra Collaboration Security Assessment

## Objective

Fingerprint a scoped Zimbra deployment, review SOAP and admin surfaces, and validate patch/configuration exposure with minimal non-sensitive evidence. Do not enumerate real users, test passwords, retrieve mail, or write files on production.

## Testing Methodology

### Phase 1: Confirm Zimbra and scope

Confirm the webmail host is in scope and identify UI, SOAP, proxy, upload, download, and admin paths from documentation and normal traffic. Use bounded requests and compare a suspected route to a random nonexistent path.

### Phase 2: Establish version evidence

Inspect headers, published version pages, static assets, and a documented version endpoint if access is intended. A login page or branded asset does not establish an exact version. Cross-check an exact version against current vendor advisories.

### Phase 3: Review SOAP without enumerating users

Use documentation or a vendor test fixture to understand SOAP methods. Avoid a list of candidate usernames or repeated bad-password requests. For an authentication differential, only use synthetic accounts explicitly created for the engagement and the approved request budget.

### Phase 4: Assess proxy and upload boundaries

Review /service/proxy and upload servlet behavior from source/configuration or in a vendor lab. If SSRF testing is explicitly permitted, send one request to a controlled callback endpoint and do not probe internal ports, metadata paths, credentials, or other tenants. Use inert test files in a lab; never attempt path-traversal writes on production.

### Phase 5: Check admin console exposure

Record whether admin routes/ports are reachable and whether they require authentication. A reachable login page alone is not a bypass. Do not attempt default credentials, admin login, mailbox reads, configuration changes, or exploit-specific uploads.

### Phase 6: Validate CVE applicability

For a candidate advisory, record product branch, version, patch level, reachable handler, authentication requirements, reverse-proxy behavior, and any explicit configuration prerequisite. Use a disposable lab reproduction or approved vendor test—not an unsafe payload against the live service.

## What Constitutes a Finding

- **Candidate / lead:** Zimbra fingerprint, older-looking version, SOAP endpoint, proxy route, upload servlet, or exposed admin login.
- **Confirmed finding:** a non-public configuration is exposed, a controlled test flow proves unauthorized access, or a documented affected version and reachable vulnerable code path are validated within scope.
- **Not a finding:** branding alone, SOAP endpoint availability, login page exposure, or HTTP 200 on a route.

## Evidence Requirements

- Exact scoped host/path, timestamp, response headers and sanitized body.
- At least two version signals where possible plus advisory affected/fixed range.
- For SSRF, controlled callback evidence with unique marker; don't include internal network data.
- For authorization, use synthetic accounts/fixtures and state before/after. No mail contents, credentials, hashes, or file data.

## Tools

- **curl:** bounded SOAP/HTTP response checks.
- **Zimbra release notes/security advisories:** confirm patch levels and feature prerequisites.
- **XML/SOAP parser:** inspect synthetic protocol responses offline.
- **Source/config review or isolated lab:** validate proxy/upload handlers safely.

## Zimbra Surface and CVE Matrix

| Surface | Signal | Confirmation requirement |
|---|---|---|
| Version disclosure | Banner, UI asset, version endpoint | Corroborated release/build and current advisory match |
| SOAP | Endpoint responds or method names visible | Authentication/access policy tested using synthetic fixture only |
| Proxy | Parameter suggests target URL | Controlled callback confirms outbound request; no internal scans |
| Upload servlet | Handler reachable | Version and patch evidence; lab confirms traversal or write semantics |
| Admin console | Login page/port reachable | Actual unauthorized control needed; login surface alone isn't a finding |
| User existence differential | Distinct error patterns | Only two engagement-provided synthetic accounts; no user list probing |

**Mitigation:** apply current Zimbra security updates, restrict admin/proxy paths, disable unnecessary endpoints, enforce strong auth, lock down upload directories, and add regression tests for the affected handler.

## Verification and False Positives

- Error messages may differ due to localization, cache, gateway, or input validation rather than account existence.
- Reverse proxies can block an upload path even where a servlet exists; establish actual reachability.
- A proxy endpoint is not SSRF until a controlled server-side request is confirmed.
- Do not attempt file writes, shell uploads, internal target sweeps, default credentials, password guessing, or customer mailbox reads.

## References

- [uphiago/recon-skills — zimbra-attack](https://github.com/uphiago/recon-skills/tree/main/recon/zimbra-attack)
- [Zimbra Security Center](https://www.zimbra.com/security/)
- [NIST National Vulnerability Database](https://nvd.nist.gov/)
