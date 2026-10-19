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

## Public bug-bounty boundary
Treat groupware and mail systems as high-impact services. Confirm explicit product ownership and engagement rules before any active request; default to passive version/configuration review and harmless read-only checks. Do not enumerate mailboxes, access messages, alter accounts, upload files, attempt persistence, or validate exploit payloads on production. Version banners are not a confirmed CVE; check exact build, mitigation/backport state, reachable component, and safe proof criteria. Use an isolated lab for exploit validation, redact tenant/mail identifiers, and stop at minimum sufficient evidence.


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

- `curl`: bounded SOAP/HTTP response checks with explicit timeouts.
- XML/SOAP parser: inspect synthetic protocol responses offline.
- Vendor release notes/security advisories: confirm patch levels and feature prerequisites.
- Source/config review or isolated lab: validate handlers without production state changes.

Verify `curl --version`. Official docs: https://curl.se/docs/, https://wiki.zimbra.com/wiki/Security_Center, https://www.zimbra.com/downloads/.

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


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful, authorized read-only hypotheses. Continue while a distinct check can change the conclusion; deduplicate equivalent requests and stop when evidence resolves the question, relevant branches are exhausted, prerequisites are unavailable, or scope/safety requires stopping. Do not test credentials, access mail, or invoke exploit payloads on production.

Track each attempt as hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired requests and controlled test identities/fixtures; save only minimal sanitized evidence.

### Skill-specific hypothesis order

1. Confirm the in-scope Zimbra deployment and exact version/build using read-only evidence; keep product identification separate from exploitability.
2. Map public login/webmail/admin surfaces and compare anonymous, regular test-user, and authorized-admin behavior using mailboxes you control.
3. Check supported version against current vendor advisories and the exposed preconditions; do not run public exploit scripts or invoke file/command endpoints on a live deployment to validate a version match.
4. Validate suspected disclosure with a synthetic test message or harmless account setting only when the program permits it; never access real mailboxes or export private mail.
5. Record exact asset/version confidence, route, demonstrated impact and remediation path. Stop on unexpected mailbox/credential exposure or stability issues.


### Verdict gates

- **Confirmed:** repeatable impact at an explicit in-scope boundary is demonstrated using a controlled identity/fixture and a meaningful control.
- **Likely / needs corroboration:** independent indicators support the candidate, but the consequence or root cause remains uncertain.
- **Unconfirmed:** evidence is generic, ambiguous, cached, or not tied to a security property.
- **Refuted / false positive:** a relevant negative control or valid implementation/policy explanation accounts for the observation. Document tested branches; do not claim all imaginable variants were exhausted.
- Scanner alerts, version strings, banner text, status codes, and response length alone are not proof.

### Stop, cleanup, and handoff

Stop on scope ambiguity, unexpected user data, state changes, service degradation, secret exposure or prohibited behavior. Clean disposable test state and revoke temporary sessions/tokens where possible. Return scope proof, baseline, hypothesis, attempts used, impact, negative controls, verdict/confidence, sanitized evidence and cleanup status. Start a chained skill only when its trigger has been independently observed.

## References

- [uphiago/recon-skills — Zimbra attack surface](https://github.com/uphiago/recon-skills/blob/main/recon/zimbra-attack/SKILL.md) — merged service-specific source.

- [uphiago/recon-skills — zimbra-attack](https://github.com/uphiago/recon-skills/tree/main/recon/zimbra-attack)
- [Zimbra Security Center](https://www.zimbra.com/security/)
- [NIST National Vulnerability Database](https://nvd.nist.gov/)


## Product/version and SOAP evidence ledger

For a Zimbra candidate, record the product family, build evidence, affected advisory, reverse-proxy path, authentication requirement, and whether the relevant handler is actually reachable. Keep unknowns explicit rather than converting version similarity into exploitability.

| Evidence | Safe collection | Not sufficient alone |
|---|---|---|
| UI/static assets | Response headers and asset metadata | Branding or asset name |
| Version/build | Read-only documented endpoint or owner-provided config | One generic banner |
| SOAP surface | Normal traffic or docs; parse synthetic responses locally | Endpoint responds |
| Proxy behavior | One controlled callback only if explicitly authorized | URL parameter exists |
| Upload handler | Source/config review or isolated vendor lab | Route name or status code |
| Admin surface | Login page/access-control metadata | Login page implies admin access |

### Safe response capture

```bash
curl -sS --max-time 6 -D zimbra.headers -o /dev/null "$IN_SCOPE_ZIMBRA_URL"
grep -iE '^(HTTP/|content-type:|location:|server:|www-authenticate:)' zimbra.headers
```

Do not save SOAP bodies containing mailbox, user, or authentication data. If protocol structure must be inspected, use a synthetic lab fixture and retain only the fields needed to establish the behavior.

Record product_build_sources, vendor_advisory, affected_range, fixed_build, handler_path, auth_requirement, proxy_path, validation_environment, callback_evidence_if_permitted, and cleanup_status. Keep production exploitability unconfirmed when only version/build evidence is available.
