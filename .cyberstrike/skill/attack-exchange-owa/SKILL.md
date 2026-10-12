---
name: attack-exchange-owa
description: "Assess Microsoft Exchange and Outlook on the web exposure through bounded endpoint fingerprinting, NTLM challenge metadata, autodiscover configuration, and patch validation."
category: "infrastructure"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - exchange
  - owa
  - ntlm
  - autodiscover
  - email
  - identity
tech_stack:
  - microsoft-exchange
  - owa
  - ews
  - ntlm
  - adfs
  - microsoft-365
cwe_ids:
  - CWE-200
  - CWE-209
  - CWE-693
chains_with:
  - attack-ntlm-info
  - attack-saml-sso
  - attack-oauth
prerequisites: []
severity_boost:
  attack-ntlm-info: "NTLM metadata can increase infrastructure exposure context, but domain disclosure is not credential compromise or authentication bypass."
---

# Exchange and OWA Exposure Assessment

## Objective

Map a scoped Exchange/OWA deployment, validate version and protocol metadata, and identify configuration disclosure without password spraying, NTLM relay, or access to real mailboxes.

## Testing Methodology

### Phase 1: Confirm target ownership and role

Verify the specific OWA/mail/autodiscover hosts are in scope. Start with low-rate HEAD/GET requests to documented routes and record redirects and TLS. A mail-like hostname or Exchange-themed login page is only a lead.

### Phase 2: Fingerprint endpoints and versions

Inspect OWA/ECP, EWS, Autodiscover, MAPI, ActiveSync, and health-check paths using a small fixed list and bounded timeouts. Record status, content type, and selected response headers; don't enumerate arbitrary paths or neighboring hosts. Treat product/CU inference as provisional until cross-checked with vendor release documentation.

### Phase 3: Inspect NTLM challenge metadata

Where the endpoint naturally issues a Negotiate/NTLM challenge or the program permits one handshake, capture the challenge and decode only non-secret target-info fields such as NetBIOS/DNS domain and host. Do not perform password guessing, relay, coercion, or repeated auth attempts.

### Phase 4: Review Autodiscover and hybrid identity

Use a documented test mailbox only if explicitly provided. Compare external versus expected response fields and inspect whether internal server names, tenant identifiers, or unsafe redirects are exposed. Avoid supplying real users' addresses or enumerating mailbox existence.

### Phase 5: Assess patch and authentication posture

Match confirmed build/CU to current Microsoft security guidance and the engagement's approved configuration baseline. Review modern authentication, legacy/basic auth policy, and external admin route exposure from documentation/configuration. Do not infer vulnerability from a visible login or unsupported version string alone.

### Phase 6: Validate minimum impact and stop

Confirm whether metadata is genuinely non-public and security-relevant. Stop at disclosed host/domain/version evidence; do not use real credentials, test lockout thresholds, query mail, access ECP as another identity, or relay NTLM.

## What Constitutes a Finding

- **Candidate / lead:** Exchange fingerprint, NTLM challenge, version header, open ECP route, or internal hostname in Autodiscover response.
- **Confirmed finding:** a non-public configuration detail is exposed beyond policy, or a current advisory's affected configuration is confirmed by version and reachable preconditions.
- **Not a finding:** a normal OWA login page, standard public autodiscover metadata, or NTLM challenge existence alone.

## Evidence Requirements

- Scoped hostname, route, timestamp, TLS context, status, and sanitized headers/body.
- Exact build/version signal and authoritative advisory/version range.
- Redacted NTLM target-info fields; do not preserve credential responses or hashes.
- For Autodiscover, note whether the test mailbox was synthetic and which fields exceed expected public metadata.

## Tools

- **curl:** bounded endpoint/header checks.
- **Microsoft Exchange documentation/security updates:** confirm supported builds and fixed CUs.
- **NTLM parser:** decode only captured challenge metadata offline.
- **Browser/OWA test account:** verify login redirects without touching real mail.

## Exchange Surface and Evidence Matrix

| Surface | Candidate signal | Evidence needed |
|---|---|---|
| OWA/ECP | Login or admin route reachable | Is it intended public entry, and is protected content exposed? |
| EWS/MAPI/ActiveSync | Protocol route returns expected challenge | Confirm authentication policy and supported configuration |
| NTLM challenge | WWW-Authenticate indicates NTLM/Negotiate | Decode domain/host metadata; no secret/hash exploitation |
| Autodiscover | XML/JSON mentions endpoints | Distinguish normal public URLs from unintended internal details |
| Version/CU | Header or error fingerprints a build | Cross-check a current vendor advisory and exact prerequisites |
| Hybrid ADFS/M365 | Redirect to federation/tenant login | Treat IdP as separate asset; verify scope before testing it |

**Mitigation:** patch to a supported CU/SU, disable unused legacy authentication, restrict admin endpoints, minimize unnecessary NTLM, reduce metadata disclosure, and regression-test external routes.

## Verification and False Positives

- Proxies/CDNs can rewrite server headers or strip authentication challenges.
- Product version may be hidden, stale, or backported; corroborate against documentation.
- NTLM Type-2 target info discloses metadata, not a password or a reusable credential.
- A 401/403 route is often the intended protection; don't label it vulnerable.
- No spraying, credential stuffing, relay, coercion, mailbox access, or high-rate lockout testing in this skill.

## References

- [uphiago/recon-skills — Exchange OWA attack](https://github.com/uphiago/recon-skills/blob/main/recon/exchange-owa-attack/SKILL.md) — merged service-specific source.

- [uphiago/recon-skills — exchange-owa-attack](https://github.com/uphiago/recon-skills/tree/main/recon/exchange-owa-attack)
- [Microsoft Exchange Server documentation](https://learn.microsoft.com/en-us/exchange/)
- [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide)
