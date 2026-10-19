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

- `curl`: bounded endpoint/header checks with explicit timeouts.
- Python `httpx`: compare observed login redirects and response headers without downloading mail content.
- `openssl s_client`: inspect TLS/certificate metadata for the authorized hostname.
- Local NTLM parser: decode only captured challenge metadata offline.
- Microsoft Exchange documentation/security updates: confirm supported builds and fixed cumulative updates.

Verify `curl --version`, the selected Python client, and `openssl version`. Official docs: https://curl.se/docs/, https://www.python-httpx.org/, https://www.openssl.org/docs/, https://learn.microsoft.com/en-us/exchange/.

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


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue materially distinct, authorized checks while evidence can change the conclusion; deduplicate cosmetic variants and exact retries. Stop when direct evidence resolves the hypothesis, meaningful branches are exhausted, prerequisites are unavailable, or scope/safety requires stopping. Never override program rules or production-safety constraints.

Keep a ledger per attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve evidence, redact secrets, and avoid unrelated data.

### Skill-specific hypothesis order

1. Verify product identity and version through an approved, read-only endpoint or reliable deployment evidence, then map OWA/ECP and related authentication entry points that are actually in scope.
2. Compare anonymous, ordinary test-mailbox, and authorized-admin behavior using accounts you control; keep discovery, authentication, and mailbox authorization as separate claims.
3. Prioritize safe configuration signals such as exposed management interfaces, transport/TLS configuration, and unintended information disclosure; correlate with vendor advisories rather than testing an exploit solely because a banner matches.
4. Validate any suspected mailbox access or administrative capability with a synthetic test message/resource only. Do not access employee mailboxes, harvest tokens, or alter tenant settings.
5. Capture evidence and build recommendations around supported versions, patch state, and least-privilege exposure; stop on sensitive mailbox content or a possible service-stability issue.


### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture, with a relevant control and a clear trust-boundary failure.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause is not established.
- **Unconfirmed:** the signal is ambiguous, cached, generic, or not tied to a security boundary.
- **Refuted / false positive:** a relevant negative control, valid authorization explanation, or repeatable contradictory evidence explains the signal. Record the attempts; do not claim every theoretical variant was exhausted.
- Status, banners, stack traces, response length, endpoint existence, tool alerts, or frontend state are not sufficient on their own.

### Stop, cleanup, and handoff

Stop at scope boundaries, unexpected real-user data, production side effects, rate-limit/availability degradation, secret exposure, or prohibited action. Clean up disposable state, revoke temporary sessions/tokens when possible, and record status. Return target/scope evidence, baseline, hypothesis, attempts used, impact, controls, verdict/confidence, sanitized evidence, handoff signal, and cleanup status. Trigger a chained skill only when its signal is observed.

## References

- [uphiago/recon-skills — Exchange OWA attack](https://github.com/uphiago/recon-skills/blob/main/recon/exchange-owa-attack/SKILL.md) — merged service-specific source.

- [uphiago/recon-skills — exchange-owa-attack](https://github.com/uphiago/recon-skills/tree/main/recon/exchange-owa-attack)
- [Microsoft Exchange Server documentation](https://learn.microsoft.com/en-us/exchange/)
- [Microsoft Security Update Guide](https://msrc.microsoft.com/update-guide)


## Targeted quality-loop enrichment (2026-10-19)

### Product/version confidence and exposure boundary
Distinguish Exchange on-premises, Exchange Online, OWA, Autodiscover, hybrid identity, reverse-proxy, and unrelated endpoints by corroborating multiple version/product-specific signals. Public banners, an NTLM challenge, or a reachable OWA route do not establish a vulnerable build or exploitability. Match the exact product/build to current vendor advisories and consider backports and mitigations; use read-only evidence for external bug bounty work and validate exploit behavior only in an isolated lab or under explicit rules. Chain to identity/federation review only when the affected authentication boundary is observed, and to information disclosure only when a sensitive response is directly demonstrated.


## Agent-executable CLI tooling, resources, and helper scripts

Use bounded `curl`/`httpx` checks for the observed authorized host and review Microsoft security updates for build-specific applicability. Keep checks read-only; do not access mailboxes, enumerate users, or attempt credential attacks.

### Resources
- https://learn.microsoft.com/en-us/exchange/
- https://learn.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates
- https://learn.microsoft.com/en-us/security-updates/securitybulletins/securitybulletins
- https://curl.se/docs/

### Evidence
Record hostname, build/version evidence, timestamp, response headers, and source of the version claim. A reachable OWA/ECP endpoint or version banner alone is not a vulnerability.
