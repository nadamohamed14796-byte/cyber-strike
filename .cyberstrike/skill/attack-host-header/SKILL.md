---
name: attack-host-header
description: "Assess Host and forwarded-host trust for absolute URL generation, routing, redirect, and cache boundaries using controlled test domains and identities."
category: "web-application"
version: "1.3.0"
author: "cyberstrike-official"
tags:
  - host-header
  - forwarded-host
  - web
  - routing
  - cache
tech_stack:
  - web
  - http
  - reverse-proxy
  - cdn
cwe_ids:
  - CWE-644
  - CWE-346
  - CWE-601
chains_with:
  - attack-cache-poison
  - attack-open-redirect
  - attack-information-disclosure
prerequisites: []
severity_boost:
  attack-cache-poison: "Host-derived values raise impact only when a harmless altered response is stored in a shared cache and served to a clean test client."
---

# Host Header and Forwarded-Host Trust Assessment

## Objective

Determine whether an application or intermediary trusts client-controlled Host-related headers for security-sensitive decisions such as absolute URL generation, routing, redirects, cache variation, or origin checks. Use a hostname you control and accounts you own. A reflected hostname or a changed status code is only a lead, not proof of impact.

Authorization is governed by the engagement scope and the library's central scope policy. Use controlled accounts/domains for account-flow checks; retain only sanitized evidence. The workflow below is not restricted to labs when the target and test class are expressly authorized.

## Testing Methodology

### Phase 1: Map trust boundaries and establish a baseline

Identify the front door (CDN/load balancer/reverse proxy), canonical host, origin behavior visible within scope, and relevant endpoints. Capture one normal request and record the Location header, absolute links, response body hash, cache headers, and any request-ID metadata.

Check whether the application is behind a proxy and whether documentation specifies trusted forwarded headers. Do not assume that X-Forwarded-Host or X-Host is trusted just because it is accepted by the HTTP parser.

### Phase 2: Enumerate Host-derived sinks and test trust assumptions

Inventory sinks including absolute URL generation, canonical links, redirects, password-reset and invitation links, tenant routing, origin checks, cache variation, CSP/reporting URLs, and proxy-generated error pages. Change one authority-related input at a time (Host, Forwarded host, X-Forwarded-Host, X-Host, X-Forwarded-Server) and compare the exact sink against a baseline. Record which layer consumes each header; acceptance by the HTTP parser does not mean the application trusts it.

A value that appears only in an error message or in a body reflecting the original request is not enough. Inspect HTML/JSON context, Location, absolute URL, and cache behavior separately.

### Phase 3: Verify password-reset and notification URL construction

Perform this only when the program permits auth-flow testing and only with a test account/inbox you control. Request one reset or verification message and inspect the delivered link. Verify whether the generated hostname comes from an untrusted header or from a trusted canonical configuration.

Do not submit reset requests for real users, change a real account's recovery email, forward live tokens, or redeem a token after changing state beyond the test account. If the host is wrong but the token is still scoped to a controlled test account, redact the token completely in retained evidence.

### Phase 4: Compare proxy-header precedence, normalization, and routing

Compare canonical Host handling with one forwarded header at a time and test precedence when multiple trusted-proxy headers are present. Where the application exposes a documented route, compare normalization of case, trailing dots, ports, IDNA/punycode hostnames, comma-separated Forwarded values, and conflicting proxy headers. Confirm the backend selected and the security decision affected; do not infer a bypass from status codes alone.

For path-rewrite headers such as X-Original-URL or X-Rewrite-URL, use only an approved benign test path and verify policy before probing. A proxy's 404/403/200 difference is not confirmation unless the expected handler and authorization boundary are independently demonstrated.

### Phase 5: Assess shared-cache interactions separately

If the altered host-derived response may be cached, coordinate with the attack-cache-poison skill. Start with a unique throwaway URL or an approved cache-test key and a harmless marker. Send one altered request, then repeat the exact request without the altered header from a clean test client. Capture cache HIT/MISS/Age evidence and stop immediately after the minimal controlled proof.

Never poison a homepage, login/reset route, static asset used by real users, or any shared high-traffic URL. Do not create a persistent entry or repeatedly refresh/re-poison production content.

### Phase 6: Assess authority parsing and protocol edge cases

If evidence suggests a front proxy and origin disagree about authority, compare documented parser behavior across client, edge, and origin. Review absolute-form request-target handling, duplicate/conflicting Host values, unusual ports, malformed authority syntax, and HTTP/2-to-HTTP/1 translation where supported. Use a dedicated test route and connection for live validation; if the request could affect unrelated traffic, reproduce the parser discrepancy in an isolated harness.

### Phase 7: Confirm root cause and remediation

Trace which value controls URL generation, routing, redirects, cache keys, or origin validation. Recommend a canonical host allowlist, validated proxy trust configuration, and rejection of inconsistent authority values. Add regression checks for normal Host, untrusted forwarded-host, and invalid canonical host cases.

## What Constitutes a Finding

- **Candidate / lead:** a Host-related value is reflected, a redirect changes, or a service responds differently to a forwarded header.
- **Confirmed URL-poisoning issue:** a reset/verification URL sent to a tester-owned inbox contains an attacker-controlled host contrary to the intended policy.
- **Confirmed routing/access issue:** a controlled request reaches an unintended in-scope handler and demonstrates an authorization or data boundary failure.
- **Confirmed cache issue:** a clean test client receives a harmless altered response stored by a shared cache without the injected input.
- **Not a finding:** reflection alone, a normal 401/403, a public redirect by design, or a changed status without confirmed handler/impact.

## Evidence Requirements

- Canonical baseline and one-header-at-a-time modified request, with cookies/tokens redacted.
- Exact route, method, timestamp, and sanitized response/Location header.
- For reset/verification URLs, evidence from a test inbox with the token and any personal data fully redacted.
- For routing, evidence of the intended versus actual handler and a harmless controlled outcome.
- For cache behavior, cache status and exact clean-request reproduction from a second tester-controlled session.
- Identify whether validation was in an isolated lab or authorized production test; state unverified impact honestly.

## Tools

- **Burp Repeater / curl:** controlled one-variable header comparison on an approved endpoint.
- **Browser / test mailbox:** verify generated links and redirects without sharing tokens.
- **Reverse-proxy configuration review:** identify trusted forwarded headers and canonical-host settings.
- [**attack-cache-poison**](../attack-cache-poison/SKILL.md): assess whether a Host-derived response is stored and served from a shared cache.
- [**attack-open-redirect**](../attack-open-redirect/SKILL.md): validate redirect behavior separately, then link it to cache impact only if a clean request receives the cached altered response.
- [**attack-information-disclosure**](../attack-information-disclosure/SKILL.md): assess independently whether Host-derived URLs or routing expose sensitive information.
- **Local proxy/origin lab:** reproduce ambiguous authority parsing and duplicate-header behavior safely.

## Host Trust-Boundary Matrix

| Sink | Safe test | Confirmation threshold |
|---|---|---|
| Absolute URL generation | Owned test route and controlled hostname | Generated canonical URL uses an untrusted host in a security-sensitive context |
| Password-reset/verification link | Test account and owned inbox | Delivered link uses attacker-controlled host; token stays redacted |
| Redirect | Harmless in-scope route | Redirect target changes contrary to allowlist/policy and has meaningful impact |
| Cache | Unique approved test URL plus clean client | Shared cached response persists without injected header |
| Virtual-host routing | Local/test proxy or approved route | Wrong in-scope backend/handler reached and security boundary crossed |
| Origin/security checks | Controlled request in a test flow | Trusted-origin decision changes and permits an unauthorized test action |
| Duplicate Host/absolute-form | Isolated proxy/origin lab | Parser disagreement reproducible without involving unrelated users |

## Verification and False Positives

- Proxies and CDNs may strip or rewrite Host-related headers before the application sees them; identify the layer responsible.
- The application may intentionally use a trusted canonical host rather than the incoming header.
- A response that echoes a hostname, an email-sent confirmation, or a status-code change alone does not demonstrate link poisoning or access bypass.
- Cache headers and shared-cache behavior belong to a separate validation step; an origin-only reflection is not poisoning.
- Do not use real-user account recovery, deliver active credentials, or test internal/third-party routing outside the declared scope. For cache interactions, use the dedicated cache skill and an approved test key.

## Related Skills and Chains

- [`attack-cache-poison`](../attack-cache-poison/SKILL.md) — test shared-cache persistence of Host-derived response changes; a changed first response alone is not enough.
- [`attack-open-redirect`](../attack-open-redirect/SKILL.md) — validate attacker-controlled redirect destinations independently from Host-header trust.
- [`attack-information-disclosure`](../attack-information-disclosure/SKILL.md) — follow up only when the Host trust issue exposes sensitive data or internal routing details.


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Treat the attempt budget as a ceiling for independent, evidence-producing hypotheses, not a payload quota. If the candidate remains plausible, follow the next signal-led branch up to 20 distinct hypotheses; stop sooner when impact is decisive, no relevant branch remains, or scope/safety limits apply. Cosmetic encodings of the same request do not count as separate attempts.

Maintain an attempt ledger: hypothesis, single changed variable, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer controlled identities, synthetic resources and paired requests. Preserve sanitized evidence and minimize data collected.

### Skill-specific hypothesis order

Select distinct, low-impact branches from the skill's existing coverage matrix and do not repeat equivalent probes.

### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture and a relevant control.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause remains uncertain.
- **Unconfirmed:** response is ambiguous, cached, generic, or not linked to a security boundary.
- **Refuted / false positive:** an applicable negative control or valid policy explanation accounts for the signal. Record the attempt ledger rather than claiming every theoretical variant was exhausted.
- A 2xx status, error difference, header, schema/documentation exposure, scanner alert, or UI-only state is not proof by itself.

### Stop, cleanup, and handoff

Stop on scope ambiguity, unexpected real-user data, unexpected production state changes, service degradation, credential exposure, or a prohibited action. Restore disposable state and revoke temporary tokens/sessions where possible. Handoff target and scope proof, baseline, hypothesis, attempts used, impact, negative controls, verdict/confidence, sanitized evidence pointers, linked-skill signal, and cleanup status. Invoke a related skill only when its triggering signal is observed.

## References

- [uphiago/recon-skills — HTTP/2 header impersonation](https://github.com/uphiago/recon-skills/blob/main/recon/http2-header-impersonation/SKILL.md) — merged protocol/header trust analysis.

- [uphiago/recon-skills — hunt-host-header](https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-host-header/SKILL.md) — merged source.
- [elementalsouls/Claude-BugHunter — hunt-host-header](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-host-header/SKILL.md) — merged source.

- [PortSwigger: Host Header Attacks](https://portswigger.net/web-security/host-header)
- [OWASP WSTG: Testing for Host Header Injection](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/07-Injection/17-Host_Header_Injection/)
- [RFC 9110: HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html)
