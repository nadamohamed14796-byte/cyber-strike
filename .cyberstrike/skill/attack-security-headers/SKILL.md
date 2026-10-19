---
name: attack-security-headers
description: "Assess HTTP response security headers in browser context and chain missing controls only to demonstrated impact."
category: "web-application"
version: "1.0.0"
author: "CyberStrike contributors"
tags: [http-headers, csp, hsts, cookies, browser-security, cache]
tech_stack: [http, browser, tls, cdn, reverse-proxy]
chains_with: [attack-clickjacking, attack-cors, attack-csrf, attack-host-header, attack-cache-poison, attack-triage-validation]
sources:
  - "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
  - "https://owasp.org/www-project-web-security-testing-guide/"
  - "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"
---

# HTTP Security Headers Assessment

## Objective
Evaluate the effective security policy delivered to the browser, across routes and response types. A missing header is a hardening observation until a relevant browser or protocol behavior demonstrates security impact.

## Workflow
1. Capture response headers for public, authenticated, API, redirect, error, and security-sensitive routes. Record route, status, content type, cache state, and auth context.
2. Determine what policy the browser applies. Inspect CSP directives including default-src, script-src, object-src, base-uri, frame-ancestors, form-action, and upgrade-insecure-requests. Distinguish Report-Only from enforced policies.
3. Review HSTS only on HTTPS responses and verify max-age, includeSubDomains, and preload semantics. Do not claim downgrade impact from an HTTP response alone when other deployment controls enforce HTTPS.
4. Inspect cookies individually for Secure, HttpOnly, SameSite, Path, Domain, expiry, and session rotation. Cookie flags are context-sensitive; document the concrete abuse path before severity.
5. Review MIME sniffing, referrer policy, framing policy, permissions policy, cross-origin isolation/resource policies, and cache directives only where relevant.
6. Compare edge and origin behavior when evidence suggests headers are overwritten, duplicated, stripped, or inconsistently applied. Preserve redirects and route variants; a homepage scan is not full coverage.
7. Connect headers to an actual browser security property: framing a sensitive action, reading a cross-origin response, executing injected content, sending ambient cookies cross-site, or exposing personalized content through a cache.

## Practical header capture
```bash
curl -sS -D response.headers -o /dev/null "$TARGET_URL"
grep -iE '^(content-security-policy|strict-transport-security|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|cross-origin-|cache-control|set-cookie):' response.headers
```
Use only in-scope endpoints. Redact Set-Cookie values before saving or sharing output. This command is a starting point, not a scanner verdict.

## Chaining and impact
- Weak framing policy → controlled clickjacking proof on meaningful authenticated UI.
- CORS policy anomaly → browser proof that a controlled untrusted origin can read sensitive data.
- Host/forwarded-header trust → unsafe absolute URL, redirect, or cache interaction.
- Cookie policy issue → demonstrated CSRF/session exposure under realistic browser conditions.
- Cache directive/key issue → confirmed unauthorized personalized-response reuse.

For every chain, keep observed facts separate from hypotheses. Report actor, browser context, required user action, protected asset, expected policy, actual effect, and evidence. Do not inflate severity because several headers are absent.

## False positives
- CSP Report-Only is counted as enforced.
- A missing legacy header is mitigated by an effective modern policy.
- API or static responses have no relevant browser behavior.
- A cookie belongs to analytics or a non-sensitive feature and is not an authentication credential.
- A scanner flags a header without demonstrating a security boundary failure.

## Output
Return per-route header inventory, enforced versus report-only policy, browser behavior, chain candidates, confirmed impact, sanitized evidence, cleanup, and remediation. Prefer narrowly scoped and compatible policy recommendations over blindly adding headers that break application behavior.


## Targeted quality-loop enrichment (2026-10-19)

### Route-by-route header correlation
Capture headers for the homepage, authenticated profile, sensitive state-changing page, API response, redirect, error route, and file/download response; normalize duplicate headers and record browser context. Evaluate the policy the client actually enforces, not just whether a header string exists. Missing HSTS is not automatically downgrade impact; CSP Report-Only is not enforcement; SameSite and cookie flags must be interpreted with flow context; CORS must be proven in a browser. Chain only along a demonstrated consequence: frameable sensitive interaction → clickjacking; untrusted-origin read → CORS; cross-site state change → CSRF; host-derived link → host-header; shared response contamination → cache poisoning. One absent header should not be inflated into several findings without distinct impacts.

## Advanced test matrix: policy effectiveness, not header presence

Run this matrix on distinct response classes (anonymous page, authenticated page, JSON API, redirect, error, download, and sensitive workflow). Reuse captured requests and change one variable at a time.

| Control | Test | Evidence required before claiming impact | Common chain |
|---|---|---|---|
| CSP | Identify enforced policy, effective script sources, nonce/hash use, and unsafe directives; inspect the exact injection sink if one exists | A reachable execution path that the policy fails to block; a weak policy alone is usually hardening | XSS → CSP bypass analysis; do not claim XSS from CSP alone |
| HSTS | Compare HTTP/HTTPS behavior and relevant host coverage; note first-visit and preload assumptions | A realistic downgrade path in deployment context | Transport weakness → session exposure only if demonstrated |
| Framing | Check enforced frame-ancestors/X-Frame-Options on the sensitive page | Controlled proof frame plus a meaningful user action and realistic victim context | Clickjacking → sensitive action abuse, not mere frameability |
| Cookie flags | Map each cookie to purpose, domain/path, SameSite mode, and rotation behavior | Show how the cookie participates in an actual cross-site or script-accessible attack | CSRF/session weakness → account impact only if the flow supports it |
| Referrer policy | Inspect outgoing navigation from pages carrying sensitive URL state | Sensitive value is sent to an untrusted destination and is usable | Token/secret exposure → session/account impact only after safe validation |
| MIME / nosniff | Compare Content-Type, sniffing behavior, and browser handling for a controllable uploaded/served file | Browser interprets attacker-controlled content in a security-relevant origin/context | Upload/content-type issue → stored XSS only with browser proof |
| Cross-origin isolation/resource policy | Check actual resource loading and isolation requirements | Demonstrated data exposure or security-boundary effect, not header absence | Cross-origin data leak only when independently proven |
| Cache controls | Compare private, authenticated, and anonymous variants through the actual cache layer | A private response is stored/replayed across the wrong context | Cache deception/poisoning with cache evidence |

### Minimal header inventory with redirect visibility

```bash
# Use only an authorized endpoint. -L shows the redirect chain; save headers for review.
curl -sS -L --max-redirs 5 -D header-chain.txt -o /dev/null "$TARGET_URL"
grep -iE '^(HTTP/|location:|content-security-policy(-report-only)?:|strict-transport-security:|x-frame-options:|x-content-type-options:|referrer-policy:|permissions-policy:|cross-origin-(opener|embedder|resource)-policy:|cache-control:|vary:|set-cookie:)' header-chain.txt
```

Review every response block separately: a final response can be secure while an intermediate redirect or error response differs. Do not store live cookie values in notes; replace values with [REDACTED].

### Decision record

For each suspected issue, persist:
- route_class, status, content_type, auth_state, browser, policy_expected, policy_observed, enforced_or_report_only;
- security_property, controlled_prerequisite, reproduction, negative_control, impact_boundary, chain_parent, chain_child;
- evidence_ref, confidence, cleanup, and next_decision.

Use confirmed, disproven, inconclusive, or blocked. Keep one parent observation linked to several distinct findings only when each child has its own independently demonstrated impact. A missing header is not itself an exploit chain.


## Additional header interactions and deployment checks

- Multiple values: inspect duplicate or conflicting CSP, HSTS, CORS, and framing headers as the browser interprets them; do not assume the first or last value wins across every browser/proxy.
- Edge/origin drift: compare the same controlled response through the public edge and approved origin access, if available. Record whether a CDN, gateway, or application layer added or removed the policy; do not bypass access controls to reach an origin.
- CSP nonce lifecycle: verify nonce uniqueness and per-response binding through controlled page loads. A nonce visible in one response is not automatically reusable; only assess execution if an actual controlled injection source exists.
- frame-ancestors vs X-Frame-Options: document modern/legacy browser behavior and effective policy, not just the presence of both.
- CORS headers on errors and redirects: check whether sensitive error bodies or intermediate redirects are readable cross-origin; use synthetic data and browser proof.
- Vary: Origin and cache key: a header difference is only a lead; validate cache separation using two controlled origins and harmless synthetic responses.
- HSTS subdomain coverage: list which in-scope hostnames are HTTPS-capable before recommending includeSubDomains or preload; avoid breaking unrelated hosts.
- Cross-origin isolation: COOP, COEP, and CORP are not interchangeable. Tie each recommendation to the resource-loading or browsing-context property it protects.
- Permissions Policy: evaluate the specific feature and embedding context; absence alone is not proof of sensitive capability exposure.

### Remediation quality gate

For each recommendation, record the affected route class, required browser behavior, compatible policy, deployment layer that owns the header, and regression test. Avoid globally applying a restrictive CSP or HSTS policy without checking legitimate scripts, subdomains, third-party integrations, and rollout requirements.


## Agent-executable CLI tooling, resources, and helper scripts

Use CLI tools and local scripts the agent can invoke directly; browser UI, extensions, and interactive intercepting proxies are not dependencies. Verify official install docs, version, license, platform compatibility, and operational impact before use.

### Recommended tools
- curl — capture response headers and redirect chain
- testssl.sh — TLS configuration review
- Mozilla Observatory CLI/API only when acceptable for the target data
- Python/jq — compare header policy across paths and hosts

### Resources
- https://github.com/drwetter/testssl.sh
- https://observatory.mozilla.org/
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids, not a substitute for reviewing source, release provenance, and supported behavior.

### Helper-script contract
Collect headers from representative paths and authenticated/unauthenticated contexts where permitted. Record missing/misconfigured directives, browser applicability, and concrete impact; avoid treating every missing header as high severity.

Preserve native evidence; normalize to a separate file. Keep source, timestamp, tool/version, error state, confidence, and redaction. Use explicit paths, machine-readable output, and local test fixtures. Never silently treat missing data as a pass.

### Handoff
Return actual commands/tool versions, input/output paths, records checked, failures, confidence, limitations, and next skill. A detected service or misconfiguration is a lead until impact is confirmed.
