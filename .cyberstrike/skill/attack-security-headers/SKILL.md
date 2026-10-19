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
