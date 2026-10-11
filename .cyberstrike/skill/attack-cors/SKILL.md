---
name: attack-cors
description: "Test CORS origin trust and credentialed cross-origin reads; confirm browser-enforced impact before reporting"
category: "web-application"
version: "1.1.0"
author: "cyberstrike-official"
tags:
  - cors
  - web
  - owasp
  - access-control
  - attack
tech_stack:
  - web
cwe_ids:
  - CWE-942
  - CWE-346
chains_with:
  - attack-open-redirect
  - attack-idor-automation
prerequisites: []
severity_boost:
  attack-open-redirect: "CORS + open redirect = token theft via cross-origin request"
---

# CORS Misconfiguration Attack

## Objective

Identify Cross-Origin Resource Sharing misconfigurations that allow unauthorized cross-origin access to sensitive data or APIs.

## Testing Methodology

### Phase 1: Origin Reflection Detection

Test if the server reflects arbitrary origins in `Access-Control-Allow-Origin`:

```bash
# Automated CORS checker (bundled script)
attack_script cors_checker https://TARGET/api/endpoint --json-output
```

Manual tests:

```bash
# Arbitrary origin
curl --max-time 15 --connect-timeout 5 -s -H "Origin: https://evil.com" TARGET_URL -D- | grep -i "access-control"

# Subdomain bypass
curl --max-time 15 --connect-timeout 5 -s -H "Origin: https://TARGET.evil.com" TARGET_URL -D-

# Null origin
curl --max-time 15 --connect-timeout 5 -s -H "Origin: null" TARGET_URL -D-

# HTTP downgrade
curl --max-time 15 --connect-timeout 5 -s -H "Origin: http://TARGET" TARGET_URL -D-
```

### Phase 2: Bypass Techniques

```bash
# Backtick bypass
curl --max-time 15 --connect-timeout 5 -s -H "Origin: https://TARGET%60.evil.com" TARGET_URL -D-

# Underscore bypass
curl --max-time 15 --connect-timeout 5 -s -H "Origin: https://TARGET_.evil.com" TARGET_URL -D-

# CRLF injection
curl --max-time 15 --connect-timeout 5 -s -H "Origin: https://evil.com%0d%0a" TARGET_URL -D-

# Prefix matching bypass
curl --max-time 15 --connect-timeout 5 -s -H "Origin: https://evil-TARGET" TARGET_URL -D-
```

### Phase 3: Impact Verification

A reflected `Access-Control-Allow-Origin` value is not enough. Use an authorized test account with a harmless marker in the response and confirm that a real browser can read it cross-origin.

```html
<!-- Serve this only from a controlled test origin and use your own test account. -->
<pre id="result">Testing…</pre>
<script>
fetch('https://TARGET/api/test-profile', { credentials: 'include' })
  .then(async (r) => {
    const body = await r.text();
    document.querySelector('#result').textContent =
      'Credentialed CORS read succeeded; test marker present: ' +
      body.includes('MY_CORS_TEST_MARKER');
  })
  .catch(() => {
    document.querySelector('#result').textContent =
      'Browser blocked the cross-origin read.';
  });
</script>
```

Use a dedicated test endpoint or a record you created yourself. Do not transmit real user data to an external collector. Capture the response headers and the browser result; redact session cookies and any personal data.

## What Constitutes a Finding

| Condition | Severity |
|-----------|----------|
| Reflected/untrusted origin + ACAC true + browser can read sensitive test-account data | Severity depends on data sensitivity and affected users; often High, not automatically Critical |
| `null` origin trusted + credentials + demonstrated sensitive-data read | Severity depends on the reachable sandboxed/null-origin attacker scenario |
| Subdomain origin trusted via unsafe suffix/prefix matching + credentialed data read | Severity depends on trust boundary and data exposed |
| `Access-Control-Allow-Origin: *` on a credentialed request | Normally blocked by browsers when credentials are included; not a finding without a separate demonstrated impact |
| ACAO reflects an origin but ACAC is absent/false, or browser cannot read the response | Usually not a credentialed data-exposure finding |
| Public, non-sensitive response readable cross-origin | Usually informational unless another concrete impact is shown |

## Evidence Requirements

- Request with attacker `Origin` header
- Response showing `Access-Control-Allow-Origin` reflection
- Response showing `Access-Control-Allow-Credentials: true`
- PoC HTML demonstrating cross-origin data access

## Tools

- `attack_script cors_checker` — automated multi-origin testing
- `curl` — manual header injection
- Browser DevTools — verify CORS behavior

## Endpoint and Role Coverage Matrix

Do not test only one convenient API route. Build a small matrix of in-scope endpoints and the roles you control, then test each route with: no `Origin`, a trusted origin, a unique untrusted origin, and—only where relevant—a `null` origin. Keep request volume low and use the same harmless test record for comparisons.

- Test read-only endpoints first; include user-specific or tenant-specific routes only with accounts and records you control.
- Inspect preflight (`OPTIONS`) behavior separately from the actual request. A permissive preflight response does not prove that the browser can complete the request or read the response.
- Confirm the browser can read a sensitive, test-owned response with credentials before claiming credentialed CORS impact. Do not infer impact from headers alone or from `curl` output.
- Check `Vary: Origin` and cache behavior when the ACAO value changes across origins. If a shared-cache variant is involved, refer to the local `attack-cache-poison` skill only after the shared response behavior is reproduced.

## Verification and False Positives

- Confirm both `Access-Control-Allow-Origin` (ACAO) trust and `Access-Control-Allow-Credentials: true` (ACAC) when claiming credentialed data exposure.
- Verify in a real browser using credentials from an account you control. `curl` ignores browser CORS enforcement and cannot prove that JavaScript can read the response.
- A wildcard ACAO value combined with credentials is rejected by conforming browsers; do not report it as exploitable without a demonstrated browser-readable path.
- Check whether the endpoint returns sensitive, user-specific data. A reflected origin on a public endpoint does not automatically create a vulnerability.
- Verify whether `Origin` is correctly included in the cache variation when responses differ by origin. If the issue is shared-cache mixing, link to `attack-cache-poison` only when cache impact is demonstrated.
- Do not rely on malformed Origin values or CRLF-looking strings as proof. Confirm the server accepted the value and that the browser security boundary is actually crossed.

## Reproducible Test Matrix and Triage

Test each relevant endpoint across these dimensions, changing one variable at a time:

| Dimension | Cases to compare | What to record |
|---|---|---|
| Origin | absent, exact allowed origin, untrusted origin, null where relevant | Access-Control-Allow-Origin |
| Credentials | credentialed request vs non-credentialed request | Access-Control-Allow-Credentials and browser behavior |
| Preflight | simple request, preflighted method/header | OPTIONS status and allow-method/header values |
| Identity | anonymous, user A, user B with separate test accounts | Whether protected response data is readable cross-origin |
| Cache | unique test URL, then normal repeat | Vary: Origin and whether one origin's response is reused for another |

A permissive header alone is not enough. Demonstrate that a browser-origin security boundary is crossed and that meaningful response data is readable by an untrusted origin. Use synthetic data and a controlled test origin; do not collect another user's data.

For every report, include the exact request origin, endpoint, authentication state, browser-relevant response headers, sanitized response body, and a minimal reproduction. Distinguish credentialed data exposure from public unauthenticated data, and note whether the endpoint contains sensitive user-specific content.

## References

- [uphiago/recon-skills — CORS hunting](https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-cors/SKILL.md) (external research reference; not a local Cyber Strike skill path).
- [elementalsouls/Claude-BugHunter — CORS hunting](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-cors/SKILL.md) (external research reference; not a local Cyber Strike skill path).

- [PortSwigger: CORS](https://portswigger.net/web-security/cors)
- [OWASP: CORS Misconfiguration](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
