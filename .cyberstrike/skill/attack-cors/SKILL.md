---
name: attack-cors
description: "Validate CORS policy, credentialed cross-origin reads, origin trust, and browser-enforced impact"
category: "web-application"
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [cors, web, access-control, origin-validation, browser]
tech_stack: [http, browser, javascript, api]
cwe_ids: [CWE-942, CWE-346]
chains_with: [attack-open-redirect, attack-idor-automation, attack-graphql, attack-triage-validation]
prerequisites:
  - "Authorized in-scope endpoint and permitted browser testing"
  - "Controlled test account and a local proof page"
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-cors/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
  - "https://portswigger.net/web-security/cors"
  - "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing"
---

# CORS Misconfiguration Assessment

## Objective

Determine whether the browser's cross-origin policy allows an untrusted origin to read sensitive responses or perform a meaningful authenticated action. Header anomalies alone are leads, not confirmed vulnerabilities.

## Scope and safety gates

- Verify the endpoint and application are in scope before sending test requests.
- Use only a test account and a local page under your control; do not collect another user's data or send proof pages to real users.
- Never transmit response contents to a third-party collector. Keep proof local and use a harmless marker or synthetic account data.
- Avoid high-volume origin fuzzing. Test one hypothesis at a time and stop if sensitive data from a real account appears.
- Confirm the endpoint and test tooling before relying on any CLI helper; the repository's runtime tool registry is the source of truth.

## Procedure

### 1. Establish a baseline

Capture the endpoint's normal response and the relevant headers, including `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Vary: Origin`, and any preflight response. Record whether authentication is required and whether the response contains sensitive data.

### 2. Test origin trust

Using a harmless GET/read-only request, compare responses for:
- a normal legitimate origin;
- a unique attacker-controlled origin you own;
- a controlled untrusted subdomain;
- the `null` origin only where the application legitimately supports opaque-origin contexts;
- HTTP/HTTPS variants only when relevant to the application.

Inspect whether the server reflects an origin, uses an unsafe substring/prefix/suffix check, or allows a broader origin than intended. Do not infer exploitability from reflection alone.

### 3. Understand browser rules

- `Access-Control-Allow-Origin: *` cannot be used by browsers to expose a credentialed response to JavaScript when credentials are included.
- `Access-Control-Allow-Credentials: true` by itself proves nothing; the response must also authorize the specific origin and the browser must expose the body.
- `Vary: Origin` affects caching correctness but its absence is not automatically exploitable; evaluate the actual cache path separately.
- A preflight response and the actual response have different roles. Verify both when the request is non-simple.
- CORS does not replace server-side authentication or authorization.

### 4. Validate in a real browser

Use a local proof page and a controlled test session. Confirm whether a credentialed cross-origin fetch can read the response body. Keep the body local; demonstrate only a synthetic marker or minimal non-sensitive field. A `curl` response can show headers but cannot prove browser enforcement.

### 5. Test policy edge cases

If the implementation signals these risks, inspect anchored versus unanchored origin matching, unescaped dots in regular expressions, trusted-subdomain assumptions, redirects in the request path, and origin checks in `postMessage` handlers. Do not send CRLF or malformed-origin payloads unless the program explicitly permits that class of testing and the request remains harmless.

### 6. Validate impact and stop

Identify what sensitive data is readable or what security boundary is crossed. If the endpoint returns only public data, or the browser refuses to expose the response, downgrade or close the hypothesis. Stop immediately if proof unexpectedly returns real personal data.

## Findings and confidence

A strong finding includes:
1. the expected origin policy;
2. the exact request origin and redacted response headers;
3. the controlled account and authentication context;
4. a browser-observed readable response;
5. the minimum synthetic data proving sensitivity;
6. a clear impact statement and repeatable steps.

Header reflection alone, `ACAC: true` alone, and wildcard ACAO alone are not enough to claim credentialed CORS data theft. Do not assign a fixed severity from a header pattern; use demonstrated impact and program policy.

## Common false positives

- Wildcard ACAO without credentialed data exposure.
- Reflection of an origin that the browser still rejects.
- Public data incorrectly described as private.
- Testing only with curl and assuming browser behavior.
- A CORS issue claimed where the actual weakness is missing authentication or object-level authorization.

## Output contract

Return: `endpoint`, `origin_tested`, `auth_context`, `acao`, `acac`, `vary_origin`, `preflight_result`, `browser_readable`, `data_sensitivity`, `impact`, `confidence`, and redacted evidence references.


## Minimal request pair and browser proof
Use an origin marker you control and a test account with synthetic data. Start with a read-only endpoint and capture response headers without sharing the body with a third-party collector.

```bash
curl -sS -D cors.headers -o cors.body -H 'Origin: https://origin-marker.invalid' "$TARGET_URL"
grep -iE '^(access-control-allow-origin|access-control-allow-credentials|vary):' cors.headers
```

Then verify in a local browser whether the untrusted origin can actually read the protected response under the intended credential mode. Do not count wildcard Access-Control-Allow-Origin alone as impact. Chain to attack-idor-automation only if the readable data is improperly scoped, to attack-security-headers for broader browser policy review, or to attack-csrf if a separate state-changing request is implicated.


## Enrichment: browser proof
Start with a harmless origin marker on a read-only in-scope endpoint, then inspect Access-Control-Allow-Origin, Access-Control-Allow-Credentials, and Vary. Confirm in a local browser whether an origin you control can read the protected response while using a controlled test account. Do not send the response body to an external collector. A wildcard or reflected origin alone is not impact without browser-enforced access to sensitive data. Link to object-authorization checks only when the returned data is private to another identity or tenant.


## Targeted quality-loop enrichment (2026-10-19)

### Browser-based origin proof
Test a controlled origin in a real browser using a synthetic account and harmless endpoint. Record Origin, Access-Control-Allow-Origin, Access-Control-Allow-Credentials, Vary: Origin, preflight behavior, cookies/SameSite context, and which response bytes JavaScript can actually read. An echoed Origin or wildcard header alone is not a finding; prove that untrusted JavaScript reads a sensitive synthetic value and compare with a trusted-origin control. Evaluate headers on API and session routes, not only the homepage. Chain to CSRF only where a cross-site state change is possible; chain to XSS only if a target-origin script execution path is separately demonstrated. Never use real user sessions or export private records.


## Minimal local browser proof harness

Use a synthetic test account and a read-only endpoint whose response contains only test data. Serve this file locally (or from a controlled origin you own); do not host it publicly or send it to another user. The script reports only the status and a harmless marker field, not the full response body.

```html
<!doctype html>
<meta charset="utf-8">
<title>Controlled CORS validation</title>
<pre id="result">Waiting for a controlled test request…</pre>
<script>
(async () => {
  const endpoint = "https://IN-SCOPE-API.example/api/test-profile";
  const result = document.getElementById("result");
  try {
    const response = await fetch(endpoint, {
      method: "GET",
      credentials: "include",
      mode: "cors"
    });
    result.textContent = JSON.stringify({
      readableByBrowser: true,
      status: response.status,
      contentType: response.headers.get("content-type"),
      // Use only a synthetic field deliberately created for this test.
      syntheticMarker: (await response.json()).syntheticMarker ?? null
    }, null, 2);
  } catch (error) {
    result.textContent = "Browser did not expose the response: " + error.name;
  }
})();
</script>
```

Replace the endpoint with the exact authorized test route and ensure the account contains only synthetic data. The harness is an observation aid, not proof by itself: compare with a trusted-origin control and confirm the returned marker should not be readable from the test origin. Never log or transmit private response bodies.

## Preflight vs actual-request decision table

| Request class | Check | Interpretation |
|---|---|---|
| Simple GET | Actual response ACAO and credential mode | Browser readability is decisive for read exposure |
| Non-simple JSON/custom-header request | OPTIONS preflight and actual response separately | Passing preflight alone does not prove actual response readability |
| Credentialed request | ACAO must be a specific allowed origin and ACAC semantics must permit credentials | Wildcard ACAO does not expose credentialed response to browser JavaScript |
| Cacheable origin-dependent response | Vary: Origin and actual cache behavior | Missing Vary is a lead; confirm cross-origin cache mix-up separately |
| Public endpoint | Compare data sensitivity and auth context | Public data is not sensitive exposure even if readable cross-origin |

Add browser_version, page_origin, credential_mode, preflight_result, actual_response_headers, readable_marker, trusted_origin_control, and cache_context to the evidence record. If the browser blocked reading but the server processed a state change, assess CSRF separately rather than reporting CORS data theft.


## Practical tooling, references, and helper scripts (2026-10-19)

### Tools that fit this skill
- Browser DevTools, Burp Proxy/Repeater/Comparer, and curl for a replay of one observed request. Verify optional CLIs locally and use only tools exposed by the current runtime.
- Treat CLIs as optional until locally verified; prefer read-only checks. State-changing tests require permission and a disposable fixture.

### Primary resources
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — test methodology.
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — controlled labs.
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/) — mitigation guidance.

### Small reusable helper
    python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt
Compares local artifacts offline and heuristically redacts common secrets; it sends no requests and cannot prove complete sanitization.

### Evidence and hand-off
- Keep cookies, tokens, reset links, private user data, and secret values out of notes, global research storage, and Git commits. Keep private originals local; share only reviewed derivatives.
- Mark outcomes confirmed, disproven, or still hypothetical. Record tool errors and coverage gaps rather than inventing results.

Compare a known-good baseline with a control, vary one meaningful property, and record alternative explanations before calling a lead confirmed.


## Agent-executable CLI tooling, resources, and helper scripts

### Agent-usable CLI tools
- `curl`: compare the same observed endpoint with a controlled Origin value and preserve response headers.
- Python `httpx`: repeat a small, authorized request matrix and serialize results for comparison.
- `jq` and `rg`: parse saved JSON/header artifacts and search local source/configuration.
- `python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt`: compare saved responses offline.
### Installation and verification
Verify `curl --version`, `python3 -c "import httpx; print(httpx.__version__)"`, and `jq --version`. Official docs: https://curl.se/docs/, https://www.python-httpx.org/, https://jqlang.org/. If unavailable, use a local fixture or source/configuration review and report the gap.
### Resources
- https://portswigger.net/web-security/cors
- https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
- https://owasp.org/www-project-web-security-testing-guide/
### Proof and limits
Record the exact Origin, ACAO/ACAC headers, credential context, and whether a browser-enforced cross-origin read is actually possible. A wildcard or reflected Origin alone is not automatically exploitable.

## Agent-executable CLI tooling, resources, and helper scripts

This section lists command-line tools and local scripts the agent can invoke. Browser interfaces, browser extensions, and interactive intercepting proxies are not dependencies. Verify availability, version, official documentation, license, and expected request impact before use.

### Recommended tools
- curl — baseline CORS header capture
- Python requests/httpx — compare Origin values with controls
- jq — parse captured headers/JSON
- A local origin-matrix generator for null, same-site, and controlled external origins

### Resources
- https://portswigger.net/web-security/cors
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids only; consult official docs for supported usage and limitations.

### Helper-script contract
Record Origin, Access-Control-Allow-Origin/Credentials, preflight result, authenticated context, and whether browser-readable sensitive data is actually exposed. Wildcard headers without sensitive response access are not sufficient proof.

Use explicit inputs and outputs, preserve native evidence separately from normalized data, record tool/version and timestamps, redact sensitive values, handle malformed records, and include local test fixtures. Do not claim a vulnerability from a scanner signal alone.

### Handoff
Return command/tool/version, baseline and variant references, output path, controls, errors, confidence, limitations, and next skill. Missing tools and blocked tests are explicit statuses.
