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
