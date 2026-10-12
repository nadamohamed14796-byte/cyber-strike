---
name: attack-cache-poison
description: "Web cache poisoning and Web Cache Deception — validate unkeyed inputs, cache-key discrepancies, and exposure of private responses through shared caches"
category: "web-application"
version: "1.3.0"
author: "cyberstrike-official"
tags:
  - cache-poisoning
  - web
  - xss
  - attack
tech_stack:
  - web
cwe_ids:
  - CWE-444
  - CWE-525
chains_with:
  - attack-host-header
  - attack-open-redirect
  - attack-request-smuggling
  - attack-cors
  - wstg-inpv-02
  - wstg-clnt-01
prerequisites: []
severity_boost:
  attack-host-header: "Host/X-Forwarded-Host injection stored in a shared cache can turn a reflection or redirect into cross-user impact."
  attack-request-smuggling: "A confirmed proxy parsing discrepancy can affect shared cache responses; validate the desynchronization and cache impact independently."
  wstg-inpv-02: "Cache poisoning can amplify an injection into stored XSS only when the poisoned response is shared and executable."
---

# Web Cache Poisoning

## Objective

Assess two distinct cache flaws without conflating them: (1) Web Cache Poisoning (WCP), where an unkeyed input changes a shared cached response; and (2) Web Cache Deception (WCD), where URL/path handling causes a shared cache to store a sensitive response as if it were static. Prove the relevant cache behavior and security impact independently.

Authorization is governed by the engagement scope and the library's central scope policy. The methods below cover cache behavior on real targets when that testing class is permitted; use a unique test key, controlled marker, and clean test client to isolate the result.

## Crown Jewel Targets

- Shared CDN/edge caches serving JavaScript, CSS, downloadable assets, or tenant-specific content.
- Account, authentication, password-reset, and API routes that may be incorrectly marked public/cacheable.
- Multi-tenant SaaS routes where tenant identity or authorization context may be missing from the cache key.
- Redirect, canonical-link, CSP, metadata, and affiliate/referral responses influenced by request headers or parameters.
- Static-looking URLs routed to dynamic handlers, such as account pages with a `.css` or `.jpg` suffix.

## Attack Surface Signals

Cache signals include `X-Cache`, `X-Cache-Status`, `CF-Cache-Status`, `Age`, `Via`, `Surrogate-Control`, `Cache-Control: public`, and `X-Served-By`. These indicate a possible cache layer but do not prove that an attacker-controlled response is shared. Identify browser, service-worker, reverse-proxy, CDN, and origin cache layers separately; note cache key dimensions, default TTL, revalidation behavior, and whether authenticated and anonymous traffic share a cache namespace.

Candidate inputs include `Host`, `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `Forwarded`, `X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override`, `True-Client-IP`, and `Origin`. Test one input at a time; reflection alone does not establish that it is unkeyed.

## Testing Methodology

### Phase 1: Identify Cache Behavior

```bash
# Check cache headers
curl --max-time 15 --connect-timeout 5 -s -D- https://TARGET/ | grep -i "x-cache\|age\|cache-control\|cf-cache\|x-varnish"

# Identify cache key components (vary header)
curl --max-time 15 --connect-timeout 5 -s -D- https://TARGET/ | grep -i "vary"
```

### Phase 2: Check Candidate Inputs with a Unique Canary

Do not probe a normal shared URL with attacker-controlled headers as the first test. Use an in-scope, non-critical endpoint and a unique throwaway cache key for every candidate. Use a harmless marker, not executable JavaScript or a real external hostname.

```bash
# Example: use a unique cache-busting key and a reserved .invalid marker
curl --max-time 10 --connect-timeout 5 -s -D- \
  -H 'X-Forwarded-Host: cyberstrike-canary.invalid' \
  'https://TARGET/test-page?cb=UNIQUE_VALUE'

# Repeat the exact URL without the candidate header
curl --max-time 10 --connect-timeout 5 -s -D- \
  'https://TARGET/test-page?cb=UNIQUE_VALUE'
```

Check whether the response changes and whether a later clean request receives the marker. If there is no shared-cache evidence, stop and record the candidate as unconfirmed. Never test account, password-reset, payment, or other sensitive routes for cache poisoning unless explicitly permitted.

### Phase 3: Validate Shared-Cache Poisoning with a Harmless Canary

First use a unique throwaway cache key and a harmless canary. Do not begin with executable JavaScript or a production-shared URL.

```bash
# Use an in-scope endpoint and a unique key for this test
curl --max-time 15 --connect-timeout 5 -s -D- \
  -H 'X-Forwarded-Host: canary.attacker.example' \
  'https://TARGET/page?cb=UNIQUE_VALUE'

# Repeat the exact URL without the injected header
curl --max-time 15 --connect-timeout 5 -s -D- \
  'https://TARGET/page?cb=UNIQUE_VALUE'
```

Only continue if the clean request receives the canary from the cached response. Verify from a separate authorized test session where possible. If no shared response is observed, stop; do not repeat against unrelated users or a shared production URL. Demonstrate XSS or redirect impact only with a program-approved, non-destructive proof after shared-cache behavior is established.

### Phase 4: Unkeyed Parameter Poisoning

```bash
# Probe a harmless parameter on a unique test key
curl --max-time 15 --connect-timeout 5 -s -D- \
  'https://TARGET/page?cb=UNIQUE_VALUE&utm_source=CANARY_VALUE'

# Check the same URL without the candidate parameter where cache-key behavior permits
curl --max-time 15 --connect-timeout 5 -s -D- \
  'https://TARGET/page?cb=UNIQUE_VALUE'
```

Check whether the parameter changes response content and whether it participates in the cache key. A parameter reflected only in its own request is not proof of poisoning. Avoid executable payloads until a harmless canary confirms shared-cache behavior and the program explicitly allows impact testing.

### Phase 5: Fat GET / POST-based Poisoning

Test GET-body and method-override behavior only on an approved, non-critical endpoint using a harmless marker.

```bash
curl --max-time 15 --connect-timeout 5 -s -D- -X GET 'https://TARGET/test' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'param=CANARY_VALUE'

curl --max-time 15 --connect-timeout 5 -s -D- -X GET 'https://TARGET/test' \
  -H 'X-HTTP-Method-Override: HEAD'
```

Compare origin behavior with the cache behavior. Do not intentionally overwrite production assets or repeatedly trigger error responses.

### Phase 6: Cache Key Normalization

```bash
# Path normalization differences
curl --max-time 15 --connect-timeout 5 -s "https://TARGET/path/../admin"
curl --max-time 15 --connect-timeout 5 -s -D- "https://TARGET/PATH?cb=UNIQUE_VALUE"
curl --max-time 15 --connect-timeout 5 -s -D- "https://TARGET/path?cb=UNIQUE_VALUE"
curl --max-time 15 --connect-timeout 5 -s "https://TARGET/path;.js"
```

### Phase 7: Path normalization and routing discrepancies

Compare the cache's URL normalization with the origin router using a small number of safe requests to a non-critical endpoint. Candidate differences include path case, trailing segments, encoded delimiters, semicolon suffixes, duplicate separators, and static-looking extensions.

```bash
curl --max-time 15 --connect-timeout 5 -s -D- 'https://TARGET/test/../test?cb=UNIQUE_VALUE'
curl --max-time 15 --connect-timeout 5 -s -D- 'https://TARGET/test;canary.css?cb=UNIQUE_VALUE'
```

Use only variants relevant to the application's routing. Do not assume a discrepancy is exploitable until you demonstrate that the origin and cache interpret the same request differently and a clean request receives the affected cached response.

### Phase 8: Error-response caching

Observe whether an in-scope, non-critical endpoint caches an error response. Do not deliberately create sustained errors, overwrite production assets, or run repeated poisoning loops. Confirm that a later clean request receives the cached error and state the availability impact precisely.

### Phase 9: Origin and CORS cache variation

When `Origin` changes `Access-Control-Allow-Origin`, verify that the cache varies correctly by Origin. Use a controlled test origin and a test account; a permissive header alone is not proof of cross-origin data exposure. If a browser can read sensitive test-account data because cached CORS headers are mixed between origins, record both the browser result and cache evidence.

### Phase 10: Affiliate and redirect flows

On explicitly in-scope link/redirect endpoints, check whether a candidate header or parameter influences the generated destination and whether that destination is stored in a shared cache. Use a destination you control, a unique test key, and a non-sensitive flow. A redirect that affects only the original request is not shared-cache poisoning.

### Phase 11: Verify shared storage and measure blast radius

1. Establish a baseline request and record cache status, `Age`, `Vary`, and cache provider if known.
2. Use a harmless unique canary on a throwaway key.
3. Repeat the exact URL without the injected input.
4. Where authorized, verify from a separate clean session/client.
5. Determine whether the effect is client-local, edge-local, regional, tenant-wide, or broader. Never infer global impact from a single cache node.

## What Constitutes a Finding

| Finding | Severity |
|---------|----------|
| Shared cached script execution affecting other users | High to Critical, depending on demonstrated impact and blast radius |
| Shared cached redirect to an attacker-controlled destination | Medium to High, depending on trust and concrete impact |
| Private/authenticated response served to an unauthenticated client (WCD) | High to Critical, depending on the data exposed and scope |
| Cached error response disrupts a shared asset/service | Low to High, depending on availability impact |
| Header/parameter reflection without shared-cache impact | Not a confirmed cache-poisoning finding; usually informational/low |

## Evidence Requirements

- Unkeyed input identified (header or parameter)
- Response showing injected content
- Cache headers proving response was cached (X-Cache: HIT, Age > 0)
- Second request (clean) still receiving poisoned content
- Impact: shared script execution, redirect, private-response exposure (WCD), CORS data read, or service disruption

## Advanced Validation: Prove Shared-Cache Impact and Locate the Fault

A reflected input is not sufficient evidence of cache poisoning. Confirm each layer separately:

1. **Reflection:** a unique, harmless canary appears in a response field, redirect, canonical URL, CSP, script URL, or generated link.
2. **Cache-key behavior:** determine whether the varied header/parameter changes the cache key. Vary one input at a time and compare responses.
3. **Storage:** repeat the exact throwaway URL without the injected header. Check whether the altered response persists without the input.
4. **Cross-client scope:** where authorized, request the same throwaway URL from a clean browser/session or a second test client. Do not use another real user's session.
5. **Impact:** show a concrete outcome such as script execution, a meaningful redirect, private test-data exposure, or service disruption. Do not infer impact from a cache HIT alone.

Use a unique query key for initial probes, and verify how the target treats query strings before assuming it isolates cache entries. Never repeatedly poison production assets or create a re-poisoning loop.

## Web Cache Deception (WCD)

WCD is a separate cache-confusion issue, not a synonym for poisoning. The core question is whether a victim-specific response can be stored under a URL the cache treats as shared/static, then served to another request context. Use only two test accounts you control and synthetic/non-sensitive data.

1. Identify an authenticated route that returns account-specific content and a nearby static-looking path pattern (for example, an application route with an extra path segment or static extension).
2. Request the candidate URL as test account A, then inspect cache headers and whether the response is cacheable. Do not use a real user's data.
3. Request the exact same URL from a clean session or test account B. Check whether A's synthetic marker appears without A's session.
4. Stop once cross-session exposure is confirmed. Do not enumerate other users or collect real private responses.
5. Report the cache key, path normalization behavior, cache status, account/session separation, and the minimum redacted evidence needed to reproduce.

Treat WCD as a distinct hypothesis from cache poisoning. WCD occurs when a cache stores a victim's dynamic/private response at a URL it believes is static or publicly cacheable.

- Use only an account and non-sensitive records that you control.
- Compare the normal authenticated endpoint with a static-looking suffix or route variant, such as a profile route ending in `.css` or `.jpg`, only when the application's routing makes this relevant.
- Inspect `Cache-Control`, `Vary`, cache status, content type, and whether the origin returns dynamic content for the altered path.
- Request the exact test URL without authentication from a separate clean session. Do not attempt to retrieve another user's private data.
- A mismatched content type or a cache HIT is only an indicator. Confirm that the unauthenticated response actually exposes the test account's private response before reporting WCD.

## Cache-Key, Normalization, and Origin/Edge Discrepancy Checks

Use only controlled, low-volume requests on in-scope endpoints. Change one dimension per comparison:

- **Headers:** `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `Forwarded`, `Origin`, and method-override headers.
- **Query handling:** parameter order, ignored tracking parameters, duplicate parameters, and whether query values participate in the cache key.
- **Path handling:** case differences, trailing segments, encoded delimiters, semicolon suffixes, and static-looking extensions, if supported by the app's router.
- **Method handling:** compare GET/HEAD and method-override behavior only on an approved, non-critical endpoint using a harmless canary.
- **Error caching:** observe whether an error response is cached and then served to a clean request; do not intentionally create sustained failures.
- **CORS variation:** if `Origin` changes `Access-Control-Allow-Origin`, verify whether the cache correctly varies by Origin and whether a real cross-origin read is possible. A permissive header alone is not proof of data exposure.

Do not treat request-smuggling as a prerequisite for ordinary cache poisoning. If there is a credible proxy parsing discrepancy, test it as a separate, explicitly authorized vulnerability class and link the findings only when the cache impact is demonstrated.

## Origin Header and Cache-Variation Checks

Treat `Origin` as a separate cache-key candidate. First compare the same harmless endpoint with no `Origin`, a normal allowed origin, and a unique untrusted origin, using a fresh test key for each variant. Record `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`, `Vary`, `Age`, and the cache status.

- If the response varies by origin, verify that the cache key or `Vary: Origin` keeps those variants separate. A missing `Vary` header is a signal to investigate, not proof on its own.
- Do not claim cross-user CORS impact until a clean request from a separate authorized client receives the cached variant and a browser test confirms the relevant read/action.
- A request header such as `Cache-Control: no-cache` is not a reliable guarantee that an edge will bypass storage. Prefer a unique, harmless test key and verify cache state from the response.
- Keep cache poisoning, cache deception, CORS misconfiguration, and request smuggling as distinct hypotheses. Report a chain only when each necessary step is independently demonstrated.

## Severity and False-Positive Gate

Before assigning severity, answer all of the following:

- Does the clean request receive a response altered by the earlier canary request?
- Is the effect shared beyond the original request/session, and what is the demonstrated scope (one client, one edge, one region, tenant-wide)?
- What user-visible security outcome is proven?
- Can the behavior be reproduced without causing persistent disruption or accessing another user's data?
- Does the program's severity rubric support the proposed rating?

A response code, a reflected header, an `Age` value, or `X-Cache: HIT` alone does not establish a vulnerability. Severity depends on the demonstrated impact and the affected audience, not on the technique name.

## Evidence to Preserve

Record a sanitized request/response pair for the canary request and the clean follow-up request, timestamps, endpoint, relevant cache headers, `Vary`, cache provider if known, test-account context, and the precise impact demonstrated. Redact cookies, authorization headers, session IDs, private data, and unrelated user information. Keep raw engagement evidence outside this public skill file.

## Useful Detection Patterns

```text
X-Cache: HIT
CF-Cache-Status: HIT
Age: [1-9]
canary\\.attacker\\.example
Cache-Control: public.*max-age (on a private/authenticated route)
```

These are triage indicators only. Confirm semantics and clean-client impact before reporting.

## Common Root Causes

1. Cache key is based on path while the origin serves dynamic content.
2. Request headers affect redirects, canonical URLs, script sources, or generated links but are omitted from the cache key.
3. Static-file cache rules disagree with origin routing or path normalization.
4. Tenant identity, cookies, or authorization context are missing from shared-cache variation.
5. Error responses are cached and replace legitimate content.
6. `Vary` is missing, incomplete, or stripped by an intermediary.
7. `Origin` changes CORS response headers but the cache does not vary on Origin.
8. Proxy parsing or hop-by-hop header handling differs across layers.

## Bypass, Variant, and Cache-Key Coverage Checks

- Header variants: `X-Host`, `X-Forwarded-Server`, `Forwarded: host=...`, `X-Original-URL`, and `X-Rewrite-URL`.
- Query handling: ignored tracking parameters, parameter order, duplicate parameters, and query strings omitted from the cache key.
- Method handling: GET/HEAD differences, GET bodies, and method-override headers on a non-critical test endpoint.
- Path handling: case, trailing segments, encoded delimiters, semicolon suffixes, and static-looking extensions.
- Cache policy: whether sensitive routes honor `Cache-Control: private` and whether `Vary` matches the inputs that change the response.
- Request smuggling is a separate test class. Pursue it only when explicitly in scope; link findings only after the shared-cache impact is independently demonstrated.

## Historical Case Patterns and Root-Cause Taxonomy

Public research and disclosures describe patterns including `X-Forwarded-Host` influencing generated URLs, `X-Forwarded-Port` poisoning cached redirects, method-override/cache confusion, static-looking suffixes exposing authenticated responses, cache-deception extension gaps, path-normalization differences, and proxy parsing discrepancies affecting edge caches. Treat these as test hypotheses, not proof that a target is vulnerable or that a specific payout/severity applies.

## Pitfalls and False Positives

- Reflection without shared-cache persistence is not cache poisoning.
- `200 OK`, `Age > 0`, or `X-Cache: HIT` alone is not proof of a poisoned response.
- Cache entries may be partitioned by cookies, `Vary`, user agent, Origin, tenant, region, or edge node.
- Web Cache Deception exposes a victim's private response through a cacheable-looking URL; cache poisoning changes a cached response using attacker-controlled input. Keep the claims separate.
- A suspicious content type or cached error is only an indicator until clean-client behavior and actual impact are confirmed.
- Do not claim Critical or global impact from the technique name alone. Use the program's severity rubric and the demonstrated blast radius.

## Related Skills and Chains

- `attack-host-header` — application logic influenced by Host/forwarded-host headers; this skill owns the case where the affected response is shared through a cache.
- `attack-open-redirect` — validate the redirect itself separately from whether a poisoned destination is stored.
- `attack-request-smuggling` — investigate proxy desynchronization only when authorized and supported by evidence.
- `attack-cors` — validate browser-readable cross-origin impact when Origin and cache variation interact.
- `wstg-inpv-02` and `wstg-clnt-01` — follow up only when stored or DOM-based XSS is actually demonstrated.
- `triage-validation` — verify the shared-cache boundary, repeatability, scope, and actual impact before reporting.
- `evidence-hygiene` — redact cookies, tokens, private response fields, and target-sensitive artifacts before attaching evidence.

## Cache Test Runbook, Cleanup, and Stop Conditions

Use an endpoint approved for active testing and a unique, non-sensitive cache key. First establish normal cache behavior, then test one candidate unkeyed input at a time with a harmless marker.

1. Capture cache headers and baseline body for a clean request.
2. Send one controlled variation and record whether the origin response changes.
3. Repeat the exact same URL without the variation; verify whether the marker remains and whether the response is a cache hit.
4. Where the program permits, verify only with a second test session you control. Do not involve real users.
5. Stop immediately after confirming shared-cache persistence or if the response could affect a public page, authentication flow, or other users.

Never use destructive payloads, poison high-traffic shared URLs, or trigger repeated cached errors to demonstrate impact. Separate origin reflection, private-cache behavior, and shared-cache poisoning. Report the cache layer, key dimensions, TTL/status, clean-request reproduction, and only the minimum sanitized evidence needed.

## References

- [uphiago/recon-skills — recon/cache-attack](https://github.com/uphiago/recon-skills/blob/main/recon/cache-attack/SKILL.md) — merged cache discovery source.

- [uphiago/recon-skills — cache attack methodology](https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-cache-poison/SKILL.md) (external research reference; not a local Cyber Strike skill path).
- [elementalsouls/Claude-BugHunter — cache poisoning methodology](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-cache-poison/SKILL.md) (external research reference; not a local Cyber Strike skill path).

- [PortSwigger: Web Cache Poisoning](https://portswigger.net/web-security/web-cache-poisoning)
- [James Kettle: Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
