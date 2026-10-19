---
name: attack-cache-deception
description: "Test whether shared caches store private dynamic responses under static-looking URL paths or extensions."
category: "web-application"
version: "1.0.0"
author: "CyberStrike contributors"
tags: [cache-deception, caching, authorization, cdn, privacy]
tech_stack: [http, cdn, reverse-proxy, web]
chains_with: [attack-cache-poison, attack-session, attack-idor-automation, attack-triage-validation]
sources:
  - "https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html"
  - "https://portswigger.net/web-security/web-cache-deception"
  - "https://www.rfc-editor.org/rfc/rfc9111"
---

# Web Cache Deception Assessment

## Objective
Determine whether a cache treats a personalized route as a cacheable static resource and later serves that response in the wrong security context. A static-looking suffix, cache header, or successful request alone is not a finding.

## Procedure
1. Use a dedicated account with synthetic profile data and a read-only route that is safe to request repeatedly. Identify the normal dynamic route and its response policy.
2. Review URL normalization, route matching, extension handling, reverse-proxy cache rules, Cache-Control, Vary, Age, and provider cache-status headers.
3. Select a harmless path variation that the application routes to the same controlled resource while the cache may classify it differently. Do not use real personal data or attempt to obtain another user's response.
4. Capture a baseline, request the controlled variation, then make a clean request through the same cache path. Compare response identity, cache status, and whether synthetic private marker content is served to the same controlled session after the variation.
5. If and only if the program permits cross-identity validation, use a second controlled account and synthetic fixtures to establish whether cache isolation fails. Never use another real user's session or data.
6. Verify cache layer and persistence; distinguish browser cache, CDN cache, reverse proxy, application cache, and client-side service worker behavior. Clean test state through an approved cache-invalidation method.

## Safe observation record
```text
route_baseline: /account/profile
controlled_variant: /account/profile/marker.css
test_fixture: synthetic profile marker owned by controlled account
response_content_type: recorded
cache_status_headers: recorded
clean_follow_up_result: recorded
cross_identity_test: not run unless explicitly permitted
```

## Impact and chaining
The impact chain is private/dynamic response → cache classification mismatch → response stored or treated as shared → a request in the wrong security context receives private content. State exactly which links were observed. Chain to cache poisoning only if an unkeyed request input changes a stored response; chain to IDOR only if application authorization itself is independently broken; chain to session review if auth state or cookie variation drives the result.

## False positives
- The route returns a public or synthetic static resource.
- Cache status indicates bypass or miss rather than storage.
- A suffix produces a 404/soft-404 or a distinct handler.
- The response is present only in the same browser's local cache.
- A cache key already varies by authorization, session, or tenant.

## Output
Record route pair, cache layer, response policy, synthetic marker, storage/reuse evidence, identity context, impact boundaries, cleanup, and redacted evidence. Do not claim broad user exposure from same-account behavior alone.


## Targeted quality-loop enrichment (2026-10-19)

### Cache isolation proof
Use a synthetic private marker belonging only to a test account and a route that is normally dynamic. Capture the baseline, the controlled path variant, cache headers (Age, Vary, Cache-Control, provider cache status), and a clean repeat request. Distinguish browser cache, service worker, application cache, reverse proxy, and CDN behavior. Do not attempt to retrieve another real user's personalized response; cross-identity validation requires two test-controlled accounts and explicit permission. Route a cache-key input that changes shared response content to cache-poisoning review; route host-derived links to host-header review; report only when the cache boundary and realistic exposure are demonstrated.


## Agent-executable CLI tooling, resources, and helper scripts

### Agent-usable CLI tools
- `curl` or Python `httpx`: compare an authenticated baseline with one harmless path/suffix variation, using only tester-owned sessions.
- `jq` and `rg`: inspect saved response metadata and local route/cache configuration.
- `python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt`: compare saved redacted responses offline.
### Install and verify
Verify `curl --version` and the selected Python client; official docs: https://curl.se/docs/ and https://www.python-httpx.org/. If missing, inspect server/cache configuration or use a local fixture. Do not claim a test ran without output.
### Resources
- https://portswigger.net/web-security/web-cache-deception
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching
- https://www.rfc-editor.org/rfc/rfc9111
### Proof and limits
Use only a tester-owned authenticated account and non-sensitive test content. Prove that a cache stores and serves the controlled response under the relevant key; do not attempt to retrieve another user's private content.
