---
name: attack-cache-poison
description: "Assess web cache poisoning through cache-key analysis and controlled response-differential validation"
category: "web-application"
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [cache-poisoning, web, caching, host-header, response-diff]
tech_stack: [http, cdn, reverse-proxy, web]
cwe_ids: [CWE-444, CWE-525]
chains_with: [attack-host-header, attack-open-redirect, attack-triage-validation]
prerequisites:
  - "Authorized cacheable endpoint and low-rate test window"
  - "Controlled marker value and a safe way to verify cache separation"
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-cache-poison/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
  - "https://portswigger.net/web-security/web-cache-poisoning"
---

# Web Cache Poisoning Assessment

## Objective

Determine whether an attacker-controlled input influences a shared cached response without being represented safely in the cache key, causing later requests to receive an unintended response. Reflection alone is not cache poisoning.

## Scope and safety

Use a low-impact endpoint and a unique inert marker. Do not poison shared production content with executable scripts, redirects, or content visible to other users. Do not test high-volume cache fills or purge shared caches without explicit permission. Prefer a staging environment; if live validation is permitted, use a non-sensitive response and immediately verify and clean up the test state.

## Procedure

### 1. Establish cache behavior

Capture status, response body hash, `Cache-Control`, `Age`, `Vary`, and provider-specific cache headers. Repeat the same request conservatively to determine whether a cache hit occurs. Account for CDN, reverse proxy, browser, and application caches separately.

### 2. Identify candidate inputs

Review headers, query parameters, cookies, and host/scheme metadata that may affect response generation. Candidates can include forwarded host/proto headers or unkeyed query parameters, but only test values supported by observed behavior. Keep a record of the exact request variant.

### 3. Compare response and cache key behavior

Use an inert unique marker in one input at a time. Determine whether it changes the response and whether the altered response is stored and served to a second clean request that omits the marker. Confirm that the second request is a cache hit and that the marker did not simply appear in an uncached response.

### 4. Validate safely

First use a harmless text marker on a private or non-sensitive response. Do not use XSS, credential-bearing links, or redirects as initial probes. If program rules do not permit proving a shared-cache effect, stop at a documented hypothesis and mark it unconfirmed.

### 5. Assess keying and variants

Review `Vary`, normalized URLs, cookies, authorization state, cache directives, and CDN-specific behavior. Check whether authenticated and anonymous variants are isolated. Never attempt to expose another user's cached private response.

### 6. Cleanup and impact

If a test object or cache entry was created, purge or restore it only through an approved mechanism. Document whether a second clean request received the altered response, the affected cache scope, and who could be impacted.

## Common false positives

- A reflected header value in a response that is not cached.
- A cache header without a demonstrated shared-cache effect.
- A unique response caused by cache-busting parameters.
- A browser cache mistaken for a shared CDN/proxy cache.
- An unkeyed input that does not influence a security-relevant response.

## Evidence and output

Return `endpoint`, `cache_layer`, `candidate_input`, `baseline_cache_state`, `marker_response_diff`, `clean_request_result`, `shared_cache_confirmed`, `impact_scope`, `cleanup_status`, `confidence`, and redacted evidence. Never claim stored XSS or broad user impact without separate proof.

## Related skills

- `attack-host-header` — host and forwarded-header trust.
- `attack-open-redirect` — redirect behavior as a possible downstream impact.
- `attack-triage-validation` — validate exploitability and severity.


## Practical differential request
Use an inert marker and an endpoint whose cache behavior you understand. Do not poison shared production content or place active script/redirect payloads into a shared cache.

```bash
: "TARGET_URL must be a permitted, low-impact cacheable endpoint"
curl -sS -D clean-1.headers -o clean-1.body "$TARGET_URL"
curl -sS -D marker.headers -o marker.body -H 'X-Forwarded-Host: cs-marker.invalid' "$TARGET_URL"
curl -sS -D clean-2.headers -o clean-2.body "$TARGET_URL"
sha256sum clean-1.body marker.body clean-2.body
```

Record Age, Vary, cache status, response hash and the clean follow-up. A difference without a confirmed shared-cache hit is not cache poisoning. Route host-derived behavior to attack-host-header, personalized-content under static-looking paths to attack-cache-deception, and any final claim to attack-triage-validation.


## Enrichment: safe cache differential
Use a harmless marker on a permitted low-impact endpoint and compare a clean request before and after; never place active script or credential-bearing content into a shared cache.

```bash
curl -sS -D clean.headers -o clean.body "$TARGET_URL"
curl -sS -D marker.headers -o marker.body -H 'X-Forwarded-Host: cs-marker.invalid' "$TARGET_URL"
curl -sS -D follow-up.headers -o follow-up.body "$TARGET_URL"
sha256sum clean.body marker.body follow-up.body
```

Inspect cache status, Age/Vary, the clean follow-up, and whether the altered response was truly served from a shared cache. Reflection alone is not cache poisoning. Correlate with host-header and cache-deception testing only when the relevant behavior is independently observed.


## Targeted quality-loop enrichment (2026-10-19)

### Cache-key differential and safe chain
Build a baseline with status, body hash, Cache-Control, Age, Vary, and provider cache markers, then alter one observed candidate input at a time (query, host-derived value, forwarded scheme, or content-negotiation header). Use an inert per-test marker on a low-impact response and verify a second clean request receives the same changed response before concluding shared-cache contamination. Do not poison executable content, login flows, or shared content visible to others. A host-derived reset URL is a separate host-header hypothesis; a private route variant cached as static is cache deception. Chain only when the response mutation and cache persistence are both evidenced, and record cache layer uncertainty as inconclusive.


## Practical tooling, references, and helper scripts (2026-10-19)

### Tools that fit this skill
- Browser DevTools Network/Application, Burp Proxy/Repeater/Comparer, and curl for replaying one observed request. Use only tool integrations that the current CyberStrike runtime actually exposes; optional CLI programs must be verified with command -v first.
- Before treating an optional CLI command as runnable, verify its presence and version locally. Do not claim integrations or tools that the current runtime has not exposed.
- Start with passive/read-only observation. Only active tests against authorized assets; state-changing tests require an approved disposable fixture and explicit program permission.

### Primary resources
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — test procedures and evidence criteria.
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — controlled labs and differential testing.
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/) — remediation-oriented guidance.

### Small, reusable helper
    python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt
This compares local artifacts offline and heuristically redacts common secrets before displaying differences. It sends no requests and does not prove complete sanitization.

### Evidence and hand-off
- Save a sanitized artifact reference and the exact claim it supports. Keep credentials, full cookies, reset links, private user data, and raw secrets out of notes, global research storage, and commits.
- Mark the result confirmed, disproven, or still a hypothesis. If the key check cannot be run safely or the expected control is missing, record the gap rather than inventing a conclusion.

Validation note: use a known-good baseline and a control case, change one meaningful variable at a time, record the alternative explanation, and route a lead onward only when the evidence meets this skill's proof criteria.


## Agent-executable CLI tooling, resources, and helper scripts

### Agent-usable CLI tools
- Python `httpx` or `curl`: compare cacheable responses for one controlled header/query variation using a unique benign marker.
- `jq` and `rg`: parse saved headers/body metadata and inspect collected source/configuration.
- `ffuf`: optional small candidate-header/parameter checks only when program rules allow; never use high-volume guessing or shared-cache disruption.
- Existing helper `python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt`: compare saved responses offline.
### Install and verify
Verify `curl --version`, the selected Python client, and `ffuf -V`. Official docs: https://curl.se/docs/, https://www.python-httpx.org/, https://github.com/ffuf/ffuf. Use a unique marker and disposable/test account; record missing tools and use a saved-response or source-review fallback.
### Resources
- https://portswigger.net/web-security/web-cache-poisoning
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Caching
- https://www.rfc-editor.org/rfc/rfc9111
### Proof and limits
Show a reproducible cache-key mismatch and controlled marker reaching a later request. Avoid contaminating shared users' cache or storing private responses.
