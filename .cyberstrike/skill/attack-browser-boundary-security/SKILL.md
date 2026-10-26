---
name: attack-browser-boundary-security
description: "Assess browser trust boundaries around postMessage, service workers, cross-origin state, opener/navigation, and cache behavior using minimal authorized tests."
category: "web-application"
version: "1.0.0"
author: "CyberStrike contributors"
tags: [browser-security, postmessage, service-worker, cross-origin, xs-leaks, cors, dom]
tech_stack: [javascript, browser, html, http]
cwe_ids: [CWE-346, CWE-349, CWE-602, CWE-200]
chains_with: [attack-javascript-analysis, attack-dom-xss, attack-cors, attack-csrf, attack-clickjacking, attack-triage-validation]
prerequisites:
  - "A confirmed in-scope web application and an authorized browser/test context"
sources:
  - "https://github.com/usestrix/strix/blob/main/strix/skills/README.md"
  - "https://owasp.org/www-project-web-security-testing-guide/"
---

# Browser Boundary Security

## Purpose

Test browser-specific trust boundaries that can be missed by endpoint-only checks: cross-window messaging, service-worker scope/cache, opener/navigation relationships, and cross-origin state side channels. Use the existing JavaScript asset manifest and captured browser requests as the starting evidence.

## Safety and scope

Test only in-scope origins and authorized browser sessions. Do not export real tokens, cookies, personal data, or private cross-origin state. Use a test-owned account and harmless synthetic values. Avoid high-volume timing probes, cache poisoning of shared users, state changes, service-worker unregister/registration changes, or navigation that can impact real users. If safe browser instrumentation or a controlled test page is unavailable, keep the lead unconfirmed.

## Procedure

### 1. Build the boundary map

From first-party bundles, HTML, source maps, and captured browser traffic, identify:
- `postMessage` senders/listeners and the expected origins, source windows, and message schema;
- `BroadcastChannel`, `window.name`, `window.opener`, frame, popup, and cross-origin navigation relationships;
- service-worker script URL, registration scope, cache keys, cached response types, and update/fallback behavior;
- cross-origin resource loads and browser-visible signals that vary with authenticated state;
- storage, cookie, redirect, and CORS assumptions relevant to the flow.

Record URL/hash, line or offset, origin, source request/capture ID, and the trust decision that needs verification. Route generic CORS, CSRF, clickjacking, or DOM XSS behavior to the existing specialist when that class is the real issue.

### 2. Validate postMessage trust

Inspect whether listeners compare `event.origin` to an exact expected origin, whether `event.source` is the expected window/frame, and whether the received message shape and type are validated before sensitive actions. A wildcard target origin is not automatically exploitable if the message contains no sensitive data or state change.

When authorized, use only a harmless synthetic message from a controlled origin/window. Verify both the expected-origin control and the untrusted-origin case. Never send credentials or live tokens to a third-party origin, and do not claim impact from a missing origin check without demonstrating a reachable protected action or sensitive-data exposure.

### 3. Review service-worker and cache boundaries

Inspect registration scope, script origin, cache matching keys, handling of authenticated/private responses, offline fallback, and version/update logic. Compare behavior with a test-owned session and synthetic resource. Do not modify shared caches or clear/replace registrations for other users. A cached response is a vulnerability only when the evidence shows an unintended audience or stale authorization boundary, not merely because caching exists.

### 4. Assess cross-origin state and navigation

Where the application uses popups, iframes, cross-origin resources, or redirects, review opener isolation, referrer handling, origin checks, cookie attributes, and whether response/timing/state differences create a meaningful unauthorized signal. For XS-Leak-style hypotheses, use a low-volume controlled comparison with test-owned resources and record only the boolean/timing signal needed; never enumerate private records or extract sensitive state.

### 5. Confirm impact and route correctly

Trace the browser signal to a security-relevant outcome: unauthorized action, sensitive information revealed across origins, account/session confusion, or a protected flow bypass. Use baseline and negative controls, preserve the exact browser context and role, and stop if the result risks user data or service stability. A source-code pattern alone remains a candidate.

For every plausible finding, invoke `validate_finding` and follow the durable verification ledger. Unknown prerequisites/evidence stay unknown; unresolved cases remain inconclusive, not confirmed or disproven by a single failed attempt.

## Output contract

Merge into the existing target-local JavaScript/endpoint inventory and finding ledger. Retain the affected origin, asset URL/hash, source location, event origin/source logic or service-worker scope, relevant request/capture IDs, authorized test context, control comparison, observed impact, redacted evidence, confidence, limitations, and next safe step. Do not create a file per message handler or bundle.
