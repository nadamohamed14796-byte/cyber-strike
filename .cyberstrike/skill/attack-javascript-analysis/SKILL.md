---
name: attack-javascript-analysis
description: "Turn authorized JavaScript assets and source maps into a deduplicated endpoint, parameter, auth-signal, and vulnerability-hypothesis inventory."
category: "recon"
version: "1.0.0"
author: "CyberStrike contributors"
tags: [javascript, source-maps, endpoints, api, frontend-security, secrets]
tech_stack: [javascript, typescript, browser, rest, graphql, spa]
chains_with: [attack-web-recon, attack-source-leak, attack-dom-xss, attack-prototype-pollution, attack-shadow-api, attack-triage-validation]
sources:
  - "https://github.com/uphiago/recon-skills"
  - "https://owasp.org/www-project-web-security-testing-guide/"
  - "https://tc39.es/ecma262/"
---

# JavaScript Attack-Surface Analysis

## Goal
Convert first-party JavaScript into validated leads for manual hunting. Do not treat a string, secret-like value, route fragment, or source-map comment as proof that an endpoint exists or a credential is usable.

## Workflow
1. Inventory only target-related assets discovered by authorized navigation, passive sources, or recorded browser responses. Store URL, content hash, observation time, response type, and source.
2. Check for source maps and readable bundles; identify minified/vendor code versus first-party application logic. Preserve source-to-bundle mapping when available.
3. Extract routes, API base URLs, methods, GraphQL operation names, WebSocket URLs, parameter names, feature flags, role/tenant hints, request headers, cookie names, storage keys, file-upload destinations, and URL-fetching features.
4. Normalize endpoint templates but retain HTTP method, content type, API version, parameter shape, auth context, and discovery source. Do not collapse endpoints just because their paths look similar.
5. Search for risky client sinks and data flows: innerHTML, insertAdjacentHTML, document.write, eval-like APIs, postMessage listeners, URL/redirect assignments, dynamic script loading, unsafe template rendering, and prototype-sensitive merge helpers. Confirm reachability and control of the source before assigning a vulnerability class.
6. Treat token-like strings as secret fingerprints only. Never print candidate secret values, test them, or copy them into requests. Store file, line/offset, type, confidence, and a redacted fingerprint.
7. Correlate extracted endpoints with actual network requests from the authorized browser session. An endpoint string may be dead code, a test route, a feature disabled in production, or a third-party URL.
8. Route only evidence-matched items to specialist skills: object identifiers to IDOR/BOLA; untrusted HTML sinks to DOM XSS; URL-fetch features to SSRF; redirect parameters to open redirect; undocumented/versioned routes to shadow API review; and credential exposure to triage without using the value.

## Practical local-only searches
```bash
# Run inside a local copy of assets already collected from the authorized target.
rg -n -i 'sourceMappingURL|innerHTML|insertAdjacentHTML|document\.write|postMessage|WebSocket|graphql|fetch\(|axios\.|Authorization|tenant|role|redirect' ./javascript/
```
Treat output as candidate metadata. Redact token-like values before persisting, and do not include entire minified lines in a report.

## Prioritization and chaining
Prioritize routes that connect to privileged actions, tenant/object identifiers, file transfers, authentication flows, remote URL fetches, billing/export operations, and hidden API versions. A useful chain is JavaScript clue → correlated live request → missing server-side control → controlled proof → impact. If the live request cannot be observed or safely tested, keep it as an unconfirmed lead.

## Output contract
Save an endpoint/parameter inventory with asset, file hash, source, method, route template, parameters, headers, auth signals, role/tenant hints, sink/source, live-request correlation, confidence, redaction, and next skill. Keep one endpoint record with multiple parameter observations rather than duplicating the endpoint itself.

## False positives
- Bundled third-party code or dead code is mistaken for the target's application logic.
- A development URL, test route, or obsolete API version is no longer reachable.
- A token-like string is a public identifier or dummy fixture.
- Client-side hiding is mistaken for server-side authorization.
- A sink appears in code but is unreachable from attacker-controlled input.
