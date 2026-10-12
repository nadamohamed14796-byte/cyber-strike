---
name: attack-dom-xss
description: "Trace attacker-controlled browser sources into unsafe DOM sinks and verify DOM-based script execution with a benign, test-account-only proof."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - dom-xss
  - javascript
  - spa
  - sources-sinks
  - client-side
tech_stack:
  - javascript
  - web
  - spa
  - react
  - vue
  - angular
cwe_ids:
  - CWE-79
chains_with:
  - attack-xss
  - attack-oauth
  - attack-csrf
prerequisites: []
severity_boost:
  attack-oauth: "DOM XSS on an authentication callback can expose identity-flow data; use test tenants and never collect tokens."
---

# DOM-Based XSS Source-to-Sink Analysis

## Objective

Find client-side paths where URL, message, storage, or API data becomes executable markup or script. Produce a reproducible source-to-sink trace rather than a payload catalogue.

## Scope

- Only test tester-owned accounts/sessions and tester-supplied synthetic values (own CSRF token, own nonce, own session). Never run a CSS-exfiltration or clobbering PoC designed to capture a real third party's token or data.
- Out-of-band confirmation (CSS attribute-selector exfil, service-worker fetch interception) is limited to the engagement's own collaborator/request-bin, scoped to the tester's own test window, and must be removed/unregistered immediately after proof is captured.
- A same-origin Service Worker PoC must be registered only against a route/scope the tester controls (own upload, own test page) and must be unregistered at the end of the test — never leave a persistent SW capable of intercepting other users' traffic.
- DOM-clobbering probes use markup only (no `<script>`) against the tester's own content; never pivot a clobbering PoC into stealing another session's data.

## Testing Methodology

### Phase 1: Inventory controllable sources

Search for location.search/hash, document.URL/referrer, postMessage event.data, window.name, local/session storage, and API-returned values. Establish whether a remote party can influence each source in a normal application flow.

### Phase 2: Map sinks and transformations

Review innerHTML, outerHTML, insertAdjacentHTML, document.write, eval, Function, string-based timers, unsafe URL assignments, and framework escape hatches (`dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`). Also check for DOM-clobbering-susceptible patterns: global lookups with an `||`/nullish fallback (`window.config || {}`), and code that trusts a DOM node's own properties (e.g., iterating `element.attributes` without confirming it is still a `NamedNodeMap`) — markup-only injection (duplicate `id`/`name` attributes, a `<form id="attributes"><input id="x">` shape) can overwrite these even when `<script>` is stripped. Trace sanitizers, parsers, decoders, and allowlists; a dangerous API alone is not enough.

### Phase 3: Use inert runtime tracing

Set a unique benign marker at the candidate source and watch it in DevTools or breakpoints. Confirm whether it reaches the sink and whether a safe text API or context encoder intervenes. A marker reaching textContent is not XSS. For a suspected DOM-clobbering path, inject benign markup (an anchor/form with the target `id`/`name`) on tester-owned content and confirm in the console that the global now resolves to an `Element`/`HTMLCollection` rather than its expected type — this is the clobbering signal, independent of any sink.

### Phase 4: Validate in an authorized browser

If active proof is authorized, use a harmless execution indicator with a tester-owned account and clean up afterward. Never inspect or export cookies, local-storage tokens, OAuth fragments, or another user's message contents. Where live execution is disallowed, preserve the source-to-sink trace and mark active confirmation as pending authorization.

### Phase 5: Check framework and origin boundaries

Determine whether code runs in the application origin, a sandboxed iframe, or a separate content/upload origin. Review exact postMessage origin checks, safe URL APIs, CSP, and Trusted Types. Treat a substring/partial origin check (`origin.indexOf('target.com') > -1`, `endsWith('target.com')`) as a candidate bypass, not a safe check — confirm only by serving a controlled PoC from a look-alike hostname the tester owns (e.g., a tester-registered domain containing `target.com` as a substring) and showing the message is still accepted; never rely on a hostname impersonating a real third party.

### Phase 6: Bounded CSS-exfiltration and service-worker checks (OOB-confirmed only)

Where the application accepts attacker-influenced CSS (theme/custom-CSS field, `style=` passthrough, email template) and the tester's own non-sensitive attribute value (own CSRF token or nonce) is reachable, a single-character attribute-selector probe (`input[name="x"][value^="a"]{background:url(COLLABORATOR)}`) against the tester's own page, confirmed only via a hit on the engagement's own OOB listener, demonstrates the side channel — first check the live `Content-Security-Policy` for `style-src`/`img-src`/`connect-src` restricting external origins, since that alone defeats this technique. Where a same-origin Service Worker could be registered from a confirmed XSS/upload path, limit the PoC to registering against a tester-owned scope, observing one OOB hit to prove fetch interception, and unregistering it immediately; do not intercept traffic beyond that single proof.

## What Constitutes a Finding

- **Candidate / lead:** attacker-controlled source data reaches a potentially script-capable sink.
- **Confirmed finding:** an unsafe flow safely demonstrates script execution in an in-scope origin, or code-review evidence establishes a reachable exploitable sink in a review-only engagement.
- **Not a finding:** a source reaches textContent, the value is safely encoded, or it appears only in DevTools without being parsed by the page.

## Impact

Severity tracks what the client-side primitive actually reaches, not that a sink was merely found:

- **Low:** a clobberable global or an unchecked postMessage listener is identified, but no reachable sink (script execution, navigation, privileged action) is demonstrated from it.
- **Medium:** a confirmed CSS-exfiltration side channel limited to the tester's own non-sensitive value, or a weak (partial-match) postMessage origin check confirmed bypassable in a controlled test, without a demonstrated path to another session's data.
- **High:** DOM clobbering or a postMessage flaw confirmed to reach a script-capable sink (innerHTML, eval, unsafe URL assignment, navigation) under markup-only or cross-frame input, or a confirmed path from a public source (URL fragment, storage) to session-bearing data.
- **Critical:** a same-origin Service Worker registered via a confirmed XSS/upload path and proven (via OOB, then promptly unregistered) to intercept fetches and capture auth headers/tokens persistently across sessions, or a postMessage/DOM-clobbering chain that reaches account takeover or cross-origin token theft (e.g., an OAuth implicit-flow fragment token read by a DOM sink).

State the exact source, the sink it reaches, whether a sanitizer/origin-check was bypassed or simply absent, and whether confirmation was live-execution or source-to-sink-only.

## Evidence Requirements

- Source value, URL/message setup, file/function/line of sink, and transformations in between.
- Browser/version, origin, account role, timestamp, and reproduction steps.
- Sanitized DOM or harmless execution proof; no private storage or token values.
- Note whether confirmation was active or source-to-sink-only due to authorization limits.

## Tools

- **Browser DevTools debugger:** trace values at runtime without copying sensitive storage.
- **Burp Suite:** establish controllable URL/query/API inputs.
- **Semgrep / code search:** locate dangerous sinks and data flows.
- **DOM Invader or equivalent:** prioritize sources and sinks, then verify manually.

## DOM Source-to-Sink Decision Matrix

| Source | Potential sink | Required validation |
|---|---|---|
| location.search / hash | HTML/script parser | Confirm URL control and absence of safe encoding |
| postMessage event.data | DOM insertion, eval, unsafe URL | Verify exact event.origin policy and message schema |
| local/session storage | HTML insertion after redirect/restore | Show attacker control and later unsafe use |
| API response / Markdown | innerHTML or raw HTML component | Trace data to renderer with synthetic input |
| referrer / window.name | navigation or markup construction | Verify source control and encoding |

**Mitigation / regression:** prefer textContent and safe DOM builders, sanitize rich content, validate message origins with exact comparisons, and use Trusted Types where supported. Add a regression test for the identified flow.

## Verification and False Positives

- Minified bundles may show dead or guarded code; verify a live call path.
- An attacker-controlled value may be made inert before reaching the sink.
- Wildcard origin checks or string-based sinks are leads, not proof without a reachable flow.
- Never copy OAuth fragments or real browser tokens into logs/reports.

## Stop Conditions

- Stop if testing requires delivery to an uninvolved user, tenant crossing, or third-party payload execution.
- Stop and unregister immediately if a Service Worker PoC begins intercepting requests outside the tester's own test scope, or if a CSS-exfiltration probe starts leaking more than the single designated test value.
- Stop before reading, exporting, or logging any real session cookie, OAuth fragment, local-storage token, or another user's postMessage payload — confirm the primitive, then stop.
- Stop and reconfirm scope if a postMessage or origin-check bypass appears reachable from a hostname or origin the tester does not control.

## Defensive Notes

- Prefer framework-level auto-escaping (`textContent`, safe DOM builders, React/Vue/Angular default interpolation) over raw-HTML sinks, and gate any unavoidable `dangerouslySetInnerHTML`/`v-html`/`[innerHTML]` use behind a vetted sanitizer (e.g., DOMPurify) applied immediately before the sink, not earlier in the pipeline.
- Validate `postMessage` origins with an exact string/allowlist comparison, never `indexOf`/`endsWith`/regex-without-anchors, and always check `event.origin`, not `event.source` or message content.
- Adopt a strict Content-Security-Policy with Trusted Types to make DOM-XSS sinks fail closed by default, and restrict `style-src`/`img-src`/`connect-src` to defeat CSS-exfiltration side channels even when a markup-injection bug exists.
- Avoid clobberable global-lookup patterns (`window.x || default`) for security-relevant configuration, and freeze or namespace globals that must not be overwritable by attacker-controlled markup.

## References

- [uphiago/recon-skills — hunt-dom](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-dom)
- [elementalsouls/Claude-BugHunter — hunt-dom](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-dom)
- [OWASP — DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [PortSwigger Web Security Academy — DOM-based vulnerabilities](https://portswigger.net/web-security/dom-based)
