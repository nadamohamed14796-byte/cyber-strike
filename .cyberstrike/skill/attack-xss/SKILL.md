---
name: attack-xss
description: "Validate reflected, stored, and template-driven cross-site scripting using context-aware canaries and browser confirmation without accessing victim data."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - xss
  - html-injection
  - browser
  - client-side
  - injection
tech_stack:
  - web
  - javascript
  - html
  - markdown
  - svg
  - spa
cwe_ids:
  - CWE-79
chains_with:
  - attack-dom-xss
  - attack-csrf
  - attack-cache-poison
  - attack-file-upload
prerequisites: []
severity_boost:
  attack-dom-xss: "Server-rendered XSS checks complement source-to-sink analysis for browser-only flows."
---

# Cross-Site Scripting Validation

## Objective

Establish whether untrusted input is interpreted as script or unsafe HTML in a real browser, identify the affected context, and document minimum impact. Use test-owned content; never collect cookies/tokens, impersonate users, or persist payloads in shared production content.

## Scope

- Only submit payloads into fields the tester owns or controls (own profile, own ticket, a disposable test record). Never craft a PoC intended to be delivered to, clicked by, or viewed by a real third party, admin, or support agent.
- Out-of-band confirmation for blind/stored XSS (a collaborator/callback beacon) is limited to the engagement's own listener, planted only in fields explicitly in scope, and must be tracked and removed/expired promptly — never leave an unbounded number of beacons running unattended across the target.
- Never read `document.cookie`/storage, exfiltrate data off-target, call state-changing APIs, or alter another account's settings from a PoC, even when execution is confirmed. A harmless, self-contained proof (e.g., a benign DOM mutation on the tester's own page) is sufficient.
- File-upload XSS testing (SVG/HTML content-type confusion) is limited to content the tester uploads to their own account; never pivot an uploaded payload into a shared/public gallery or feed.

## Testing Methodology

### Phase 1: Map input and rendering paths

Review query parameters, profile text, support tickets, labels, Markdown/wiki renderers, search results, upload previews, URL fragments, and non-obvious reflected fields (`User-Agent`, `Referer`, redirect/`return_url`/UTM parameters) that admin tooling, logs, or analytics dashboards may render later. Determine whether input is reflected immediately, stored and rendered later, or read by client code. Establish a clean baseline and disposable test record.

### Phase 2: Probe the output context

Submit a unique inert marker containing context-appropriate delimiters (e.g., `aaa"bbb'ccc<ddd>eee`fff`) and inspect raw response and browser-parsed DOM. Use an 8+ character random alphanumeric marker, never a common word (`test`, `payload`, `script`) — first search the unmodified baseline response for that exact marker, since help text, hrefs, or boilerplate can contain the same substring and produce a false "reflection." Identify HTML-text, attribute, URL, CSS, JavaScript, or template context. Confirm context-specific escaping; avoid long WAF-bypass lists. Before treating any reflected/stored tag as a finding, identify the rendering framework (React/Vue/Angular/Svelte all auto-escape by default) and confirm the specific field reaches a known-dangerous sink (`dangerouslySetInnerHTML`, `v-html`, `[innerHTML]`, `{@html}`, raw `innerHTML`/`document.write`/`eval`) rather than assuming presence implies exploitability.

### Phase 3: Validate execution safely

If the program permits active XSS testing, use a minimal harmless browser proof on a tester-owned record and remove it immediately. For a sanitizer believed to allow mutation-XSS, a single bounded tag-combination probe (e.g., `<svg><style>` or `<math><style>` nesting) on the tester's own content is sufficient to show the mutation; do not chain it with data exfiltration. Do not read document.cookie/localStorage, send data externally, alter account settings, or run it in another user's view. If active execution is not authorized, stop at the inert canary and source-to-sink evidence.

### Phase 4: Trace DOM and framework sinks

Inspect location/hash/search, postMessage, storage, and API sources alongside innerHTML, document.write, eval, unsafe URL assignment, and raw-rendering escape hatches. For postMessage handlers, check whether `event.origin` is validated correctly (a missing check, or a weak `indexOf`/`endsWith` comparison that a crafted hostname like `target.com.attacker.com` can pass) before treating the handler as a safe boundary. Verify whether encoders, sanitizers, allowlists, and framework protections apply on the actual path.

### Phase 5: Classify persistence and audience

Determine whether content affects only the submitting account, another tester-owned account, or a shared page. For stored behavior use two controlled accounts. Check whether responses carrying the tested input are cacheable (`Cache-Control: public`) and whether an unkeyed input (e.g., `X-Forwarded-Host`) could turn a reflected finding into a cache-wide one — note this as a chain hypothesis with `attack-cache-poison`, not as an executed attack against shared cache state. Review CSP as defense in depth; missing CSP alone is not an XSS vulnerability. Note separately whether an `image/svg+xml` response is covered by the same CSP as HTML responses, since CSP is sometimes not applied to SVG.

## What Constitutes a Finding

- **Candidate / lead:** input is reflected, appears unescaped, or reaches a potentially dangerous DOM sink.
- **Confirmed finding:** controlled input executes in a current browser in the target security origin, or an authorized code-review establishes an exploitable reachable path where live execution is prohibited.
- **Impact-qualified finding:** persistence and affected test-account role are established without accessing another person's session or data.
- **Not a finding:** inert/escaped reflection, self-XSS without a realistic authorized trigger, or an alert shown only by a tool/extension.

## Impact

Severity tracks what the execution context actually reaches, not the mere fact that script ran:

- **Low:** self-XSS with no realistic, authorized delivery to another account; or a harmless DOM mutation confirmed only in the tester's own session with no state-changing or data-reading capability demonstrated.
- **Medium:** reflected or stored XSS confirmed to execute in a current browser against a tester-owned record, on a page with limited blast radius (e.g., a non-shared settings page), without a demonstrated path to another user's session or data.
- **High:** stored XSS confirmed to affect a second tester-controlled account (cross-account execution), a confirmed path from DOM/postMessage sink to session-bearing storage, or XSS on a shared/collaborative surface (wiki, ticket, comment) that would predictably reach other viewers.
- **Critical:** XSS confirmed or strongly evidenced (via authorized OOB beacon) to execute in a privileged context (admin panel, SSO/sign-in page, OAuth callback handling a token in the URL fragment), or chained with another primitive (CSRF to plant a self-XSS payload, cache poisoning to make a reflected payload CDN-wide, or a sanitizer/CSP bypass reaching a trusted origin) to reach account takeover or token theft.

Chain impact honestly: do not report "Critical" from `alert(1)` alone — state the terminal capability (session/token theft, privileged action, mass-victim delivery) and how execution reaches it, or report the lower tier that the actual evidence supports.

## Evidence Requirements

- Sanitized request, exact input path, test-owned record identifier, and timestamp.
- Raw response and DOM/browser screenshot showing the execution context, or clear source-to-sink evidence if execution is prohibited.
- Content-Type, CSP, encoding behavior, account role, and reflected/stored/DOM classification.
- Before/after comparison and confirmation that test content was removed.
- Never capture session tokens, private data, or exfiltration.

## Tools

- **Burp Suite Repeater/Proxy:** trace input through request and response.
- **Browser DevTools:** inspect parsed DOM, sources/sinks, CSP, and console behavior.
- **DOM Invader or equivalent:** identify candidate DOM paths for manual verification.
- **OOB collaborator client (Burp Collaborator or equivalent):** authorized confirmation of blind/stored XSS when delivery and viewing happen out of band; distinguish a browser-UA callback from a backend HTTP client fetching the same URL.
- **Static search:** locate unsafe rendering APIs and framework escape hatches, e.g. `grep -rn "innerHTML\|document\.write\|eval(\|dangerouslySetInnerHTML\|v-html\|\[innerHTML\]\|\{@html\}" --include="*.js"`.

## Rendering Context and Impact Matrix

| Context | Review | Evidence standard |
|---|---|---|
| HTML text | Context-aware HTML encoding | Canary remains text rather than markup |
| Attribute | Attribute encoding and safe-attribute allowlist | Input cannot break into a script-capable attribute |
| URL/link | URL parsing and allowed-scheme policy (`javascript:`, `data:`, `vbscript:`) | Dangerous schemes are rejected by policy, not substring filtering |
| JavaScript/JSON | Serialize data; do not interpolate into executable code | Parsed value remains data |
| DOM source-to-sink | URL, fragment, message, or storage to script-capable sink | Reachable flow and browser interpretation are established |
| Framework escape hatch | `dangerouslySetInnerHTML`/`v-html`/`[innerHTML]`/`{@html}` reachable from the tested field | Confirms the one exception to the framework's default auto-escaping |
| mXSS / tag-combination | Allowlist sanitizer tested with nested tag combos (`<svg><style>`, `<math><style>`) on tester-owned content | Browser re-parse mutates sanitizer-safe output into an executable sink |
| postMessage handler | `event.origin` validation strength (missing, or weak substring match) | A crafted origin bypasses the check in a controlled test page |
| Shared/stored content | Two tester-owned accounts | Persistence and audience are documented without victim delivery |
| SVG/Markdown/rich text | Maintained allowlist, safe origin/content headers, and whether CSP applies to `image/svg+xml` separately from HTML | Sanitizer and CSP are not assumed infallible |

**Mitigation / regression:** encode for the exact output context, avoid unsafe DOM APIs, sanitize rich HTML with a maintained allowlist, validate URL schemes, and test the same rendering path in a current browser.

## Verification and False Positives

- Reflection does not equal execution; inspect the browser-parsed DOM, not response text alone.
- Encoding, sanitizers, framework escaping, CSP, Trusted Types, and sandboxed origins can prevent script interpretation.
- Self-XSS visible only to the submitting account is not stored cross-user XSS without a realistic, authorized trigger.
- Extensions, injected DevTools snippets, stale caches, and service workers can mislead; repeat in a clean browser profile.
- A request-validator rejection (different status code on `<`/`"`) is WAF/validator noise, not an XSS signal; a payload shown HTML-encoded (`&lt;script&gt;`) or URL-encoded inside an attribute value (the browser does not decode percent-encoding inside an HTML attribute) is correct encoding, not a finding.
- No current shipping browser has an "XSS Auditor" (removed from Chrome in 2019) — never attribute a failed PoC to one; look at the actual sink/encoding instead.
- For blind/stored XSS, a callback firing from a backend HTTP client (not a browser User-Agent) is not confirmation — only a browser-originated callback after storage/queueing proves execution.
- Do not test real users, bypass CSP by chaining unrelated weaknesses, or access token-bearing storage.

## Stop Conditions

- Stop and do not deliver a payload if the only way to reach another user's view requires targeting a specific real third party, admin, or support agent outside an explicitly authorized blind-XSS program.
- Stop and remove/expire any OOB beacon once its purpose is served; do not leave broad, untracked beacon coverage running after the test window.
- Stop before reading cookies/storage, exfiltrating data, or calling any state-changing endpoint from a confirmed PoC — capture a screenshot/DOM proof instead.
- Stop and reconfirm scope if a payload unexpectedly reaches a cache layer, a shared/public surface, or appears to affect sessions other than the tester's own.

## Defensive Notes

Context-aware output encoding (HTML-body, attribute, URL, JS, CSS) applied by the templating/framework layer closes most of this class; treat any raw-rendering escape hatch (`dangerouslySetInnerHTML`, `v-html`, `innerHTML`, `.html_safe`) as a reviewed exception, not a convenience default. Maintain and regularly re-test allowlist HTML sanitizers against mutation-XSS (mXSS) tag-combination bypasses, since sanitizer patches are frequently incomplete. Apply Content-Security-Policy (ideally nonce/hash-based, with Trusted Types where supported) consistently across content types — including `image/svg+xml` responses and cached/CDN-fronted pages — and serve untrusted uploads from a separate, cookieless origin with `Content-Disposition: attachment` where executable rendering is not required.

## References

- [uphiago/recon-skills — hunt-xss](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-xss)
- [elementalsouls/Claude-BugHunter — hunt-xss](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-xss)
- [OWASP — Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
