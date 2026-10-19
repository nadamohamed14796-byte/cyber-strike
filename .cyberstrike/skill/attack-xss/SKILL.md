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

## Testing Methodology

### Phase 1: Map input and rendering paths

Review query parameters, profile text, support tickets, labels, Markdown/wiki renderers, search results, upload previews, and URL fragments. Determine whether input is reflected immediately, stored and rendered later, or read by client code. Establish a clean baseline and disposable test record.

### Phase 2: Probe the output context

Submit a unique inert marker containing context-appropriate delimiters and inspect raw response and browser-parsed DOM. Identify HTML-text, attribute, URL, CSS, JavaScript, or template context. Confirm context-specific escaping; avoid long WAF-bypass lists.

### Phase 3: Validate execution safely

If the program permits active XSS testing, use a minimal harmless browser proof on a tester-owned record and remove it immediately. Do not read document.cookie/localStorage, send data externally, alter account settings, or run it in another user's view. If active execution is not authorized, stop at the inert canary and source-to-sink evidence.

### Phase 4: Trace DOM and framework sinks

Inspect location/hash/search, postMessage, storage, and API sources alongside innerHTML, document.write, eval, unsafe URL assignment, and raw-rendering escape hatches. Verify whether encoders, sanitizers, allowlists, and framework protections apply on the actual path.

### Phase 5: Classify persistence and audience

Determine whether content affects only the submitting account, another tester-owned account, or a shared page. For stored behavior use two controlled accounts. Review CSP as defense in depth; missing CSP alone is not an XSS vulnerability.

## What Constitutes a Finding

- **Candidate / lead:** input is reflected, appears unescaped, or reaches a potentially dangerous DOM sink.
- **Confirmed finding:** controlled input executes in a current browser in the target security origin, or an authorized code-review establishes an exploitable reachable path where live execution is prohibited.
- **Impact-qualified finding:** persistence and affected test-account role are established without accessing another person's session or data.
- **Not a finding:** inert/escaped reflection, self-XSS without a realistic authorized trigger, or an alert shown only by a tool/extension.

## Evidence Requirements

- Sanitized request, exact input path, test-owned record identifier, and timestamp.
- Raw response and DOM/browser screenshot showing the execution context, or clear source-to-sink evidence if execution is prohibited.
- Content-Type, CSP, encoding behavior, account role, and reflected/stored/DOM classification.
- Before/after comparison and confirmation that test content was removed.
- Never capture session tokens, private data, or exfiltration.

## Tools

- `rg`: locate unsafe rendering APIs and framework escape hatches in collected source.
- `semgrep`: scan an authorized local checkout for relevant XSS patterns.
- `dalfox`: optional candidate analysis against explicitly authorized endpoints, with low-impact settings.
- Python `httpx` or `curl`: reproduce an observed request and compare controlled input/response behavior.
- `python3 .cyberstrike/skill/scripts/js_endpoint_inventory.py ./javascript`: inventory local route candidates; not proof of XSS.

Verify `rg --version`, `semgrep --version`, `dalfox --help`, and the chosen request client. Official docs: https://semgrep.dev/docs/getting-started/, https://github.com/hahwul/dalfox, https://curl.se/docs/.

## Rendering Context and Impact Matrix

| Context | Review | Evidence standard |
|---|---|---|
| HTML text | Context-aware HTML encoding | Canary remains text rather than markup |
| Attribute | Attribute encoding and safe-attribute allowlist | Input cannot break into a script-capable attribute |
| URL/link | URL parsing and allowed-scheme policy | Dangerous schemes are rejected by policy, not substring filtering |
| JavaScript/JSON | Serialize data; do not interpolate into executable code | Parsed value remains data |
| DOM source-to-sink | URL, fragment, message, or storage to script-capable sink | Reachable flow and browser interpretation are established |
| Shared/stored content | Two tester-owned accounts | Persistence and audience are documented without victim delivery |
| SVG/Markdown/rich text | Maintained allowlist and safe origin/content headers | Sanitizer and CSP are not assumed infallible |

**Mitigation / regression:** encode for the exact output context, avoid unsafe DOM APIs, sanitize rich HTML with a maintained allowlist, validate URL schemes, and test the same rendering path in a current browser.

## Verification and False Positives

- Reflection does not equal execution; inspect the browser-parsed DOM, not response text alone.
- Encoding, sanitizers, framework escaping, CSP, Trusted Types, and sandboxed origins can prevent script interpretation.
- Self-XSS visible only to the submitting account is not stored cross-user XSS without a realistic, authorized trigger.
- Extensions, injected DevTools snippets, stale caches, and service workers can mislead; repeat in a clean browser profile.
- Do not test real users, bypass CSP by chaining unrelated weaknesses, or access token-bearing storage.

## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Follow materially distinct, authorized branches while evidence can change the conclusion; deduplicate cosmetic payload variants and exact retries. Stop when execution/impact is resolved, relevant branches are exhausted, prerequisites are unavailable, or scope/safety requires stopping. This does not override program rate limits or safe-production constraints.

Track each attempt as hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired requests and controlled test identities/fixtures; save only minimal sanitized evidence.

### Skill-specific hypothesis order

1. Identify the input source and rendering context (HTML text, attribute, URL, script, DOM sink, or stored content); record a literal baseline and a random nonexistent/benign control.
2. Start with a unique inert canary to find encoding/reflection boundaries, then use only a harmless browser proof on an authorized test page to distinguish text reflection from script execution.
3. Test stored, reflected, and DOM flows separately, using controlled accounts for storage/visibility boundaries and changing one parser/context dimension per hypothesis.
4. Do not read cookies/local storage, capture credentials, beacon private data, or create a payload intended to affect third-party users. Keep demonstrations self-contained and non-persistent where possible.
5. Confirm execution in the relevant browser context and document origin, victim/role preconditions, sanitizer/encoding failure, control behavior, and a context-specific output-encoding regression test.

### Verdict gates

- **Confirmed:** repeatable impact at an explicit in-scope boundary is demonstrated using a controlled identity/fixture and a meaningful control.
- **Likely / needs corroboration:** independent indicators support the candidate, but the consequence or root cause remains uncertain.
- **Unconfirmed:** evidence is generic, ambiguous, cached, or not tied to a security property.
- **Refuted / false positive:** a relevant negative control or valid implementation/policy explanation accounts for the observation. Document tested branches; do not claim all imaginable variants were exhausted.
- Scanner alerts, version strings, banner text, status codes, and response length alone are not proof.

### Stop, cleanup, and handoff

Stop on scope ambiguity, unexpected user data, state changes, service degradation, secret exposure or prohibited behavior. Clean disposable test state and revoke temporary sessions/tokens where possible. Return scope proof, baseline, hypothesis, attempts used, impact, negative controls, verdict/confidence, sanitized evidence and cleanup status. Start a chained skill only when its trigger has been independently observed.

## References

- [uphiago/recon-skills — hunt-xss](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-xss)
- [elementalsouls/Claude-BugHunter — hunt-xss](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-xss)
- [OWASP — Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

## Targeted quality-loop enrichment (2026-10-19)

### Output-context and audience map
For each input, record source, transformations, output context, persistence, affected viewer, and any sanitizer/contextual encoder. Use inert unique markers first; confirm execution only in a controlled browser/test account with a harmless proof. Check reflected, stored, DOM, and template routes separately, and test only the context actually reached (HTML text, attribute, URL, JS, CSS, or DOM sink). A reflected marker, HTML-looking response, or CSP absence is not itself XSS. Confirm whether another user/admin sees the content before claiming stored-impact amplification. Chain to clickjacking/CSRF only when the distinct browser interaction or state-change preconditions are observed, and to session risk only when cookie/session controls actually change the demonstrated impact.

## Source-to-sink inventory for JavaScript-assisted hunting

Use static search to create candidates, then manually trace each source through transformations to a reachable sink. Commands are discovery aids, not proof.

```bash
# Run in a downloaded/authorized source tree; avoid dumping minified bundles wholesale.
rg -n --glob '*.{js,mjs,cjs,ts,tsx,jsx,html,vue,svelte}' \
  'innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function|dangerouslySetInnerHTML|v-html|\$\{.*\}' .
rg -n --glob '*.{js,mjs,cjs,ts,tsx,jsx,html,vue,svelte}' \
  'location\.(hash|search|href)|URLSearchParams|postMessage|message\.data|localStorage|sessionStorage' .
```

Review false matches, templates, sanitizers, framework semantics, and whether the source is attacker-controlled. For every candidate record source, transformations, sink, guard/sanitizer, route/component, execution context, and evidence reference. Never label a grep hit as confirmed XSS.

### Chaining matrix

| Proven observation | Related skill | Required separate evidence |
|---|---|---|
| Input executes in a trusted origin | DOM-XSS / JavaScript analysis | Reachable source-to-sink and browser execution context |
| Executable content is retrieved from an upload | File-upload review | Upload validation and retrieval origin/content behavior |
| A response with attacker-controlled content is replayed from shared cache | Cache poisoning | Shared-cache storage/replay of the altered response |
| Sensitive action is frameable | Clickjacking | A realistic controlled interaction that changes protected state |
| Cross-site request changes state | CSRF | Server-side state change without required intent validation |
| Session compromise is suggested | Session review | Do not read/export cookies; prove impact through a harmless controlled account flow |

### Evidence and regression fields

Add source_location, sink_location, transformation_chain, sanitizer_name_and_version, output_context, execution_origin, persistence_scope, affected_test_role, csp_effective_policy, browser_version, negative_control, cleanup_verified, and regression_case. If no browser execution is permitted, keep the result as a source-to-sink candidate with an explicit limitation.

## Agent-executable CLI tooling, resources, and helper scripts

Use command-line tools and local libraries the agent can run and parse directly. Browser UI, extensions, and interactive proxies are not dependencies. Check the installed version and official usage before running commands, and never report a check as completed unless its output was inspected.

### Tools
- `dalfox` — identify and validate candidate XSS behavior on explicitly authorized targets; begin with low-impact settings and verify every candidate manually.
- `semgrep` and `rg` — review collected source for risky DOM sinks, unsafe rendering, and sanitization boundaries.
- Python `httpx` or `requests` — reproduce an observed request with a controlled input and compare the response.
- `jq` — parse saved JSON results and remove sensitive fields before sharing.
- Existing helper: `python3 .cyberstrike/skill/scripts/js_endpoint_inventory.py ./javascript` — inventory candidate URLs from local JavaScript files; it does not prove a source-to-sink flow.

### Installation and verification
Use the official instructions at https://github.com/hahwul/dalfox and https://semgrep.dev/docs/getting-started/. Verify with `dalfox version` or `dalfox --help`, and `semgrep --version`. Check Python dependencies with `python3 -c "import httpx; print(httpx.__version__)"` or the corresponding `requests` import. If a tool is missing, record that and continue with available source review or local fixtures; do not silently claim success.

### Resources
- https://portswigger.net/web-security/cross-site-scripting
- https://owasp.org/www-project-web-security-testing-guide/
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- https://github.com/hahwul/dalfox
- https://semgrep.dev/docs/

### Evidence and fallback
Record the controllable input, context/encoding, relevant sink, control response, and safe evidence. Reflection alone is not proof of exploitable XSS. Keep credentials and real user data out of fixtures and artifacts. Use a disposable local fixture when live validation is not appropriate.
