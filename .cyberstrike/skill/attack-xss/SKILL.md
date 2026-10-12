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

- **Burp Suite Repeater/Proxy:** trace input through request and response.
- **Browser DevTools:** inspect parsed DOM, sources/sinks, CSP, and console behavior.
- **DOM Invader or equivalent:** identify candidate DOM paths for manual verification.
- **Static search:** locate unsafe rendering APIs and framework escape hatches.

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


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Use the 20-attempt budget as a ceiling for independent evidence-producing hypotheses, not as a quota for payload mutations. Follow relevant signal-led branches only while the candidate remains plausible; stop early on decisive evidence, scope/safety limits, or when no meaningful branch remains. Cosmetic variants are not separate hypotheses.

Track each attempt as hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired requests and controlled test identities/fixtures; save only minimal sanitized evidence.

### Skill-specific hypothesis order

Choose distinct low-impact checks supported by the skill's existing matrix and avoid equivalent probes.

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
