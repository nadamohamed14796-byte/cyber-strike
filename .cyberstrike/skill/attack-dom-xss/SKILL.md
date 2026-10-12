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

## Testing Methodology

### Phase 1: Inventory controllable sources

Search for location.search/hash, document.URL/referrer, postMessage event.data, window.name, local/session storage, and API-returned values. Establish whether a remote party can influence each source in a normal application flow.

### Phase 2: Map sinks and transformations

Review innerHTML, outerHTML, insertAdjacentHTML, document.write, eval, Function, string-based timers, unsafe URL assignments, and framework escape hatches. Trace sanitizers, parsers, decoders, and allowlists; a dangerous API alone is not enough.

### Phase 3: Use inert runtime tracing

Set a unique benign marker at the candidate source and watch it in DevTools or breakpoints. Confirm whether it reaches the sink and whether a safe text API or context encoder intervenes. A marker reaching textContent is not XSS.

### Phase 4: Validate in an authorized browser

If active proof is authorized, use a harmless execution indicator with a tester-owned account and clean up afterward. Never inspect or export cookies, local-storage tokens, OAuth fragments, or another user's message contents. Where live execution is disallowed, preserve the source-to-sink trace and mark active confirmation as pending authorization.

### Phase 5: Check framework and origin boundaries

Determine whether code runs in the application origin, a sandboxed iframe, or a separate content/upload origin. Review exact postMessage origin checks, safe URL APIs, CSP, and Trusted Types.

## What Constitutes a Finding

- **Candidate / lead:** attacker-controlled source data reaches a potentially script-capable sink.
- **Confirmed finding:** an unsafe flow safely demonstrates script execution in an in-scope origin, or code-review evidence establishes a reachable exploitable sink in a review-only engagement.
- **Not a finding:** a source reaches textContent, the value is safely encoded, or it appears only in DevTools without being parsed by the page.

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
- Stop if testing requires delivery to an uninvolved user, tenant crossing, or third-party payload execution.


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Treat the attempt budget as a ceiling for evidence-producing hypotheses, not a quota for payload variants. When a candidate remains plausible, branch to the next independent hypothesis up to a maximum of 20; stop earlier when evidence is decisive, the remaining hypotheses are not relevant, or safety/scope limits apply. Cosmetic variants of the same request do not count as independent attempts.

Keep a ledger per attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve evidence, redact secrets, and avoid unrelated data.

### Skill-specific hypothesis order

Select distinct, low-impact hypotheses from this skill's coverage matrix; avoid repeating equivalent probes.

### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture, with a relevant control and a clear trust-boundary failure.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause is not established.
- **Unconfirmed:** the signal is ambiguous, cached, generic, or not tied to a security boundary.
- **Refuted / false positive:** a relevant negative control, valid authorization explanation, or repeatable contradictory evidence explains the signal. Record the attempts; do not claim every theoretical variant was exhausted.
- Status, banners, stack traces, response length, endpoint existence, tool alerts, or frontend state are not sufficient on their own.

### Stop, cleanup, and handoff

Stop at scope boundaries, unexpected real-user data, production side effects, rate-limit/availability degradation, secret exposure, or prohibited action. Clean up disposable state, revoke temporary sessions/tokens when possible, and record status. Return target/scope evidence, baseline, hypothesis, attempts used, impact, controls, verdict/confidence, sanitized evidence, handoff signal, and cleanup status. Trigger a chained skill only when its signal is observed.

## References

- [uphiago/recon-skills — hunt-dom](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-dom)
- [elementalsouls/Claude-BugHunter — hunt-dom](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-dom)
- [OWASP — DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
