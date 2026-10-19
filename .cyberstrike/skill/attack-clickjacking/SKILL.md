---
name: attack-clickjacking
description: "Assess framing controls and user-interface redressing exposure with controlled pages and test accounts without tricking real users into sensitive actions."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - clickjacking
  - frame-ancestors
  - x-frame-options
  - browser
tech_stack:
  - web
  - html
  - javascript
  - oauth
cwe_ids:
  - CWE-1021
chains_with:
  - attack-csrf
  - attack-auth-bypass
prerequisites: []
severity_boost:
  attack-csrf: "A frameable state-changing interface may combine with a separate CSRF weakness; validate each boundary independently."
---

# Clickjacking and Framing Control Assessment

## Objective

Determine whether sensitive pages can be embedded by an untrusted origin and whether framing could expose a meaningful user action. Validate locally with your own account; do not trick real users.

## Testing Methodology

### Phase 1: Identify sensitive pages

Inventory login, security settings, admin actions, consent, and other pages where interaction changes a security-relevant state. Use only in-scope pages and tester-owned accounts.

### Phase 2: Inspect framing policy

Review CSP frame-ancestors, X-Frame-Options, legacy frame-busting logic, and route differences among redirects, error pages, and alternate subdomains.

### Phase 3: Build a controlled frame test

Use a local HTML page under an origin you control to check whether a page renders in a frame. Observe rendering and browser console only; do not overlay deceptive controls or cause a protected action.

### Phase 4: Evaluate interaction consequence

Determine whether a frameable page exposes a meaningful action and whether re-authentication, confirmation, CSRF, or origin protections block it. Use a disposable test action only if explicitly authorized.

### Phase 5: Compare route coverage

Check login redirects, legacy paths, and error responses for consistent framing controls. Do not test unrelated identity-provider pages without written scope.

## What Constitutes a Finding

- **Candidate / lead:** sensitive page lacks frame restrictions or loads inside a controlled frame.
- **Confirmed finding:** an in-scope sensitive interface is frameable and has a plausible security consequence under the program policy.
- **Not a finding:** a public non-sensitive page is frameable or no meaningful interaction is exposed.

## Evidence Requirements

- Exact route, response headers, timestamp, and browser version.
- Screenshot of controlled frame and console evidence.
- Identify the sensitive action and available interaction guards; do not perform real financial/admin actions.
- State whether proof was framing-only or an approved test action.

## Tools

- `curl`: capture route-specific headers and redirect chains for an observed authorized URL.
- Python `httpx`: compare CSP/X-Frame-Options across documented routes.
- `rg`: inspect local source/configuration for framing policy and sensitive actions.
- Playwright headless API may test a local fixture when effective framing behavior needs reproduction; it is optional, not a core dependency.

Verify with `curl --version` and the selected Python client. Official docs: https://curl.se/docs/, https://www.python-httpx.org/, https://playwright.dev/python/.

## Framing Policy Matrix

| Control | Expected behavior | Validation |
|---|---|---|
| CSP frame-ancestors | Only documented trusted parents allowed | Untrusted local origin cannot embed page |
| X-Frame-Options | DENY/SAMEORIGIN where compatible | Browser enforces exact response header |
| Action confirmation | Fresh proof reduces impact | Verify guard without completing sensitive action |
| Redirect/error page | Framing policy persists | Inspect every response in the chain |
| SSO/consent | Framing matches documented design | Test only owned tenant and scoped provider surface |

**Mitigation:** set restrictive frame-ancestors, maintain compatible X-Frame-Options, avoid sensitive actions in frameable pages, and regression-test redirects/errors.

## Verification and False Positives

- Header inspection may miss CDN/middleware behavior; validate in a browser.
- Trusted partner embedding may be intentional; verify exact allowlist matching.
- Frameability is a prerequisite, not always an exploit by itself.
- Never use real-user clickjacking or deceptive delivery pages.


## Adaptive Verification Contract (evidence-driven; no arbitrary attempt ceiling)

Continue testing materially distinct, evidence-producing hypotheses while the candidate remains plausible and a meaningful next branch exists. Do not impose a fixed attempt ceiling or count cosmetic retries as new hypotheses. Stop when direct evidence confirms or disproves this hypothesis, no meaningful new branch remains, a valid prerequisite is unavailable, or program/safety rules require stopping; unresolved cases remain inconclusive.

Keep a ledger per attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve evidence, redact secrets, and avoid unrelated data.

### Skill-specific hypothesis order

1. Inspect effective CSP frame-ancestors and X-Frame-Options on the exact sensitive route, including redirects and relevant authenticated response paths.
2. Test framing in a controlled local page and a separate unauthenticated/benign route as controls; distinguish an intentional public embed from a private authenticated action exposed to framing.
3. Identify a meaningful victim-triggered action and test only with your own disposable account/data. Demonstrate whether a framed interaction could submit that action—not merely whether the page can be displayed in an iframe.
4. Compare routes, browser behavior, CSP inheritance, and frame-busting scripts one at a time; do not bypass browser security controls or use third-party users as victims.
5. Capture the response headers, controlled proof page, exact action, and before/after test state. Stop and clean up the test resource after evidence collection.


### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture, with a relevant control and a clear trust-boundary failure.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause is not established.
- **Unconfirmed:** the signal is ambiguous, cached, generic, or not tied to a security boundary.
- **Refuted / false positive:** a relevant negative control, valid authorization explanation, or repeatable contradictory evidence explains the signal. Record the attempts; do not claim every theoretical variant was exhausted.
- Status, banners, stack traces, response length, endpoint existence, tool alerts, or frontend state are not sufficient on their own.

### Stop, cleanup, and handoff

Stop at scope boundaries, unexpected real-user data, production side effects, rate-limit/availability degradation, secret exposure, or prohibited action. Clean up disposable state, revoke temporary sessions/tokens when possible, and record status. Return target/scope evidence, baseline, hypothesis, attempts used, impact, controls, verdict/confidence, sanitized evidence, handoff signal, and cleanup status. Trigger a chained skill only when its signal is observed.

## References

- [Claude-BugHunter — hunt-clickjacking](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-clickjacking)
- [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)


## Header-first field check
Fetch only an in-scope page and inspect the actual response headers for every relevant route; a home page's policy may not cover account, consent, or administrative screens.

```bash
curl -sS -D response.headers -o /dev/null "$TARGET_URL"
grep -iE '^(content-security-policy|x-frame-options|content-type|set-cookie):' response.headers
```

If headers are absent or weak, confirm the browser-effective frame-ancestors policy and whether a sensitive action can be framed and triggered in a controlled browser using your own test account. Missing X-Frame-Options by itself is not impact when CSP already blocks framing or the page has no sensitive interaction. Chain only confirmed context to attack-security-headers, attack-csrf, or session/auth skills.


## Enrichment: route-level header inspection
Inspect every sensitive route, not just the home page. Verify the browser-effective CSP frame-ancestors directive and X-Frame-Options behavior, then use a controlled browser and your own test account to establish whether a meaningful action can be framed. Missing X-Frame-Options is not itself a finding when CSP already blocks framing or the page has no sensitive interaction. Chain to security-headers and CSRF checks only when the corresponding browser behavior is observed.


## Targeted quality-loop enrichment (2026-10-19)

### Interaction consequence, not frameability alone
Inventory sensitive views and test whether a controlled foreign-origin page can render the exact route while signed in to a disposable account. Preserve screenshots/console policy evidence but do not overlay deceptive UI or trigger a sensitive action. A meaningful chain requires all links: framing is allowed, the intended victim context would be authenticated, a user gesture could trigger a security-relevant state transition, and existing confirmation/CSRF/origin defenses do not prevent it. Chain to CSRF only when a distinct request-forgery weakness is evidenced; missing X-Frame-Options alone is not impact. Record route-specific differences because login/error/public routes may legitimately be frameable.


## Practical tooling, references, and helper scripts (2026-10-19)

### Tools that fit this skill
- Browser DevTools, Burp Proxy/Repeater/Comparer, and curl for a replay of one observed request. Verify optional CLIs locally and use only tools exposed by the current runtime.
- Treat CLIs as optional until locally verified; prefer read-only checks. State-changing tests require permission and a disposable fixture.

### Primary resources
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — test methodology.
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — controlled labs.
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/) — mitigation guidance.

### Small reusable helper
    python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt
Compares local artifacts offline and heuristically redacts common secrets; it sends no requests and cannot prove complete sanitization.

### Evidence and hand-off
- Keep cookies, tokens, reset links, private user data, and secret values out of notes, global research storage, and Git commits. Keep private originals local; share only reviewed derivatives.
- Mark outcomes confirmed, disproven, or still hypothetical. Record tool errors and coverage gaps rather than inventing results.

Compare a known-good baseline with a control, vary one meaningful property, and record alternative explanations before calling a lead confirmed.


## Agent-executable CLI tooling, resources, and helper scripts

### Tools
- `curl` — capture route-specific response headers for an observed, authorized URL.
- Python `httpx` — compare headers across documented routes and save structured results.
- `rg` — search local source/configuration for frame policy, CSP, and sensitive actions.
- Playwright's headless CLI/API may be used against a local fixture when effective frame behavior needs reproduction; do not require interactive browser DevTools.

### Installation and verification
Verify `curl --version` and the chosen Python client. Official docs: https://curl.se/docs/, https://www.python-httpx.org/, and https://playwright.dev/python/. If a headless browser dependency is unavailable, report that effective framing was not tested and use header/source review only.

### Resources
- https://portswigger.net/web-security/clickjacking
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors

### Reusable helper
`curl -sS -D headers.txt -o /dev/null --max-time 15 https://IN-SCOPE-HOST/PATH` saves one authorized response's headers. Redact cookies before sharing; headers alone do not prove exploitability.

### Result handling
Verify effective framing in a local fixture or approved test environment when possible. Explain whether a sensitive authenticated action can be framed and why it matters; do not treat a missing header alone as confirmed impact.