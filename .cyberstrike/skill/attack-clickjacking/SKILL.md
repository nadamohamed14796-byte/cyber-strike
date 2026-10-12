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

- **Browser DevTools:** inspect frame behavior and CSP console messages.
- **curl:** capture route-specific headers.
- **Local HTML page:** reproduce framing from a test origin.
- **Burp Suite:** compare redirects/error paths.

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

- [Claude-BugHunter — hunt-clickjacking](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-clickjacking)
- [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
