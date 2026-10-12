---
name: attack-csrf
description: "Validate cross-site request forgery by checking whether a browser can cause a state-changing action without intended request-boundary protections."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - csrf
  - cookies
  - browser
  - web
  - state-change
tech_stack:
  - web
  - html
  - javascript
  - rest-api
cwe_ids:
  - CWE-352
chains_with:
  - attack-session
  - attack-xss
  - attack-business-logic
prerequisites: []
severity_boost:
  attack-xss: "XSS may bypass browser-side CSRF protections, but each issue needs independent evidence."
---

# Cross-Site Request Forgery Assessment

## Objective

Determine whether a browser sends an authenticated state-changing request that lacks required intent/origin validation. Test a controlled account and reversible test state; never trigger actions for other users.

## Scope

- Only test accounts the tester owns or was explicitly provisioned for the engagement. Never craft a PoC intended to be delivered to, clicked by, or visited by a real third-party user, in-scope or not.
- Reversible, low-impact mutations only during live testing (e.g., a display-name or preference field). Security-sensitive mutations (password/email change, MFA enrollment/removal, payment, account deletion) are modeled and reasoned about, not actually triggered, unless the engagement explicitly authorizes it with a disposable account.
- A local/staging HTML PoC page is acceptable for reproduction; it must never be hosted where it could be reached by anyone other than the tester.

## Testing Methodology

### Phase 1: Map state-changing endpoints

Inventory mutations to profile, preferences, security settings, and other account-owned state. Select a harmless reversible field in a tester-owned account.

### Phase 2: Review browser protections

Inspect SameSite/Secure/HttpOnly cookies, CSRF tokens, Origin/Referer validation, content-type requirements, and credentialed CORS behavior.

### Phase 3: Capture legitimate baseline

Perform the change normally and capture the request, token presence, headers, redacted cookies, and resulting state. Restore the baseline before testing.

### Phase 4: Test in lab/staging

Replay the same harmless state change with only the suspected defense omitted or via a controlled cross-site form request. Verify the browser sends the session and the server persists the change. Do not ask real users to visit a PoC.

### Phase 5: Verify and clean up

Confirm the server-side result, restore the test value, and distinguish CSRF from CORS or XSS.

## What Constitutes a Finding

- **Candidate / lead:** a mutation endpoint lacks an obvious token or relies only on cookies.
- **Confirmed finding:** controlled cross-site browser request causes a protected state change on the tester's account without required intent validation.
- **Not a finding:** read-only GET, UI-only change, or request blocked by effective browser/server defenses.

## Impact

Severity tracks what the forged request actually controls, not the mere absence of a token:

- **Low:** cosmetic or easily-reversible preference with no security or financial consequence.
- **Medium:** data exposure to the attacker's own planted state, non-sensitive profile changes, or an action a victim would need to notice to undo.
- **High/Critical:** account takeover primitives (email/password change, MFA removal, API key or OAuth app linkage), financial transactions, or privilege/role changes — especially when the forged request can run silently without user-visible feedback.

State the exact mutation reached, the privilege level required to exploit it, and whether the attacker needs a victim to be authenticated and simply visit a page, or to also perform an action.

## Evidence Requirements

- Legitimate request and controlled cross-site variant with differences highlighted.
- Cookie attributes, Origin/Referer behavior, role, timestamp, and reversible field changed.
- Before/after server-side state and cleanup proof.
- Never deliver proof to third parties or include session tokens.

## Tools

- **Browser DevTools:** confirm cookie behavior and actual browser request.
- **Burp Suite:** compare normal and reduced-defense requests.
- **Local/staging test page:** safely reproduce cross-origin forms.
- **Source review:** validate CSRF middleware coverage.

## CSRF Defense Decision Matrix

| Defense | Validation question | Insufficient alone |
|---|---|---|
| CSRF token | Required and bound to session/action? | Hidden field exists |
| SameSite | Does browser send session in this context? | Cookie attribute without browser reproduction |
| Origin/Referer | Are cross-site origins rejected? | Response code without state comparison |
| Content-Type | Are cross-site simple forms accepted unexpectedly? | JSON endpoint status alone |
| CORS | Can foreign origin read response or only trigger request? | CORS header issue alone |
| Fresh authentication | Is sensitive action gated by fresh proof? | UI prompt if API bypasses it |

**Mitigation:** framework CSRF protections, synchronizer/double-submit tokens, origin validation for sensitive actions, appropriate SameSite, and no state-changing GET.

## Verification and False Positives

- Browser restrictions vary by method, content type, cookie policy, and browser; test the real context.
- CORS read permission and CSRF triggering are different properties.
- Repeater is not a browser-origin context.
- Stop before credential changes, MFA removal, payments, or irreversible actions.


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

- [uphiago — hunt-csrf](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-csrf)
- [Claude-BugHunter — hunt-csrf](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-csrf)
- [OWASP CSRF Prevention Cheat Sheet](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.md)
