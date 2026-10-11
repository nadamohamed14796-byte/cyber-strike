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

## References

- [uphiago — hunt-csrf](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-csrf)
- [Claude-BugHunter — hunt-csrf](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-csrf)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
