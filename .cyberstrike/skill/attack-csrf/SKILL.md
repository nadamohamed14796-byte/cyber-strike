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


## Adaptive Verification Contract (evidence-driven; no arbitrary attempt ceiling)

Continue testing materially distinct hypotheses while they remain plausible and new evidence can resolve the question; do not impose a fixed attempt ceiling. Stop when direct evidence resolves the hypothesis, no meaningful branch remains, a prerequisite is genuinely unavailable, or program/safety rules require it. Cosmetic retries do not count as new strategies.

Keep a ledger per attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve evidence, redact secrets, and avoid unrelated data.

### Skill-specific hypothesis order

1. Identify one state-changing endpoint and baseline its normal behavior with a test-owned account; document whether authentication uses ambient cookies, bearer headers, or another browser-sent credential.
2. Check anti-CSRF token enforcement by omitting, invalidating, replaying, or cross-session binding the token one condition at a time; a missing token is not a finding if another robust defense applies.
3. Evaluate Origin/Referer validation, cookie SameSite settings, content-type requirements, and CORS as separate defenses. Do not conflate CORS read restrictions with CSRF write prevention.
4. Demonstrate the state change only against a disposable test record using a local controlled page or approved harness, then restore the record and record cleanup.
5. Compare a legitimate request, an invalid-token request, and a cross-origin attempt. Confirm the server-side state—not merely a successful HTTP response—changed without the required user intent.


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


## Enrichment: browser-triggered state change
Use only a controlled account and a disposable object. Compare the normal same-site state-changing request with a controlled cross-origin browser attempt, then re-read the object's state and capture the actual server decision. Record whether cookies are sent, which SameSite policy applies, token validation, and Origin/Referer behavior. A missing token is not sufficient if another server-side control rejects the request. Chain to session management or clickjacking only when the respective condition is shown independently.


## Targeted quality-loop enrichment (2026-10-19)

### CSRF request-pair and state proof
Use a disposable test account, a reversible state-changing feature, and a baseline request captured from the legitimate UI. Test the same operation through a locally hosted cross-origin page or documented test harness, varying one defense dimension at a time (token, Origin/Referer, SameSite cookie behavior, content type, or required custom header). Confirm the server-side state transition, then restore it. A 2xx response without a state change is not proof; JSON CORS constraints and SameSite behavior may be valid defenses. Chain to clickjacking only when framing/interaction is separately shown, or session/cookie review only when ambient credentials are the enabling condition.

## Advanced branch: distinguish request trigger, credential inclusion, and response readability

These are three separate questions and must be logged separately:
1. Can a cross-site context cause the browser to send the mutation?
2. Does the browser attach the ambient credential under the actual cookie/SameSite and fetch context?
3. Does the attacker need to read the response, or is a blind state change enough?

A CSRF can succeed without reading the response. Conversely, CORS can allow a read without enabling a state-changing request. Do not use a successful curl/Repeater replay as proof of a cross-site browser attack.

### Safe request-pair checklist

- Save a sanitized legitimate baseline: method, URL, content type, Origin/Referer, CSRF token location, custom headers, cookie names/attributes, and before-state.
- Use only a local proof page and a disposable test-owned record. Never embed a real session token or target a real user.
- Change one defense dimension per comparison: remove token; use a different test-session token; change Origin; use a browser-compatible simple form; or inspect whether SameSite suppresses the cookie.
- Re-read server-side state through the legitimate UI/API after each attempt. A 2xx, redirect, or generic success message is not enough.
- Restore the original value after proof and retain sanitized evidence of cleanup.

```html
<!doctype html>
<meta charset="utf-8">
<title>Local CSRF test harness — use only with a disposable in-scope account</title>
<form method="POST" action="https://TARGET-HOST.example/account/preferences">
  <input type="hidden" name="displayName" value="csrf-test-marker">
  <button type="submit">Send controlled test request</button>
</form>
```

Replace the example host/path/field with the exact in-scope endpoint and a reversible field from a tester-owned account. This is a manual harness template, not a claim that a target is vulnerable. Do not add credentials, tokens, destructive fields, or automatic submission.

### Chain decision table

| Observed prerequisite | Next skill | What must be independently proven |
|---|---|---|
| Browser includes ambient session cookie on a cross-site request | attack-session | Cookie/session behavior actually enables the state change |
| Sensitive action can be framed and requires a user click | attack-clickjacking | Framing is possible and the interaction has meaningful effect |
| Foreign origin can read sensitive response bytes | attack-cors | Browser JavaScript can read controlled synthetic sensitive data |
| Cross-site request causes an unintended business workflow transition | attack-business-logic | Workflow rule is violated beyond the generic CSRF condition |
| Script executes on the trusted origin and can act with its privileges | attack-xss | A separate script-execution path exists; do not infer XSS from CSRF |

### Output additions

Persist browser_context, credential_included, cross_site_request_sent, response_readable, server_state_changed, defense_variant, negative_control, cleanup_verified, and chain_basis. If any of the first three browser facts is unknown, mark the result inconclusive rather than filling gaps with assumptions.


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

### Agent-usable CLI tools
- `curl` or Python `httpx`: compare a captured, authorized state-changing request with and without the expected anti-CSRF control, using tester-owned accounts and disposable changes.
- `jq` and `rg`: parse saved response data and inspect local code/configuration for token validation and cookie settings.
- `python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt`: compare saved response samples offline.
### Installation and verification
Verify `curl --version`, `python3 -c "import httpx; print(httpx.__version__)"`, and `jq --version`. Official docs: https://curl.se/docs/, https://www.python-httpx.org/, https://jqlang.org/. Missing tools: use a local fixture or source review and record the gap.
### Resources
- https://owasp.org/www-project-web-security-testing-guide/
- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
### Proof and limits
Use only tester-controlled accounts and reversible test actions. Record token, Origin/Referer, SameSite, and state-change controls; do not alter another user's data.
