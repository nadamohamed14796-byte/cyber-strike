---
name: attack-oauth
description: "Assess OAuth 2.0 and OpenID Connect redirect validation, state/nonce/PKCE binding, token handling, and client registration with test identities."
category: "identity"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - oauth
  - oidc
  - sso
  - tokens
  - authentication
tech_stack:
  - oauth2
  - oidc
  - web
  - mobile
  - rest-api
cwe_ids:
  - CWE-601
  - CWE-346
  - CWE-352
  - CWE-287
chains_with:
  - attack-ato
  - attack-auth-bypass
  - attack-open-redirect
  - attack-session
  - attack-xss
prerequisites: []
severity_boost:
  attack-ato: "OAuth flaws become ATO only when a controlled flow binds a test client to the wrong principal or exposes a test token."
---

# OAuth 2.0 and OpenID Connect Assessment

## Objective

Validate identity-flow integrity, including client registration, redirect URI matching, CSRF/state, nonce, PKCE, token audience, and callback handling. Exercise only registered test clients, controlled accounts, and explicitly scoped identity-provider surfaces.

## Testing Methodology

### Phase 1: Map the full flow and scope

Locate authorization, token, callback, revocation, metadata, and mobile deep-link endpoints. Read the provider's discovery document and registered redirect URI configuration where available. Verify whether the identity provider is explicitly in scope; don't assume a third-party IdP is included.

### Phase 2: Capture valid baseline

Run a normal authorization-code flow with a test account. Record client ID, exact redirect URI, state, nonce, code challenge/method, issuer, audience, and resulting test principal. Never put production tokens into online decoders.

### Phase 3: Validate redirect URI and state binding

In staging/test client, compare exact registered URI with a different host, path, encoding, duplicate parameter, or open-redirect route under a controlled domain. Check state is unpredictable and bound to initiating browser session. Do not direct codes/tokens to an attacker-controlled external endpoint.

### Phase 4: Check PKCE, nonce, and code binding

Use a test authorization code and verify that omitted/incorrect PKCE verifier, mismatched state, wrong nonce, wrong issuer/audience, expired code, and reused code are rejected. Use fresh flow artifacts; don't replay another user's artifacts.

### Phase 5: Inspect token handling and mobile callbacks

Check whether tokens/codes appear in URLs, logs, referrers, analytics, deep links, or postMessage. Review client secrets in JS/APK as a design issue; public clients must not rely on embedded secrets. Use test credentials and inert canaries.

### Phase 6: Verify identity and clean up

Confirm the resulting principal through a harmless profile endpoint in the test tenant. Revoke test tokens and remove test registrations/artifacts. Distinguish standards/configuration warnings from a demonstrated account/authorization boundary failure.

## What Constitutes a Finding

- **Candidate / lead:** permissive redirect registration, missing state/nonce, optional PKCE, token in URL, or a client secret in a public app.
- **Confirmed finding:** a controlled flow accepts a mismatched callback/state/nonce/PKCE/issuer or binds authorization to a wrong test principal.
- **Impact-qualified finding:** a test token grants a privilege or identity not intended by the registered flow; no real-user token theft is required.
- **Not a finding:** a client ID being public, token response visible to the authorized client, or a redirect that stays on the registered exact URI.

## Evidence Requirements

- Sanitized authorization/token requests, callback sequence, timestamp, test client and account.
- Registered URI versus submitted URI, state/nonce/PKCE outcomes, issuer/audience and resulting test principal.
- Redact authorization codes, client secrets, access/refresh/ID tokens, and PII completely.
- Include configuration or source evidence where response behavior cannot safely prove the control.

## Tools

- **Burp Suite:** compare authorization requests and callbacks.
- **OIDC discovery/JWKS viewer:** inspect metadata and public key configuration.
- **Local JWT decoder:** analyze only test tokens offline.
- **Android/iOS source tools:** review deep-link registration and callback routing when mobile assets are in scope.

## OAuth/OIDC Validation Matrix

| Control | Safe check | Confirmation bar |
|---|---|---|
| redirect_uri | Compare registered URI to controlled invalid variants | Authorization server refuses any non-exact/unregistered URI under its policy |
| state | Initiate two owned flows and cross their state values in staging | Callback cannot complete under mismatched state/session |
| nonce | Use a test ID token with a deliberately mismatched nonce in harness | Client rejects mismatched nonce where OIDC requires it |
| PKCE | Omit or change verifier in test flow | Code exchange fails as required for the client type |
| Code lifecycle | Test expiry and single-use with own code | Expired/reused codes are rejected |
| Issuer/audience | Compare issuer/tenant and client audience | Token from wrong issuer/client is rejected |
| Token leakage | Review callback URL, referrer policy, logs, analytics | Sensitive token/code is not disclosed outside intended client |
| Mobile deep link | Inspect scheme/host allowlist and test harness redirect | External URL cannot replace approved callback target |

**Mitigation:** exact redirect allowlists, session-bound state, nonce validation, PKCE for public clients, strict issuer/audience checks, single-use codes, and no secrets in public clients.

## Verification and False Positives

- OAuth has public identifiers by design; client_id alone is not a secret.
- A redirect to an owned domain or registered URI may be intentional; compare the authorization-server registration.
- A missing parameter is a lead until the resulting flow or source code proves the validation was bypassed.
- Do not trick real users, exchange their codes, exfiltrate tokens, or test third-party IdPs without explicit scope.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

There is no arbitrary fixed ceiling for meaningful verification hypotheses. Continue while a materially different authorized test can change the conclusion; deduplicate semantically identical retries and stop when direct evidence resolves the hypothesis, relevant branches are exhausted, a prerequisite is unavailable, or safety/scope limits apply. This is not permission for unbounded traffic: comply with program rate rules and stop on instability.

Record each attempt: hypothesis, single changed variable, control/baseline, observed signal, interpretation, confidence and next branch. Prefer paired requests, controlled identities, synthetic records and independent corroboration; retain minimal sanitized evidence.

### Skill-specific hypothesis order

1. Map the actual authorization-code or other OAuth/OIDC flow using a client and accounts you control; capture state, nonce, redirect URI, PKCE parameters, issuer, audience, and scopes.
2. Check redirect URI exact matching, state/nonce binding, PKCE enforcement, token audience, and issuer validation one at a time with controlled client configuration.
3. Exercise login, consent, logout, and account-linking flows only with test identities. Verify that callback results are bound to the initiating browser session and intended identity.
4. Check token leakage through redirects/referrers/logs and scope overreach using canary claims or a harmless test API; do not reuse tokens or attempt another user's account.
5. Re-run a valid flow as a positive control and a changed-state/redirect/token control as negative evidence. Report the exact protocol invariant violated and the required provider/client fix.


### Verdict gates

- **Confirmed:** repeatable security impact against an explicitly in-scope resource is shown using a tester-controlled identity/fixture and a meaningful negative control.
- **Likely / needs corroboration:** independent observations support the hypothesis but impact/root cause remains uncertain.
- **Unconfirmed:** output is generic, cached, ambiguous, or detached from a security boundary.
- **Refuted / false positive:** a relevant negative control or valid product/security-policy explanation accounts for the signal. Document attempted branches rather than claiming to exhaust every theoretical variant.
- Status codes, banners, timing changes, error messages, or scanner alerts alone are not proof.

### Stop, cleanup, and handoff

Stop at scope ambiguity, real-user data, unexpected state changes, service degradation, secret exposure or a prohibited action. Clean disposable state, revoke temporary sessions/tokens where possible, and log cleanup status. Handoff scope proof, baseline, hypothesis, attempts used, impact, controls, verdict/confidence, sanitized evidence and any proven related-skill trigger; do not chain from a speculative association.

## References

- [uphiago — hunt-oauth](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-oauth)
- [Claude-BugHunter — hunt-oauth](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-oauth)
- [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)


## Targeted quality-loop enrichment (2026-10-19)

### OAuth/OIDC transaction-binding matrix
Use a dedicated client and test accounts. Record issuer, client ID, exact redirect URI, state, nonce, PKCE challenge/method, authorization-code binding, token audience, and final subject. Preserve a known-good flow as a control and change one transaction property at a time. Verify the token/session accepted by the relying party and resulting test identity; a provider error, open redirect in isolation, or decoded token is not proof of takeover. Keep sensitive token values out of notes and reports. Route a destination-only redirect issue to open-redirect review, reset-link authority to host-header review, and an identity-control outcome to ATO only after the full terminal state is reproduced.


## Transaction correlation and cross-skill impact gates

Treat one login attempt as a correlated transaction across browser session, authorization request, callback, code exchange, ID/access token, and relying-party session. Record a local transaction label rather than raw state, code, or token values. Do not compare artifacts from unrelated sessions as if they belonged to one flow.

| Signal | Follow-up | Proof bar before escalation |
|---|---|---|
| Redirect accepted outside the registered callback list | attack-open-redirect | The authorization server accepts the unregistered destination and a meaningful code/token exposure path is shown safely in a controlled client |
| State is missing or not bound | CSRF/session review | A callback can complete in the wrong initiating browser session or identity, not merely that state looks predictable |
| ID token audience/issuer mismatch accepted | attack-jwt | The relying party accepts a token intended for a different client/issuer and resolves a wrong test principal |
| Account-linking flow can bind the wrong identity | attack-ato | A controlled account ends up linked/authenticated as the wrong test identity; never test real users |
| Token/code appears in a URL or Referer | information-disclosure/session review | A real controlled secret crosses a trust boundary and remains usable; redact it and revoke promptly |
| Public-client secret found in shipped JS/mobile app | client-design finding | Show the secret is treated as confidential by the server or grants privileged capability; public client IDs alone are expected |

### Controlled transaction checklist

1. Capture a complete successful flow for one tester-owned account.
2. Create a fresh flow and alter one property (redirect, state, nonce, verifier, issuer/audience, or code reuse) in a controlled test client.
3. Confirm both the protocol-level response and the relying party's final authenticated principal.
4. Repeat a valid flow as a positive control to rule out account/session setup errors.
5. Revoke test tokens and clear disposable registrations or sessions; note anything that could not be cleaned up.

Do not create a chain merely because two weaknesses coexist. Every child finding needs its own protocol invariant, observable terminal effect, and evidence reference.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Use Burp Proxy/Repeater/Comparer, browser DevTools with separate controlled test profiles, and the JWT Editor extension only when token claim/signature inspection is relevant. Capture each authorization flow's baseline and expected redirect/token handling.

### Installation and setup
- [Burp Community/Professional](https://portswigger.net/burp) — install from PortSwigger and configure the browser through the official setup guide.
- JWT Editor can be enabled through Burp's official BApp Store; verify its listing and permissions before enabling it.
- Use a provider's own sandbox or your application’s local identity-provider fixture. Do not paste live access/refresh tokens into public decoders or external services.

### Primary resources
- [RFC 9700 OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700/) — current security requirements for OAuth 2.0.
- [PortSwigger OAuth authentication](https://portswigger.net/web-security/oauth) — controlled testing methodology.
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) — identity-layer semantics.

### Reusable helper
`python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt` compares sanitized flow artifacts offline; it does not validate tokens or prove authorization.

### Result handling
Use test accounts and test clients; preserve state/nonce/PKCE context and redact tokens, authorization codes, and callback query values from saved artifacts.

## Agent-executable CLI tooling, resources, and helper scripts

Agent-invokable CLI tools and local libraries only; browser UI, extensions, and interactive intercepting proxies are not required dependencies. Verify official installation docs, version, license, platform support, and impact before use.

### Recommended tools
- Python requests/httpx — controlled identity/session comparisons
- jq — parse structured responses
- http_response_diff.py — compare baseline and test variants
- Local JSONL matrix for account, role, token lifecycle, and operation

### Resources
- https://portswigger.net/web-security/access-control
- https://owasp.org/API-Security/
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids; confirm tool maintenance and CLI behavior from official sources.

### Helper-script contract
Use tester-owned accounts and synthetic resources. Change one trust dimension at a time and preserve baseline/control, auth context, result, and redacted evidence. Never retain live bearer tokens or modify real user data.

Preserve raw evidence and normalize a separate copy. Record source, timestamp, tool/version, auth context, errors, confidence, redaction state, and artifact references. Use explicit paths, structured output, and local fixtures.

### Handoff
Report actual commands and versions, input/output paths, control results, failures, confidence, limitations, and next skill. Missing tools and blocked tests are explicit.
