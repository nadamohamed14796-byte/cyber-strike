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

## References

- [uphiago — hunt-oauth](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-oauth)
- [Claude-BugHunter — hunt-oauth](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-oauth)
- [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700.html)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
