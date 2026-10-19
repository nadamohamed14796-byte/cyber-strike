---
name: attack-auth-bypass
description: "Validate authentication-control failures across login, recovery, federation, and alternate API flows with test-owned identities and reproducible session checks."
category: "identity"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - authentication
  - auth-bypass
  - login
  - identity
  - api
tech_stack:
  - web
  - rest-api
  - oauth
  - saml
  - oidc
cwe_ids:
  - CWE-287
  - CWE-306
  - CWE-384
chains_with:
  - attack-ato
  - attack-mfa-bypass
  - attack-session
  - attack-sqli
  - attack-nosqli
prerequisites: []
severity_boost:
  attack-ato: "Authentication bypass can enable account takeover when a controlled account's identity or session is accepted without valid proof."
---

# Authentication Bypass Assessment

## Objective

Determine whether an in-scope application grants an authenticated identity or protected operation without enforcing its documented authentication proof. Use only test accounts, synthetic identities, and permitted flows.

## Testing Methodology

### Phase 1: Map authentication entry points

Inventory web/mobile/API login, recovery, invitations, magic links, OAuth/OIDC/SAML callbacks, legacy routes, and versioned endpoints. Verify ownership of identity-provider hosts before testing. Capture normal successful and failed baselines.

### Phase 2: Compare state transitions

Change one condition at a time: missing credential, malformed credential, expired test token, wrong audience, stale session, missing second factor, and alternate content type. Confirm the server-side identity and resulting session, not just a status code or UI.

### Phase 3: Check alternate and legacy paths

Compare UI and API behavior, old versions, remember-me endpoints, recovery completion, and federated callbacks. Use only artifacts issued to tester-owned accounts. Do not guess credentials or target another person's identifier.

### Phase 4: Verify protected action

Use a least-privileged test account and harmless protected operation. Confirm the backend resolves an authenticated principal rather than returning public content or changing only the frontend. Stop before accessing real users' data.

### Phase 5: Trace root cause

Review credential validation, session creation, callback state/nonce, token issuer/audience, challenge completion, and middleware coverage. Ensure every route applies the same server-side gate.

## What Constitutes a Finding

- **Candidate / lead:** failed login has unusual response, route lacks an obvious guard, or UI state differs from API state.
- **Confirmed finding:** a protected harmless action succeeds without required authentication proof and is repeatable with controlled identities.
- **Not a finding:** HTTP 200 alone, client-only dashboard state, generic error differences, or intentionally public functionality.

## Evidence Requirements

- Baseline success/failure request and the single altered condition.
- Test account IDs/roles, session status, endpoint, timestamp, and resulting principal.
- Minimal harmless operation proving the failed boundary.
- Redact cookies, credentials, and tokens.

## Tools

- **Burp Repeater:** compare authentication flows and API variants.
- **Browser DevTools:** inspect redirects, cookies, and frontend/server mismatch.
- **Offline token decoders:** inspect test-token claims without sending secrets to external sites.
- **Source/log review:** confirm principal resolution and guard coverage.

## Authentication Control Matrix

| Flow | Security property | Confirmation |
|---|---|---|
| Password login | Credentials validated before session issue | Invalid test credentials never yield a valid principal |
| Recovery/magic link | Token bound to account, action, expiry, and single use | Test token cannot complete another test account's flow |
| OAuth/OIDC | State, nonce, issuer, audience, redirect URI and PKCE as applicable | Callback cannot establish the wrong test identity |
| SAML | Signature, issuer, recipient, audience, and timestamps validated | Mismatched test assertion is rejected |
| API/mobile | Backend validates independently of UI | Direct API call does not bypass the same gate |
| Legacy route | Same server-side policy | Alternate route cannot permit a denied action |

**Mitigation:** centralize authentication middleware, validate protocol state server-side, bind tokens to context, and regression-test negative cases on every route.

## Verification and False Positives

- Cached pages/client navigation can appear authenticated while APIs remain protected.
- Public/guest flows require documented expected behavior.
- Response code or timing differences do not prove bypass without an authenticated principal.
- Stop if testing requires credential guessing, real-account recovery, or out-of-scope identity-provider access.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Continue testing materially distinct, evidence-producing hypotheses while the candidate remains plausible and a meaningful next branch exists. Do not impose a fixed attempt ceiling or count cosmetic retries as new hypotheses. Stop when direct evidence confirms or disproves this hypothesis, no meaningful new branch remains, a valid prerequisite is unavailable, or program/safety rules require stopping; unresolved cases remain inconclusive.

Keep a compact ledger for every attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve raw evidence locally, redact secrets, and avoid collecting unrelated user data.

### Skill-specific hypothesis order

1. Map the authentication boundary for one in-scope feature: expected login path, protected destination, anonymous response, and allowed test account response.
2. Compare modern and legacy entry points only when the application exposes evidence for them (for example, a legacy protocol endpoint or alternate API version); verify each route's own access policy.
3. Check token/session validation dimensions independently: presence, signature/issuer/audience where applicable, expiry/revocation, and binding to the intended account or client. Do not treat malformed-token acceptance as impact by itself.
4. Test recovery, SSO callback, and alternate-channel paths only if they are present. Use two controlled identities to establish whether the path authenticates the wrong identity or skips a required factor.
5. Confirm a protected action or private test-owned resource is accessible without the required proof, then compare with a clean unauthenticated/invalid-token control and document exact preconditions.


### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture, with a relevant control and a clear trust-boundary failure.
- **Likely / needs corroboration:** multiple independent signals support the hypothesis, but the security consequence or root cause is not yet established.
- **Unconfirmed:** evidence is incomplete, ambiguous, cached, or indistinguishable from a generic response.
- **Refuted / false positive:** a relevant negative control, valid authorization explanation, or repeatable contradictory evidence explains the signal. Record what was tested; do not claim that every theoretical variant was exhausted.
- A status code, banner, stack trace, response-length difference, endpoint existence, tool alert, or visible frontend state is never sufficient on its own.

### Stop and cleanup rules

Stop immediately on an out-of-scope boundary, unexpected real-user data, production side effects, rate-limit/availability degradation, credential exposure, or a request to perform a prohibited action. Do not continue merely to spend the budget. Restore disposable test state, revoke temporary sessions/tokens where possible, and record cleanup status.

### Agent handoff record

Return: skill, target asset, in-scope evidence, baseline, candidate hypothesis, attempts used, observed impact, negative controls, confidence/verdict, related-skill signal, sanitized evidence references, and cleanup status. Invoke a chained skill only when the stated signal is independently observed; do not chain from name similarity alone.

## References

- [uphiago — hunt-auth-bypass](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-auth-bypass)
- [Claude-BugHunter — hunt-auth-bypass](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-auth-bypass)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)


## Hands-on field pattern: prove the boundary
Record a clean anonymous baseline and a valid controlled-account baseline for the same endpoint. Repeat with the minimally required role difference; don't conflate routing quirks, a login-page shell, or error text with a bypass.

```bash
curl -sS -D anon.headers -o anon.body "$TARGET_URL"
curl -sS -D user.headers -o user.body -H "Cookie: $TEST_SESSION" "$TARGET_URL"
# Inspect only sanitized files; TEST_SESSION must belong to a controlled account.
diff -u <(sed -E 's/(Set-Cookie:).*/\\1 [REDACTED]/I' anon.headers) <(sed -E 's/(Set-Cookie:).*/\\1 [REDACTED]/I' user.headers) || true
```

Explain the failed control explicitly: authentication, function authorization, object authorization, or session binding. Chain to `attack-401-403-bypass`, `attack-bfla`, `attack-idor-automation`, or `attack-session` based on that proven boundary.


## Targeted quality-loop enrichment (2026-10-19)

### Prove the principal, not the response
Keep one protected read-only action and one known-public action as controls. Compare absent, malformed, expired, revoked, and valid test credentials while preserving the same route and request semantics; then verify the server-side subject/role through a harmless endpoint. A 200, a public shell, or middleware inconsistency is not authentication bypass unless a protected principal or operation is actually granted. Check alternate API versions and legacy routes only when discovered or documented. If authentication is absent but object policy still blocks access, route to API no-auth/BOLA; if identity exists but role checks fail, route to BFLA. Use only test accounts and never probe another person's account identifier.


## Identity-resolution and enforcement matrix

| Observed behavior | Classification to investigate | Confirmation |
|---|---|---|
| Anonymous request receives a protected resource | Missing authentication / API no-auth | Protected synthetic marker is returned or protected operation is performed |
| Valid low-role identity reaches admin operation | BFLA | Backend executes a function the role cannot invoke |
| Authenticated caller reaches another owner's object | BOLA/IDOR | Controlled foreign object is returned/changed contrary to policy |
| Correct identity but wrong tenant/audience is accepted | Token/tenant binding | Server resolves the wrong test principal or grants cross-tenant authority |
| Old session retains access after reset/logout | Session lifecycle | Protected network action succeeds with old test session contrary to policy |
| MFA challenge omitted but server assurance is low | Not yet a bypass | Confirm whether the exact protected action is still denied |
| Public endpoint returns 200 without credentials | Expected public behavior unless policy says otherwise | No private data or restricted operation is exposed |

### Minimal request comparison

Capture the same read-only endpoint under anonymous, invalid/expired, least-privilege, and authorized test sessions. Preserve request method, body, content type, and object fixture. Record server-side principal/role from an approved test endpoint or logs; do not infer identity from UI state.

### Chain rules

Do not chain based on a shared word such as “auth.” The observed boundary determines the next skill: session issue → session management; factor bypass → MFA; wrong token issuer/audience → JWT/OAuth; object boundary → BOLA; function privilege → BFLA. A single symptom may reveal several hypotheses, but each reportable finding needs its own evidence and impact.


## Identity-resolution trace and regression set

For source review, trace the request from credential extraction through verifier, principal resolution, middleware/guard, authorization policy, and protected handler. Mark each layer as observed in code, approved logs, or only inferred. A route that lacks a visible decorator may still be protected by router-level middleware; inspect the full registration path before calling it a gap.

### Source-review checklist

- Locate route registration and determine inherited/global middleware, not just route-local annotations.
- Follow the credential from its actual transport (cookie, bearer token, signed request, or documented mechanism) to the verifier.
- Confirm the verifier's issuer, audience, expiry, signature/key selection, and revocation behavior where relevant.
- Follow the resolved subject/tenant/assurance level into the authorization decision and final handler.
- Check error paths and fallback behavior: authentication failure must not create a partial session or default to a privileged principal.
- Review tests for anonymous, invalid, expired, revoked, low-role, and cross-tenant controlled fixtures.

### Regression cases to hand off

- Anonymous request to a protected synthetic resource is denied.
- Invalid, expired, revoked, wrong-issuer, and wrong-audience test credentials are rejected when those cases apply.
- Valid low-role account authenticates but cannot invoke a restricted function.
- Valid identity cannot access a second tester-owned fixture belonging to another role or tenant.
- Recovery and federated callback state is bound to the initiating controlled session.
- Authentication failure does not create a partial session, trusted-device state, or elevated assurance claim.
- Legacy and versioned routes enforce the same intended policy, or documented differences are preserved.

For each regression, record route registration, effective middleware chain, expected principal, actual principal, authorization decision, fixture, negative control, and test result. Do not turn a source-search match or missing string into a confirmed finding.
