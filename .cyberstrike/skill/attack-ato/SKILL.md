---
name: attack-ato
description: "Assess account-takeover paths by validating each authentication, recovery, session, and identity-linking boundary using only test identities."
category: "identity"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - ato
  - account-takeover
  - identity
  - authentication
  - session
tech_stack:
  - web
  - rest-api
  - oauth
  - oidc
  - saml
  - mobile
cwe_ids:
  - CWE-287
  - CWE-384
  - CWE-640
chains_with:
  - attack-auth-bypass
  - attack-mfa-bypass
  - attack-forgot-password
  - attack-session
  - attack-oauth
prerequisites: []
severity_boost:
  attack-auth-bypass: "A verified authentication bypass is a precursor to ATO only when it establishes an unauthorized principal/session in a controlled test."
---

# Account Takeover Path Assessment

## Objective

Determine whether a reproducible weakness allows a tester to assume an account identity or control a test account without its intended proof. Treat ATO as an impact outcome, not a synonym for every authentication bug.

## Testing Methodology

### Phase 1: Map identity boundary

Map registration, login, recovery, MFA, verification, SSO linking, refresh, API tokens, and account recovery. Use separate test-owned identities with controlled inboxes.

### Phase 2: Capture valid/invalid baselines

For each flow, record expected proof, resulting principal, assurance level, and notification. Avoid accounts not belonging to the tester.

### Phase 3: Check identity binding

Review email/phone, OAuth subject, SAML NameID, tenant IDs, and recovery tokens for binding to the authenticated account. Compare link/unlink operations only in a test tenant.

### Phase 4: Verify the terminal state

If a candidate exists, complete only the authorized step for a disposable test account and verify the principal with a harmless profile endpoint. Do not extract private data, alter real credentials, or persist access.

### Phase 5: Measure and recover

Record whether issue affects a single test identity, role, or integration. Restore credentials/factors and revoke test sessions; distinguish direct ATO from a prerequisite bug.

## What Constitutes a Finding

- **Candidate / lead:** recovery/linking flow behaves inconsistently or token crosses contexts.
- **Confirmed ATO:** controlled flow yields authenticated control of a test account the tester was not otherwise entitled to control, independently verified server-side.
- **Prerequisite-only issue:** enumeration, token weakness, or missing UI prompt without identity control must be labeled as that specific issue.
- **Not a finding:** logging in to your own account via documented recovery.

## Evidence Requirements

- Test-account map, exact sequence, timestamp, and resulting server-side principal.
- Before/after account state, notifications, factor/session behavior; redact secrets.
- Distinguish prerequisite weakness from terminal effect.
- Confirm recovery, factor restoration, and session revocation.

## Tools

- **Burp Suite:** capture identity lifecycle requests.
- **Browser DevTools:** inspect redirects, cookies, and state transitions.
- **Offline token tools:** inspect only artifacts issued to test identities.
- **Test tenant/logs:** validate principal mapping without user data.

## ATO Evidence and Severity Matrix

| Demonstrated result | Classification guidance |
|---|---|
| Account enumeration only | Enumeration, not ATO |
| Reset-token weakness without reset | Recovery candidate, not ATO |
| Unauthorized test-account reset completed | ATO if control is established |
| Session survives required revocation | Session flaw; ATO only if account control follows |
| SSO subject misbinding in test tenant | ATO only if wrong principal is established |
| UI skips MFA but API denies access | UI bug, not ATO |
| Test account receives another test identity's principal | Confirmed identity-control failure |

**Mitigation:** secure lifecycle transitions, bind external identities to provider/tenant identifiers, enforce MFA policies, revoke sessions, and test end-to-end flows with controlled identities.

## Verification and False Positives

- ATO claims often confuse enumeration, email verification issues, or redirects with account control.
- Verify server-side principal rather than page title/display name.
- Provider subject IDs can differ across tenants; confirm issuer and tenant.
- Stop after test proof; do not access or modify real users' data or credentials.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Continue testing materially distinct, evidence-producing hypotheses while the candidate remains plausible and a meaningful next branch exists. Do not impose a fixed attempt ceiling or count cosmetic retries as new hypotheses. Stop when direct evidence confirms or disproves this hypothesis, no meaningful new branch remains, a valid prerequisite is unavailable, or program/safety rules require stopping; unresolved cases remain inconclusive.

Keep a compact ledger for every attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve raw evidence locally, redact secrets, and avoid collecting unrelated user data.

### Skill-specific hypothesis order

1. Create and baseline two accounts you control with distinct inboxes and recovery methods; verify the normal sign-in, recovery, email-change, and session-revocation behavior first.
2. Follow one identity-binding surface at a time: password reset, email/phone change, account linking, invitation acceptance, or recovery-code handling. Use only messages and tokens issued to your test accounts.
3. Check whether tokens are bound to the correct account, purpose, and time window; inspect replay, reuse, expiry, and session rotation with disposable test state rather than attempting another person's account.
4. Verify whether changing an identity factor affects existing sessions and linked identities as expected. Use a harmless profile marker to prove account-boundary impact without accessing private data.
5. Re-test the claimed path from a clean browser/session and a negative control. A weak recovery hint or unusual response alone is not account takeover; report only a reproducible ability to cross account ownership.


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

- [uphiago — hunt-ato](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-ato)
- [Claude-BugHunter — hunt-ato](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-ato)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)


## Safe request pattern and impact chain
Use only an account and mailbox/phone controlled by the tester. Capture the normal recovery flow, then test one policy property at a time: token/account binding, expiry, single use, host/scheme binding, session invalidation, and whether changing the recovery contact requires re-authentication. Never request or use a real user's recovery token.

```bash
: "TARGET_URL must be an in-scope recovery endpoint for a controlled test account"
curl -sS -D baseline.headers -o baseline.body "$TARGET_URL"
# Replay only a redacted request generated by your test account in Burp Repeater.
# Verify server-side state with a fresh login and the controlled account; do not print tokens.
```

Impact requires a demonstrated unauthorized account/session transition, not merely an unusual email or response. Chain to `attack-forgot-password`, `attack-session`, `attack-mfa-bypass`, or `attack-oauth` only when the corresponding weakness is independently observed.


## Targeted quality-loop enrichment (2026-10-19)

### Identity-chain validation
Map the whole state transition—registration or recovery start, token issuance, verification, credential/factor change, session creation, and post-authentication principal. Use two tester-owned accounts with separate controlled inboxes and record which identity each token is bound to. A reset email arriving, a token parsing, or a page rendering does not prove takeover. Prove the terminal state only by authenticating into the disposable test account and checking a harmless identity endpoint; then revoke sessions and restore factors. Chain to MFA, reset, OAuth/OIDC, or session review only when the observed defect crosses that specific boundary. Treat an isolated weak recovery control as its own finding unless the account-control consequence is reproduced.


## Identity lifecycle evidence matrix

Track the identity, factor set, and active sessions before and after every event. The invariant is that an identity transition remains bound to the intended test principal.

| Transition | Controlled test | Evidence to preserve |
|---|---|---|
| Email/phone change | Use the documented reauthentication and confirmation steps on a test account | Old/new verified contact state, notification, active sessions, effective principal |
| Password reset | Use a fresh test-account token and assess purpose, expiry, single-use and account binding | Token fingerprint only, account binding, before/after state, session invalidation |
| OAuth/OIDC linking | Link a provider identity owned by the tester to a test account | Issuer, subject, tenant, linking principal, final account identifier |
| Invitation acceptance | Create a test invitation for a known role/tenant | Invited role, accepting principal, resulting membership and tenant |
| MFA enrollment/removal | Change a factor on a test account and verify documented step-up/revocation behavior | Assurance before/after, factor inventory, old-session behavior |
| Recovery fallback | Use the product's documented recovery path with test factors | Whether the required proof is preserved and the same principal remains bound |
| Account merge/deletion | Use disposable tenant fixtures and non-production data only | Ownership/membership state and whether old sessions/links remain valid |

### Evidence ledger

Record entry_point, precondition, test_identity_A, test_identity_B, token_purpose, token_account_binding, token_reuse_result, principal_before, principal_after, factor_state_before_after, session_state_before_after, notifications_sent, terminal_effect, negative_control, and cleanup_verified. Use pseudonymous test labels, never raw tokens or recovery codes.

### Reporting discipline

- Separate a prerequisite defect from a demonstrated account-control consequence; label unproven consequences clearly.
- If a result requires user interaction, prior compromise, an already-authorized account, or a specific provider configuration, state that precondition prominently.
- Do not claim full takeover if only a low-risk profile field or a linking prompt changed.
- Preserve a clean control flow and a regression test proving the expected account/issuer/tenant binding.


## Agent-executable CLI tooling, resources, and helper scripts

### Tools
- Python `httpx` or `requests` — compare observed authentication and recovery requests using two tester-owned accounts.
- `jq` — parse structured response/session metadata after redaction.
- `rg` — inspect collected source/configuration for recovery, identity-linking, and session invalidation.
- `python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt` — compare saved responses offline.

### Installation and verification
Verify the chosen Python client with `python3 -c "import httpx; print(httpx.__version__)"` or the equivalent requests import; verify `jq --version`. Official docs: https://www.python-httpx.org/, https://jqlang.org/. If unavailable, use source/configuration review and record that live validation was not run.

### Resources
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- https://portswigger.net/web-security/authentication

### Proof and limits
Use only identities controlled by the tester and avoid repeated recovery sends. Confirm the resulting principal/session and the exact control involved. Redact reset links, cookies, OTPs, and private account data.