---
name: attack-mfa-bypass
description: "Assess multi-factor authentication enrollment, challenge, recovery, and step-up controls using test accounts and bounded state-transition checks."
category: "identity"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - mfa
  - 2fa
  - authentication
  - recovery
  - identity
tech_stack:
  - web
  - mobile
  - rest-api
  - oauth
  - oidc
cwe_ids:
  - CWE-287
  - CWE-308
chains_with:
  - attack-auth-bypass
  - attack-session
  - attack-ato
prerequisites: []
severity_boost:
  attack-ato: "A confirmed MFA gap supports ATO only when an authorized test-account flow establishes unauthorized account control."
---

# Multi-Factor Authentication Assessment

## Objective

Determine whether MFA is consistently enforced across login, enrollment, recovery, session renewal, and sensitive actions. Use identities and authenticator devices you control; do not target third-party accounts or attempt OTP guessing.

## Testing Methodology

### Phase 1: Inventory MFA state transitions

Map enrollment, verification, login challenge, remember-device, recovery codes, factor removal, password reset, session refresh, API/mobile parity, and step-up prompts.

### Phase 2: Capture valid baseline

Complete test-account login with MFA and record server-side transitions. Confirm a first-factor-only session cannot use MFA-protected operations.

### Phase 3: Test alternate paths

Compare web/API, old clients, password reset, recovery, device trust, federation, and direct endpoints. Use expired/malformed artifacts created for the test identity; do not guess codes or exhaust lockout thresholds.

### Phase 4: Check enrollment and factor change

Verify factor add/remove and recovery-code generation require documented re-authentication. Restore test state afterward.

### Phase 5: Verify step-up enforcement

Use a harmless protected operation to confirm the assurance level is checked server-side, including refresh-token and remembered-device paths.

## What Constitutes a Finding

- **Candidate / lead:** alternate route skips an MFA screen or stale challenge yields unusual response.
- **Confirmed finding:** test identity reaches protected operation without configured second factor or after invalid challenge, with server-side session evidence.
- **Not a finding:** missing UI prompt while API correctly denies the action, or one status change without protected access.

## Evidence Requirements

- Expected/observed MFA state, login route, account role, timestamp.
- Matched valid/invalid challenge requests with secrets redacted.
- Evidence for recovery/enrollment/renewal/step-up path and cleanup.

## Tools

- **Burp Suite:** compare MFA-required and alternate API paths.
- **Browser DevTools:** inspect challenge state and transitions.
- **Test authenticator:** generate valid factors for owned identities.
- **Source/log review:** verify assurance claims and middleware coverage.

## MFA Coverage Matrix

| Flow | Control | Confirmation |
|---|---|---|
| Initial login | Second factor before protected session | Session remains limited until challenge success |
| Remembered device | Trust is scoped, expiring, revocable | Stale trust cannot skip required assurance |
| Recovery code | One-time and account-bound | Used code cannot be reused |
| Factor changes | Fresh authentication and notification | Unauthorized factor mutation is denied |
| Password recovery | MFA policy remains consistent | Post-reset session has expected assurance |
| Sensitive action | Server-side step-up check | Direct API action denied without fresh proof |

**Mitigation:** centralize server-side MFA state, bind challenges to session/purpose, use one-time recovery artifacts, enforce appropriate limits, and invalidate stale trust state.

## Verification and False Positives

- Limited first-factor sessions may be intentional; verify what remains gated.
- MFA can be enforced by an identity provider; inspect the assurance claim and policy scope.
- Do not brute-force OTPs, test lockout with repeated guesses, intercept another person's factor, or degrade a real account.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue with materially distinct, authorized branches while evidence can change the conclusion; deduplicate cosmetic variants and exact retries. Stop when direct evidence resolves the hypothesis, meaningful branches are exhausted, a prerequisite is unavailable, or scope/safety requires stopping. Never bypass program retry limits or risk locking out real users.

Track each attempt as: hypothesis, one changed variable, baseline/control, observed signal, interpretation, confidence, and next branch. Use controlled identities or synthetic resources, preserve only minimal evidence, and redact secrets.

### Skill-specific hypothesis order

1. Use two test accounts with MFA enabled and record a normal password-plus-second-factor login as the positive control.
2. Test each alternate path separately: remembered device, recovery codes, factor reset/change, password reset, SSO, API login, mobile flow, and session reuse where those paths exist.
3. Check binding of challenge, account, session, and time window using invalid, expired, reused, and cross-session test artifacts; honor retry caps and avoid lockout of real users.
4. Confirm whether the protected test account reaches a sensitive feature without satisfying its configured factor; merely skipping a UI prompt is not proof if the server still enforces MFA.
5. Capture clean and bypass-path state transitions, invalidate test sessions/recovery codes afterward, and recommend consistent server-side step-up policies and revocation.


### Verdict gates

- **Confirmed:** repeatable security impact is shown against an in-scope resource using a tester-controlled identity or fixture, with a meaningful control.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause is not yet established.
- **Unconfirmed:** observations are ambiguous, cached, generic, or not tied to a security boundary.
- **Refuted / false positive:** a relevant negative control or valid policy/implementation explanation accounts for the observation; document the attempts instead of claiming all imaginable variants were exhausted.
- Do not treat status codes, error text, response length, decoded tokens, static findings, or UI state alone as proof.

### Stop, cleanup, and handoff

Stop at scope uncertainty, unrelated sensitive data, unexpected production changes, service degradation, secret exposure, or prohibited actions. Restore disposable state and revoke test tokens/sessions where possible. Return the scope proof, baseline, hypothesis, attempt count, impact, controls, confidence/verdict, sanitized evidence pointers, relevant handoff signal and cleanup status. Chain into another skill only when its trigger is present.

## References

- [uphiago — hunt-mfa-bypass](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-mfa-bypass)
- [Claude-BugHunter — hunt-mfa-bypass](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-mfa-bypass)
- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)


## Targeted quality-loop enrichment (2026-10-19)

### Factor-state transition proof
Use two controlled test accounts and map enrollment, challenge, recovery, device trust, remembered sessions, factor replacement, step-up authorization, and logout/revocation. Preserve a valid challenge baseline and compare missing, expired, wrong-purpose, and previously consumed test proof one dimension at a time. Verify server-side assurance level and protected action, not merely the UI's MFA badge. Stop before lockout or recovery of any real account. Chain to ATO only if an unauthorized test principal reaches control of the test account; chain to session review when an existing session retains privileges after a factor/security change.


## MFA assurance and recovery decision matrix

| Path | Safe comparison | Proof required |
|---|---|---|
| Password-only session | Valid first factor before/after MFA challenge | Server denies MFA-gated endpoint until challenge success |
| Remembered device | Normal trusted device vs revoked/expired test trust | Old trust does not bypass configured reauthentication |
| Recovery code | Valid owned code, then same code reused | One-time behavior and account binding are enforced |
| Factor replacement | Fresh authenticated test session vs stale/low-assurance session | Server requires the documented assurance level before replacement |
| Password reset | Test account before/after reset | Expected session/factor invalidation and notification behavior |
| SSO/federation | Valid test identity with known assurance claim vs one lacking it | Relying party enforces required acr/amr or equivalent policy |
| Mobile/API alternate path | Same protected operation through observed clients | Backend applies the same assurance requirement, not just the UI |
| Step-up sensitive action | Normal fresh step-up vs expired/missing test proof | Protected server action is denied without fresh proof |

### Safe test evidence

Record account_fixture, factor_type, challenge_purpose, session_assurance_before_after, recovery_artifact_state, device_trust_state, endpoint_result, protected_action_result, retry_policy_observed, and cleanup_verified. Never store OTPs, recovery codes, authenticator seeds, or full tokens.

### Chain rules

- Session remains privileged after MFA change → session lifecycle review.
- Recovery path accepts a factorless identity and changes account control → ATO review only with controlled identities and complete terminal-state proof.
- Missing step-up permits one protected action but not login bypass → report the exact action/assurance boundary; do not call it a full MFA bypass.
- UI omits MFA but backend rejects the operation → false positive for bypass; note the UI inconsistency separately only if it has independent impact.


## Regression handoff for MFA state and assurance

The regression should assert server-side state, not text or visual challenge presence.

- After first-factor success, the principal is authenticated only at the documented assurance level.
- Completing a valid challenge upgrades assurance for the same intended account and session.
- A challenge cannot be replayed across account, session, purpose, or expiry window.
- Factor removal/replacement requires the documented recent-authentication level.
- Recovery and password reset do not silently mark an unverified factor as trusted.
- A revoked remembered device cannot continue satisfying a fresh step-up requirement.
- Existing sessions follow the documented policy after MFA changes; test both revoke-one and revoke-all behavior if the product exposes both.
- Valid low-risk public actions remain usable where intended, preventing overbroad regressions.

For each case, include expected assurance, observed assurance, principal, challenge binding, protected operation, relevant negative control, retry/lockout safety, and cleanup. If assurance is supplied by an identity provider, preserve the issuer and the exact claim mapping with sensitive values redacted.
