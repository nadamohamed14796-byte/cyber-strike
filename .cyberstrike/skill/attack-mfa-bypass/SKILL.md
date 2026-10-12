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


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Treat the attempt budget as a ceiling for independent, evidence-producing hypotheses, not a payload quota. If the signal remains plausible, follow the next relevant branch up to 20 distinct hypotheses; stop earlier when impact is decisive, the branch is irrelevant, or scope/safety limits apply. Cosmetic variations of one request are not independent attempts.

Track each attempt as: hypothesis, one changed variable, baseline/control, observed signal, interpretation, confidence, and next branch. Use controlled identities or synthetic resources, preserve only minimal evidence, and redact secrets.

### Skill-specific hypothesis order

Use the skill's existing matrix to choose independent, low-impact branches; do not repeat equivalent probes.

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
