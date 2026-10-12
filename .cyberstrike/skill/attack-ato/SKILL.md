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


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Treat the attempt budget as a ceiling for evidence-producing hypotheses, not a quota for payload variants. When a candidate remains plausible, branch to the next independent hypothesis up to a maximum of 20; stop earlier when evidence is decisive, the remaining hypotheses are not relevant, or safety/scope limits apply. Never count the same request with cosmetic encoding changes as separate attempts.

Keep a compact ledger for every attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve raw evidence locally, redact secrets, and avoid collecting unrelated user data.

### Skill-specific hypothesis order

Use the matrix and acceptance criteria already defined in this skill to choose the next distinct, low-impact hypothesis; do not repeat equivalent probes.

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
