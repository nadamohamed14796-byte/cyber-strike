---
name: attack-account-lifecycle-verification
description: "Assess registration, email/phone verification, change-email, resend, invitation acceptance, and verified-account authorization boundaries with controlled test identities."
category: "identity"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - account-lifecycle
  - registration
  - email-verification
  - identity
  - authentication
  - business-logic
  - authorization
tech_stack:
  - web
  - rest-api
  - email
  - sms
  - oauth
  - oidc
cwe_ids:
  - CWE-287
  - CWE-640
chains_with:
  - attack-forgot-password
  - attack-ato
  - attack-auth-bypass
  - attack-session
  - attack-csrf
  - attack-bfla
  - attack-business-logic
  - attack-api-property-authorization
  - attack-evidence-hygiene
  - attack-triage-validation
prerequisites: []
severity_boost:
  attack-ato: "A lifecycle weakness supports ATO only when a controlled, authorized flow demonstrates unauthorized control of a tester-owned identity and its server-side principal/session is independently verified."
---

# Account Lifecycle and Email Verification

## Objective

Determine whether the application enforces the intended identity proof at each account lifecycle transition. Focus on registration, email/phone verification, resending confirmation, changing a verified address, invitations, and actions gated on verification. A confirmation link, weak-looking token, missing UI step, or HTTP 200 is a lead—not a confirmed vulnerability.

Use only explicitly authorized, disposable test accounts and inboxes controlled by the tester. Do not contact unrelated people, alter real users' addresses, flood mail/SMS delivery, guess tokens/codes, or persist access.

## 1. Establish scope, state, and expected policy

1. Read the current session context and persisted target scope. Reuse the established scope result; active request tools must still enforce scope for every concrete request.
2. Identify which registration, verify, resend, change-email, invite/accept, and post-verification endpoints are actually observed from captures, OpenAPI/schema, browser flows, or source review. Do not invent endpoints from naming conventions.
3. Build a small target-local state matrix for the relevant test identities, using labels only:
   - new/unregistered (only if an authorized test fixture supports it);
   - registered but unverified;
   - verified;
   - change-email pending;
   - invite pending/accepted;
   - disabled or re-authentication-required, only if observed.
4. Write the expected rule for the specific transition and its source: product documentation, program requirements, observed normal workflow, or a clearly documented invariant. Do not assume every feature must require email verification; if policy is unknown, gather evidence before testing.
5. Preserve the initial account state, role/tenant labels, captured request IDs, and the harmless endpoint that can independently verify resulting identity/state. Keep all token values, cookies, codes, and email contents out of durable notes.

## 2. Capture a normal lifecycle baseline

Use the normal UI or already-observed requests for a tester-owned account and inbox. Record:
- transition attempted and expected prior state;
- request ID, endpoint/method, response status and redacted response facts;
- resulting account verification flag/status and current principal from an authoritative source;
- whether an email/SMS was delivered to the controlled inbox (delivery alone is not proof of a security flaw);
- session behavior before and after the transition, where relevant.

Where server-side state is not accessible, use an independent, harmless authenticated profile/me endpoint and distinguish inference from direct observation.

## 3. Email/phone verification checks

Choose only checks supported by observed behavior and the expected policy:

### Token binding and action binding

- If two test-owned accounts A and B exist, obtain a normal challenge for each from their own inboxes. Confirm the challenge issued to A cannot verify B or a different identity/action by changing only a known, observed account/action selector in the controlled test request.
- Confirm a verification challenge is bound to the intended account and current pending change, not merely to a user-supplied email or ID.
- Do not guess IDs, enumerate accounts, construct tokens, or attempt to apply a token to any real person's account.

### Expiry and single-use

- Test expiry only when expiry is documented or a controlled short-lived fixture/time setup is available. An inability to wait for expiry is a proof gap, not a pass.
- Complete a controlled challenge once, then make at most one safe replay of that same challenge to see whether it re-authorizes a transition. A benign idempotent replay is not automatically a flaw; check whether it changes a protected state or crosses an identity/action boundary.
- Do not repeatedly replay tokens, brute-force OTPs, or run race/concurrency tests against production account flows.

### Verified-state enforcement

- With a controlled unverified account, compare one harmless operation that the stated policy says requires verification against the same operation after successful verification.
- Check the server-side endpoint, not only hidden/disabled buttons in the UI. Where relevant, assess APIs and alternate observed transports using the same controlled account.
- Confirm the feature's intended policy and demonstrate a meaningful consequence. Some products intentionally permit limited pre-verification access; that is not a bypass without a violated invariant.

### Resend, enumeration, and delivery behavior

- Compare responses for known test accounts only when enumeration behavior is a relevant hypothesis. A generic response or rate limit is a signal to interpret, not proof by itself.
- If resend protection is in scope, use only a small, explicitly permitted number of requests against test-owned inboxes. Record the actual limit and stop. Never trigger notification floods or evade rate limiting.
- Treat missing expiry metadata, inconsistent wording, or mail delivery without unauthorized state change as observations unless the program's requirements and demonstrated impact make them reportable.

## 4. Change-email, invitations, and identity linking

### Change-email

- Use a disposable test identity with both old and new inboxes under tester control.
- Map whether the application requires re-authentication, verification of the new address, and/or confirmation to the old address according to its stated policy.
- Confirm the account's effective email, verification state, principal, and existing sessions after the transition using authoritative state or a harmless profile endpoint.
- Check whether a challenge for one test account/change can approve another account or a stale pending change. Check notification and session-revocation behavior only when observable and relevant.
- Never change a real user's address, remove their factors, or invalidate their sessions.

### Invitations and external identity linking

- Use only a controlled test tenant and identities. Check whether invitation acceptance is bound to the intended recipient, tenant, invited role, and one-time state.
- For OAuth/OIDC/SAML linking, check provider subject/issuer/tenant and the provider's email-verification semantics. Never assume matching email text proves the same identity. Cross-reference `attack-oauth` or `attack-saml-sso` when the observed flow warrants deeper protocol testing.
- Do not use another person's provider account or try to take over an existing third-party identity.

## 5. Validate protected actions and chains

- If a verification bypass appears to enable a privileged feature, billing action, profile change, data access, or account takeover, validate the minimum safe downstream effect with a test-owned fixture. A skipped UI step is not enough.
- Route object ownership to `attack-idor-automation` / property-level issues to `attack-api-property-authorization` / action-level access to `attack-bfla` / CSRF to `attack-csrf`. Use `attack-forgot-password` for reset-token internals. Do not re-run the same test under several skill names.
- Do not test payments, destructive actions, real notification delivery, account deletion, or irreversible workflow transitions in production. If a safe proof cannot establish the consequence, retain the specific proof gap.

## 6. Evidence and disposition

Use the existing `verification_attempt`, `validate_finding`, `triage_vulnerability`, and `report_vulnerability` lifecycle; do not create a parallel ledger or new finding status.

For each meaningful executed attempt, record:
- exact request/capture IDs and redacted endpoint;
- test-account labels, expected policy, and precondition validity;
- the specific hypothesis and one changed variable;
- baseline/negative control and actual observed response;
- authoritative resulting state or identity, where available;
- expiry/reuse/account-binding result and any alternative explanation;
- remaining uncertainty and cleanup performed.

Disposition:
- **Confirmed:** an authorized, reproducible state transition violates the stated identity/security boundary and a meaningful effect is independently verified.
- **Ruled out:** a specific control is shown to apply on the same reachable path before the sensitive operation, or a valid controlled comparison disproves the hypothesis.
- **Inconclusive/blocked:** policy, inbox, test identity, state visibility, scope, or safe precondition is unavailable. State the exact missing evidence; never mark an unrun test as safe or false positive.
- **Not a standalone finding:** different error text, email delivery by itself, a missing UI step when the API still denies access, an unverified account with no meaningful policy violation, or a token-looking string without demonstrated use/impact.

For a report, include the expected state transition, minimum redacted request/response evidence, test identity labels, before/after principal/state, demonstrated consequence, applicable preconditions, limitations, root cause, and remediation. Never put live verification links, OTPs, passwords, reset links, cookies, or mailbox contents in the report.

## 7. Remediation guidance

Recommend server-side state-machine enforcement at every protected operation; cryptographically random, account- and action-bound challenges; appropriate expiry; atomic single-use consumption; revalidation of pending email changes; recipient/tenant binding for invitations; trusted canonical URL construction; protection of verification secrets from logs/referrers; and explicit session/notification policy. Prefer targeted regression tests for invalid account binding, replay, expired challenges, and unverified-state access.

## References

- Strix business-logic workflow: https://github.com/usestrix/strix/blob/main/strix/skills/vulnerabilities/business_logic.md
- Strix function-level authorization: https://github.com/usestrix/strix/blob/main/strix/skills/vulnerabilities/broken_function_level_authorization.md
- Strix CSRF account-change surface: https://github.com/usestrix/strix/blob/main/strix/skills/vulnerabilities/csrf.md
- CyberStrike password recovery: `attack-forgot-password`
- CyberStrike account takeover: `attack-ato`
