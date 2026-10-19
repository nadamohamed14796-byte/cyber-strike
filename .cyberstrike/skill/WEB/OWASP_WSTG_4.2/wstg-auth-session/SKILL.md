---
name: wstg-auth-session
description: WSTG identity, authentication, authorization, and session management testing
tags: [auth, session, idor, csrf, jwt, wstg]
version: "1.0"
---
# Authentication, Authorization, and Session Testing (Evidence-Led)

## Safety and scope

- Confirm the exact endpoint and canonical target workspace with persisted scope before active testing.
- Use only explicitly authorized test accounts and tokens. Never use default-credential lists against live accounts, brute-force usernames/passwords/OTPs/reset tokens, password-spray, credential-stuff, or trigger lockouts or real email/SMS.
- Keep credentials and reset links secret. Redact token/cookie values from logs, notes, and reports.
- Use the captured request and approved replay tool. Do not use a shell script or external scanner to expand testing beyond the authorized plan.

## Username/account enumeration

Only compare responses for test-owned accounts or identities explicitly provided by the program. A single controlled comparison can examine whether the application reveals different states for a known test account versus a deliberately nonexistent test identifier. Keep the request count low, avoid timing campaigns, and stop if the endpoint triggers notifications or lockouts. Distinguish intended validation messages from demonstrated security impact.

## Login and credential policy

- Review authentication requirements, throttling configuration, MFA enforcement, recovery flow, and session invalidation from documentation, captured behavior, and safe test-account flows.
- Do not attempt guessed/default passwords or automated login attempts. If rate-limit behavior must be tested, use a small program-approved request budget against a test account and stop before lockout or notification thresholds.
- Do not attempt account takeover or change a real user's password/email/MFA settings.

## JWT and session tokens

- Prefer offline review of a token issued to a test account: algorithm, issuer, audience, expiry, not-before, and sensitive claims.
- A decoded claim is not proof that the server trusts it. If an active negative control is necessary, alter one property of a test-owned token and send it only to a harmless authorized endpoint; verify rejection.
- Do not brute-force signing secrets, forge tokens for another identity, test key confusion against production without explicit authorization, or expose token contents in output.
- Review cookie flags and rotation behavior in the captured flow. A missing flag is a hardening observation unless the browser/session context demonstrates a security impact.

## OAuth, reset, and MFA flows

- Use a test-owned client/account and inspect state, nonce, PKCE, redirect URI validation, token audience, and revocation behavior against the documented flow.
- Use only valid test-owned reset links and known test MFA codes. Do not guess codes, enumerate reset tokens, or generate repeated outbound messages.
- Stop before a flow changes credentials, removes MFA, grants privileges, or triggers irreversible account state unless the program supplies an isolated test fixture and explicitly authorizes it.

## Evidence workflow

1. Capture the baseline request/response and the expected policy.
2. Choose one hypothesis and a safe positive/negative control.
3. Use `http_replay` only after scope check; change one factor at a time and preserve required CSRF/session context.
4. Record request IDs, credential labels (never values), actual result, valid preconditions, and limitations.
5. Use `verification_attempt` for each meaningful executed test and `validate_finding` for the ten-check assessment. Duplicates, planned tests, and invalid preconditions do not count.

A decisive confirmation may stop early. A false-positive/disproven verdict requires resolved checks, multiple evidence-backed contradictions including a primary contradiction, matching valid attempt outcomes, and a durable evidence-backed DISPROVEN ledger outcome for the exact finding; no fixed attempt count applies. If safety or prerequisites prevent this, keep `INCONCLUSIVE / NEEDS REVIEW`.

## Coverage notes

Record app-wide token/cookie mechanism observations as `wide` only when actually tested. Record endpoint-specific authentication enforcement as `local`. A tool call alone is not coverage; preserve what was observed and what remains unknown.

## Reporting

Report only a demonstrated policy violation and its minimal redacted reproduction. Never include credentials, tokens, cookies, reset links, OTPs, personal data, or another user's records.
