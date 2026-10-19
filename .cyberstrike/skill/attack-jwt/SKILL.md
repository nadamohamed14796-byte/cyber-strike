---
name: attack-jwt
description: "Assess JWT verification, algorithm policy, key selection, claims, token lifecycle, and authorization impact"
category: "web-application"
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [jwt, authentication, tokens, cryptography, authorization]
tech_stack: [http, json, jwt, jwks]
cwe_ids: [CWE-287, CWE-347, CWE-345]
chains_with: [attack-idor-automation, attack-open-redirect, attack-oauth, attack-triage-validation]
prerequisites:
  - "Authorized application and test identity"
  - "Permission to test token validation; never use another user's token"
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-jwt-crypto/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
  - "https://portswigger.net/web-security/jwt"
  - "https://www.rfc-editor.org/rfc/rfc7519"
---

# JSON Web Token (JWT) Security Assessment

## Objective

Determine whether the application verifies JWT signatures, algorithms, key selection, issuer/audience, expiry, and authorization claims correctly. Decoding a token is not verification; a vulnerability exists only when the server accepts a token or claim state that violates its security policy.

## Safety gates

- Use a dedicated account and tokens issued to that account.
- Do not attempt to access real users' accounts or data. Prove role/identity changes only in a test tenant or a controlled local environment.
- Do not brute-force signing secrets against production. Use approved offline checks only for tokens you own and only within program policy.
- Treat token strings as credentials: redact them from logs, shell history, commits, and reports.

## Procedure

### 1. Identify JWT usage and baseline

Locate tokens in authorization headers, cookies, or application responses. Decode header and payload locally without exposing the token to online services. Record `alg`, `kid`, `typ`, `iss`, `aud`, `sub`, `exp`, `nbf`, and role/scope claims as applicable. Establish a normal authenticated request and expected permissions.

### 2. Verify algorithm allowlisting

Check whether the server enforces a configured algorithm allowlist rather than trusting the token's `alg` header. In a controlled test environment, determine whether unsigned tokens or an algorithm mismatch are rejected. Never assume that changing `alg` or removing a signature is accepted; capture the server's actual decision.

### 3. Check asymmetric/symmetric key confusion

If the application uses an asymmetric algorithm, verify that the verifier cannot reinterpret a public key as a symmetric secret. Use published keys and local test tokens in an isolated environment or approved test account. Do not forge tokens for real users or elevate privileges on production systems.

### 4. Review key selection and remote key references

Inspect `kid` handling and configured JWKS/key sources. Look for unsafe file/path lookup, ambiguous key selection, untrusted `jku` or `x5u` references, or weak key-to-algorithm binding. Test only harmless invalid key identifiers unless a more intrusive test is explicitly authorized; do not use these fields to read server files or trigger outbound requests.

### 5. Validate claims and token lifecycle

Check signature verification, issuer, audience, expiry, not-before, subject binding, and expected claim types. Compare behavior for expired, not-yet-valid, wrong-issuer, wrong-audience, malformed, and revoked test tokens. Check whether logout, password reset, or account security changes invalidate tokens as documented.

### 6. Confirm authorization impact

Use a test account with known low privileges. A changed claim matters only if the server accepts the token and grants an unauthorized permission. Confirm the effect using a harmless test resource or isolated environment. A decoded payload, a generated token, or a parser response is not proof of bypass.

## Common false positives

- JWT payloads are readable by design; base64url encoding is not encryption.
- A token contains a role claim that the server ignores or independently checks.
- An untrusted `kid` causes a safe rejection.
- A weak secret hypothesis without a verified accepted forged token.
- Expiry differences caused by clock skew without meaningful policy failure.

## Evidence and output

Record token type (never the live value), algorithm policy, key source, redacted header/claims, baseline request, test condition, server acceptance/rejection, and demonstrated authorization impact. Return `token_location`, `algorithm`, `key_selection`, `claim_checks`, `lifecycle_behavior`, `auth_context`, `impact`, `confidence`, and redacted evidence references.

## Related skills

- `attack-idor-automation` — object authorization after authentication.
- `attack-open-redirect` / `attack-oauth` — redirect and OAuth token-flow boundaries.
- `attack-triage-validation` — impact confirmation and false-positive review.


## Targeted quality-loop enrichment (2026-10-19)

### Token acceptance and claim boundary
Separate local parsing from server acceptance. Record issuer, audience, expiry/not-before, key ID, algorithm, signing-key provenance, token transport, session context, and the harmless protected operation used as the acceptance oracle. Use tester-owned tokens only; never print or persist complete bearer values. Change one claim or validation dimension at a time, retain an unmodified-token control, and verify whether the server resolved a different principal or permission. A decoded payload, alg string, or rejected malformed token is not a finding. Chain to ATO only if a controlled identity becomes usable by an unauthorized party; chain to OAuth/OIDC review when issuance, audience, or callback binding is the source of the trust failure.
