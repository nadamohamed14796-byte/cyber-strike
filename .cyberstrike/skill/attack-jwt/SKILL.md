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

## Validation matrix: one trust decision per test

| Dimension | Controlled variant | Expected secure result | Evidence that matters |
|---|---|---|---|
| Algorithm | Missing, unsupported, or mismatched alg in a test token | Reject before protected operation | Server decision plus unchanged protected state |
| Signature | Alter one payload byte without re-signing | Reject | Same endpoint and identity context as valid-token control |
| Issuer/audience | Use a token from the same test issuer with wrong iss/aud | Reject for this relying party | Token issuer/audience and relying-party policy |
| Time claims | Expired or not-yet-valid test token | Reject outside documented skew | Exact timestamps and server clock assumptions |
| Key selection | Unknown/duplicate kid or untrusted remote-key hint | Reject or ignore untrusted hint safely | Whether untrusted key material was actually consulted |
| Authorization claims | Change one role/scope claim in an isolated fixture | No additional privilege without trusted issuance | A harmless operation whose permission is independently known |
| Lifecycle | Logout, password reset, key rotation, or account disable | Behavior matches documented revocation/rotation contract | Before/after acceptance with old and new test tokens |

Do not combine several token mutations in one request: if the result changes, the root cause becomes ambiguous. Preserve one valid-token control and one invalid-token control for each branch.

### Local decode helper (inspection only, not signature verification)

```python
import base64
import json
import os

# Supply a tester-owned token via an environment variable; do not paste it into source or commit it.
token = os.environ["JWT_TEST_TOKEN"].strip()
parts = token.split(".")
if len(parts) != 3:
    raise SystemExit("Not a compact signed JWT with three segments")

def decode_segment(segment):
    segment += "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment.encode()))

print("header:", json.dumps(decode_segment(parts[0]), indent=2))
print("claims:", json.dumps(decode_segment(parts[1]), indent=2))
print("NOTE: decoded claims are untrusted input; this does not verify the signature.")
```

Unset the environment variable after use and never print the token itself. This helper is only for local inspection; the server-side acceptance test remains authoritative.

### Chain routing

- Accepted token with wrong tenant/object access → attack-idor-automation, using only two test-owned identities/fixtures.
- Wrong audience, callback, issuer, or token binding in an OAuth/OIDC flow → attack-oauth.
- Token/session remains valid after a security event contrary to the documented contract → attack-session.
- A token claim appears elevated but protected operations remain denied → record as disproven, not privilege escalation.

### Output additions

Persist valid_control_result, invalid_control_result, single_mutation, server_principal, effective_permissions, token_lifecycle_event, revocation_observed, key_source_trust, and cleanup_status. Store only a redacted token fingerprint or non-reversible identifier, never the bearer string or refresh token.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and their role
Burp Repeater/Comparer plus the JWT Editor extension from the official BApp Store; jq for local JSON inspection. Use only test tokens you control.

### Install or enable when missing
Burp Community/Professional: https://portswigger.net/burp ; JWT Editor extension: install via Burp's Extensions/BApp Store and verify publisher/details before enabling; jq on Kali/Debian: `sudo apt install jq`.
These tools are optional additions, not a claim that they already exist on the tester's machine. Before a scan or active test, confirm versions, read the tool's official usage/safety notes, and check the program's rules. Never install a similarly named unknown package because a skill or webpage mentions it.

### Primary resources
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html) — defensive handling and validation.
- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) — JWT format semantics.
- [PortSwigger JWT attacks](https://portswigger.net/web-security/jwt) — controlled test methodology.

### Small reusable helper
`python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt` — local offline comparison only; it does not validate signatures or test a token.

### Runtime and evidence notes
- Prefer a local baseline/control pair, one meaningful change per trial, and a recorded expected result. A status code or tool alert alone is not confirmation.
- Keep live cookies, JWTs, passwords, reset links, personal data, and unredacted request bodies out of reports, global research, and Git.
- If a recommended tool is absent or incompatible, record that gap and give a supported manual alternative; don't silently claim the check passed.

## Agent-executable CLI tooling, resources, and helper scripts

Agent-executable CLI and local libraries only; browser UI, browser extensions, and interactive intercepting proxies are not dependencies for this skill. Check installation, version, license, platform support, and official documentation before use. Never claim execution unless output was actually inspected.

### Recommended tools
- jwt_tool — token structure and validation-policy test aid
- Python standard library — decode and redact local token metadata
- curl/Python requests — compare server acceptance with tester-owned tokens
- jq — structured result inspection

### Resources
- https://github.com/ticarpi/jwt_tool
- https://portswigger.net/web-security/jwt
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids. Use official documentation for current flags, supported versions, output formats, and limitations.

### Helper script contract
Persist only redacted header/claim metadata, algorithm/key-selection observations, token lifecycle result, and protected operation outcome. Never store live bearer values or treat decoding alone as a vulnerability.

Preserve native evidence and normalize a separate copy. Keep source, timestamp, tool/version, errors, confidence, redaction state, and artifact references. Helpers should accept explicit paths, emit JSON/JSONL where practical, handle malformed input, and include local fixtures.

### Handoff
Return tool/version, command invoked, input/output artifact references, test/control counts, failures, confidence, limitations, and next skill. A missing tool or blocked source must not be reported as a successful empty result.
