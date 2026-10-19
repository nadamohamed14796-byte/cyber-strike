---
name: wstg-authz-05.1
description: "Testing OAuth Authorization Server Weaknesses"
category: authorization
owasp_id: WSTG-AUTHZ-05.1
version: "1.0.0"
author: cyberstrike-official
tags: [authorization, access-control, privilege, wstg, authz]
tech_stack: []
cwe_ids: []
chains_with: []
prerequisites: []
severity_boost: {}
---
# WSTG-AUTHZ-05.1 — OAuth Authorization Server Review (Evidence-Led)

## Objective

Review OAuth/OIDC configuration and validate a specific authorization hypothesis using a program-owned test client and account. A discovery document, token endpoint, redirect parameter, or error response alone is not a vulnerability.

## Safety and scope

- Confirm the exact authorization server/client endpoints and canonical target workspace with persisted scope before active requests.
- Use only client IDs, redirect URIs, accounts, and tokens explicitly authorized for the assessment. Never guess client secrets, brute-force tokens, impersonate unrelated clients, or use another user's authorization code.
- Do not bypass consent, expand scopes to admin/privileged permissions, or attempt account takeover on production identities. If consent/state/PKCE testing requires a sensitive action, use a test tenant/client or stop as blocked.
- Keep authorization codes, access/refresh tokens, client secrets, and personal data redacted.

## Review workflow

1. **Inspect metadata passively.** Review the OAuth/OIDC discovery document and documentation for supported grant/response types, token endpoint authentication methods, issuer, signing algorithms, PKCE support, redirect URI rules, and revocation/introspection endpoints.
2. **Map a known test flow.** Use a program-owned test client and account. Capture the normal authorization request, callback, token exchange, and logout/revocation behavior where authorized.
3. **Test one invariant at a time.** Examples: verify a deliberately mismatched `state` is rejected in a controlled test flow; confirm PKCE verifier mismatch is rejected by a test client; confirm an unregistered redirect URI is rejected without issuing a code; verify tokens are audience/issuer-bound as documented. Do not use open redirects or external callback destinations that are not approved.
4. **Review scope/consent.** Compare the requested scopes with the test client's allowed scopes. Do not request privileged scopes or try consent-bypass parameters against real users. Use documented test scopes and verify the resulting token's effective permissions.
5. **Review token lifecycle.** Verify expiration, revocation, audience, issuer, and client binding using tokens issued to the test account. Do not expose token contents or attempt secret cracking.
6. **Interpret results carefully.** An error, redirect, missing field, or token claim alone is not proof. Establish the violated protocol property with a baseline/control and actual response semantics.

## Evidence and reporting

Record the request IDs, test client label, intended redirect URI, scope set, baseline/control, observed result, and valid preconditions. Never store secrets or live tokens in notes.

Use `verification_attempt` for meaningful executed tests and `validate_finding` for the ten-check assessment. A decisive confirmation may stop early. A false-positive/disproven verdict requires resolved checks, multiple evidence-backed contradictions including a primary contradiction, matching valid attempt outcomes, and a durable evidence-backed DISPROVEN ledger outcome for the exact finding; no fixed attempt count applies; if this cannot safely be completed, keep `INCONCLUSIVE / NEEDS REVIEW`.

Use `report_vulnerability` only when a protocol or authorization boundary violation is demonstrated. Include a minimal redacted reproduction and remediation. Do not report unsupported configuration preferences as exploitable findings.
