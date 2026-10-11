---
name: attack-idor-automation
description: "Validate object-level authorization with controlled cross-account comparisons and bounded IDOR checks"
category: "web-application"
version: "1.1.0"
author: "cyberstrike-official"
tags:
  - idor
  - bac
  - access-control
  - web
  - attack
tech_stack:
  - web
cwe_ids:
  - CWE-639
  - CWE-284
chains_with:
  - attack-jwt
  - attack-graphql
prerequisites: []
severity_boost:
  attack-jwt: "JWT tamper + IDOR = full account takeover"
---

# IDOR Automated Testing

## Objective

Systematically test all API endpoints for Insecure Direct Object Reference vulnerabilities using two accounts with different privilege levels.

## Testing Methodology

### Phase 1: Set Up Two Accounts

1. **Account A** — a test account that owns the test resources
2. **Account B** — a second test account you control, used to check whether Account A's resources are improperly accessible

### Phase 2: Automated Cross-Account Testing

```bash
# Include only endpoints and object IDs created by the two test accounts in endpoints.txt
attack_script idor_tester \
  --token-a "ACCOUNT_A_TEST_JWT" \
  --token-b "ACCOUNT_B_TEST_JWT" \
  --endpoints endpoints.txt \
  --json-output

# Test comma-separated endpoints
attack_script idor_tester \
  --token-a "ACCOUNT_A_TEST_JWT" \
  --token-b "ACCOUNT_B_TEST_JWT" \
  --endpoints "https://TARGET/api/users/123,https://TARGET/api/orders/456,https://TARGET/api/profile/123" \
  --method GET

# Test write operations
attack_script idor_tester \
  --token-a "ACCOUNT_A_TEST_JWT" \
  --token-b "ACCOUNT_B_TEST_JWT" \
  --endpoints endpoints.txt \
  --method PUT \
  --data '{"name":"CYBERSTRIKE_IDOR_CANARY"}'
```

### Phase 3: Manual Testing Patterns

**Horizontal IDOR (same role, different user):**
```bash
# Compare only IDs from test objects owned by accounts you control
curl --max-time 15 --connect-timeout 5 -s -D- -H "Authorization: Bearer ACCOUNT_B_TEST_TOKEN" "https://TARGET/api/users/$TEST_USER_A_ID"
curl --max-time 15 --connect-timeout 5 -s -D- -H "Authorization: Bearer ACCOUNT_B_TEST_TOKEN" "https://TARGET/api/users/$TEST_USER_B_ID"

# Compare one known test-owned object ID at a time; do not guess or enumerate other users' IDs
for id in "$TEST_ORDER_ID_A" "$TEST_ORDER_ID_B"; do
  curl --max-time 15 --connect-timeout 5 -s -o /dev/null -w "%{http_code}\\n" -H "Authorization: Bearer ACCOUNT_B_TEST_TOKEN" "https://TARGET/api/orders/$id"
  sleep 1
done
```

**Vertical IDOR (low-priv accessing high-priv):**
```bash
# Use only a test tenant or an approved endpoint; inspect authorization outcome without collecting real user records
curl --max-time 15 --connect-timeout 5 -H "Authorization: Bearer USER_TOKEN" https://TARGET/api/admin/users
curl --max-time 15 --connect-timeout 5 -H "Authorization: Bearer USER_TOKEN" https://TARGET/api/admin/settings
curl --max-time 15 --connect-timeout 5 -H "Authorization: Bearer USER_TOKEN" https://TARGET/api/internal/reports
```

### Phase 4: HTTP Method Switching

```bash
# Only against a disposable test-owned record; DELETE is state-changing
curl --max-time 15 --connect-timeout 5 -X DELETE -H "Authorization: Bearer ACCOUNT_B_TEST_TOKEN" https://TARGET/api/users/TEST_OWNED_DISPOSABLE_USER_ID

# GET blocked but PATCH works
curl --max-time 15 --connect-timeout 5 -X PATCH -H "Authorization: Bearer ACCOUNT_B_TEST_TOKEN" https://TARGET/api/users/TEST_OWNED_DISPOSABLE_USER_ID \
  -d '{"email":"idor-canary@example.invalid"}'
```

### Phase 5: Parameter Pollution

```bash
# Dual ID injection
curl --max-time 15 --connect-timeout 5 "https://TARGET/api/profile?user_id=TEST_ACCOUNT_B_ID&user_id=TEST_ACCOUNT_A_ID"

# Body override
# Only if the program authorizes transaction testing; use a disposable test balance and accounts you control
curl --max-time 15 --connect-timeout 5 -X POST https://TARGET/api/test-transfer \
  -H "Authorization: Bearer ACCOUNT_B_TEST_TOKEN" \
  -d '{"from":"TEST_ACCOUNT_A_ID","to":"TEST_ACCOUNT_B_ID","amount":1}'
```

### Phase 6: Response Comparison

```bash
# Compare responses between two auth contexts
attack_script response_diff "https://TARGET/api/users/TEST_OWNED_DISPOSABLE_USER_ID" \
  --header-a "Authorization:Bearer ACCOUNT_A_TEST_TOKEN" \
  --header-b "Authorization:Bearer ACCOUNT_B_TEST_TOKEN" \
  --json-output
```

## What Constitutes a Finding

| Finding | Severity |
|---------|----------|
| Read sensitive data from another test account | Severity depends on sensitivity, scope, and demonstrated impact |
| Modify another test account's data | Severity depends on the action and resulting impact |
| Delete another test account's disposable resource | Severity depends on recoverability and impact |
| Access admin-only functionality | Severity depends on the permissions and actions actually demonstrated |
| Read non-sensitive data from another test account | Severity depends on exposure and program policy |

## Evidence Requirements

- Two different auth tokens used
- Endpoint tested
- Account A (test account) response as baseline
- Account B (second test account you control) accessing Account A's resource
- Data received proving cross-account access

## Tools

- `attack_script idor_tester` — automated cross-account testing
- `attack_script response_diff` — response comparison
- `attack_script jwt_tamper` — token manipulation for IDOR

## Object-Relationship Coverage

Do not limit the check to swapping a top-level numeric ID. With test-owned records, check whether authorization is enforced for nested relationships and alternate references such as file IDs, attachment IDs, invoice/order IDs, tenant or organization IDs, and GraphQL/global IDs where the application uses them.

- Compare ownership and role checks across list, detail, export/download, update, and delete operations. Each action is a separate authorization claim.
- When the API accepts an organization or tenant ID in the request body, verify that the authenticated account is actually a member of that organization; a client-supplied identifier is not proof of membership.
- Prefer a small, explicit test fixture over sequential ID enumeration. Do not scan other users' identifiers or save unrelated personal data.
- Distinguish horizontal access (another peer account's object) from vertical access (a lower-privilege role performing a higher-privilege action), and report only the boundary that was demonstrated.

## Verification and False Positives

- Use two accounts you own (for example, Account A and Account B) and objects created by those accounts. Do not enumerate or collect identifiers belonging to unrelated users.
- Confirm the object belongs to Account B, then request it using Account A's session. Verify sensitive fields or unauthorized state changes in the response; HTTP 200 alone is not proof.
- Distinguish public objects, intentionally shared resources, and role-authorized access from an actual access-control failure. Review the expected permission model before reporting.
- Test read, update, and delete separately. A read-only IDOR does not prove write access, and a rejected update does not invalidate a separately confirmed read exposure.
- Keep automated testing bounded: use a small list of test-owned object IDs, low concurrency, request timeouts, and a stop condition for errors or unexpected data. Do not run broad ID enumeration against production.
- Preserve sanitized before/after evidence, the roles of both test accounts, object ownership, and the exact endpoint/method. Redact tokens and personal data.
- [uphiago/recon-skills — IDOR hunting](https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-idor/SKILL.md) (external research reference; not a local Cyber Strike skill path).
- [elementalsouls/Claude-BugHunter — IDOR hunting](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-idor/SKILL.md) (external research reference; not a local Cyber Strike skill path).

## Authorization Coverage and Evidence Quality

Build a small ownership matrix using accounts and objects you control:

| Principal | Own object | Another test user's object | Unauthenticated |
|---|---|---|---|
| Read | expected allow | expected deny unless sharing is intended | expected deny for private data |
| Update | expected allow when permitted | expected deny | expected deny |
| Delete/export/share | validate only if in scope | expected deny | expected deny |

Exercise identifiers in path, query, JSON body, GraphQL variables, nested references, bulk operations, and export/download flows. Change one identifier at a time so the cause is clear. Verify server-side authorization, not merely UI hiding.

Do not enumerate real users' IDs or retrieve their records. Use synthetic records, stop at the first confirmed cross-account boundary failure, and redact personal data in evidence.

Report the principal's role, object owner, operation, expected policy, actual response, and business impact. A sequential ID or an HTTP 200 response alone is not a finding; prove unauthorized access or modification.

## References

- [OWASP: IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [PortSwigger: Access Control](https://portswigger.net/web-security/access-control/idor)
