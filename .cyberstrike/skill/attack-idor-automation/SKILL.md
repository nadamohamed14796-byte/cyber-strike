---
name: attack-idor-automation
description: "Authorized IDOR/BOLA testing — object-level authorization, cross-account access, tenant isolation, evidence validation, and safe automation"
category: "web-application"
version: "1.1.0"
author: "cyberstrike-official"
tags:
  - idor
  - bola
  - bac
  - access-control
  - web
  - api-security
tech_stack:
  - web
  - rest
  - graphql
cwe_ids:
  - CWE-639
  - CWE-284
chains_with:
  - attack-jwt
  - attack-graphql
prerequisites:
  - "Explicit authorization and a confirmed in-scope target"
  - "Two controlled test accounts or an equivalent approved test fixture"
severity_boost:
  attack-jwt: "A verified token-validation flaw combined with an object-authorization flaw may increase impact; demonstrate each primitive independently."
---

# IDOR / Broken Object-Level Authorization (BOLA) Testing

## 1. Objective and scope

Systematically assess whether an authenticated or unauthenticated caller can read, modify, create, export, or delete an object outside the caller's permitted access boundary. IDOR is a common symptom; **Broken Object-Level Authorization (BOLA)** is the broader API security concept.

Run active tests only against assets explicitly in scope and with permission. Prefer accounts, tenants, objects, and records created for the assessment. Do not access real third-party data, collect bulk records, or perform irreversible state changes. If the program rules prohibit automation or a test would affect another user, stop and use a safe fixture or ask the program owner for guidance.

### Important distinctions

- **Authentication** answers who the caller is.
- **Object-level authorization / BOLA** asks whether this caller may perform this action on this particular object.
- **Function-level authorization (BFLA)** asks whether the caller may invoke the function at all, such as an administrator-only operation.
- **Object-property authorization** asks whether the caller may read or modify specific fields on an otherwise accessible object.
- A changed identifier or a `200 OK` response alone is not proof of a vulnerability. Validate the returned content or an observable, authorized state change.

## 2. Preconditions and safety gates

Before testing:

1. Resolve the target and confirm the exact host, application, API, and endpoint are in scope.
2. Read the program's automation, rate-limit, data-handling, and destructive-testing rules.
3. Use Account A as the controlled resource owner and Account B as the test caller. Record each account's role, tenant, and expected permissions.
4. Create harmless test objects with recognizable, non-sensitive marker values (for example, `idor-test-A-<random>`).
5. Record a baseline request and response while signed in as the owner.
6. Start with read-only checks. Mutations and deletes must be separately authorized, explicitly enabled, and limited to disposable test objects.
7. Keep requests low-volume. Stop on rate-limit responses, instability, unexpected access to real personal data, or any sign that testing may affect a real user.

Never put real access tokens, cookies, API keys, or personal data in committed logs, reports, or generated artifacts. Use environment variables or a local secrets mechanism and redact evidence before persistence.

## 3. Working model: identities, objects, actions, boundaries

For each candidate endpoint, capture these dimensions:

| Dimension | Questions |
|---|---|
| Principal | Which account, role, token, or session makes the request? |
| Object | Which object ID, UUID, slug, nested ID, or opaque reference is supplied? |
| Action | Read, list, create, update, delete, export, invite, approve, or another operation? |
| Boundary | Same user, another user, same tenant, another tenant, project, team, organization, or role? |
| Expected policy | What should this principal be allowed to do, based on the product's normal behavior? |
| Observable result | Is protected data returned or is a controlled test object's state changed? |

An identifier is not a permission. Sequential IDs, UUIDs, hashes, opaque IDs, and server-generated references all require authorization checks. Identifier unpredictability can reduce guessing but does not replace authorization.

## 4. Attack-surface discovery signals

Prioritize endpoints that read or act on object references:

- REST paths such as `/api/users/{userId}`, `/orders/{orderId}`, `/invoices/{invoiceId}/download`, `/orgs/{orgId}/members`, or nested paths such as `/projects/{projectId}/files/{fileId}`.
- Query and body fields such as `id`, `user_id`, `ownerId`, `tenant_id`, `accountId`, `documentKey`, `resource_uuid`, `parent_id`, and arrays of IDs.
- GraphQL queries, mutations, global `node(id: ...)` resolvers, nested relations, bulk operations, and fields that accept arrays of object identifiers.
- File previews, downloads, exports, report jobs, import/migration jobs, attachments, notifications, audit logs, invitations, and sharing links.
- Mobile and SPA API traffic, WebSocket messages, legacy API versions, and alternate transports that act on the same object.
- JavaScript source and ordinary application responses that reveal IDs for objects the test account is legitimately allowed to see.

Treat these as prioritization signals, not proof. Do not infer a vulnerability from a header such as CORS or `X-Frame-Options` alone; those controls address different security properties.

## 5. Methodology

### Phase 1 — Build an endpoint inventory

Browse the application using the test account and capture requests in an approved proxy such as Burp Suite. For every candidate, record:

- Method, route, content type, and authentication mechanism.
- Object identifiers in the path, query, headers, body, GraphQL variables, or nested structures.
- The normal response shape and status code.
- Whether the operation is read-only or state-changing.
- The object owner and tenant for the controlled fixture.

Keep a stable inventory and deduplicate endpoints by method, normalized route, and relevant parameter shape. Do not treat every numeric value as an object ID without checking its meaning.

### Phase 2 — Establish the owner baseline

As Account A, request an object created by Account A. Save a redacted baseline including status, relevant headers, response schema, and a harmless marker value. Confirm the object is not public and that access is expected to be restricted.

As Account B, request an object owned by Account B as a control. This helps distinguish a broken test setup from a genuine cross-account authorization difference.

### Phase 3 — Perform the cross-account swap test

Using the same endpoint and action, substitute only the controlled object reference while authenticated as Account B. Keep other request properties unchanged where possible.

Test the following boundaries when the application supports them:

1. **Horizontal:** Account B attempts to access Account A's object at the same role.
2. **Cross-tenant:** a principal in Tenant B attempts to access a fixture in Tenant A.
3. **Vertical / role boundary:** a lower-privileged test role attempts an object operation reserved for a higher role. Assess whether the issue is object-level authorization, function-level authorization, or both.
4. **Nested objects:** test whether authorization is enforced for both the parent and child IDs, not just the outer route.
5. **Collection and bulk operations:** use only controlled fixture IDs and minimal batches; check whether every object in a batch is individually authorized.
6. **Indirect references:** inspect IDs returned by legitimate list/detail responses, exports, notifications, or related objects, then test only approved fixtures.
7. **Time/state boundary:** where permitted, check whether access is revoked after a test object's ownership, membership, invitation, or role is changed.

Do not guess or enumerate large identifier ranges by default. Prefer known IDs belonging to your own controlled test accounts. Never use distributed IPs, proxy rotation, or rate-limit evasion to increase enumeration.

### Phase 4 — Cover methods and content types carefully

For each relevant route, compare the methods the application actually supports (for example, GET, POST, PUT, PATCH, DELETE) and the content types used by the normal client. A protected GET does not prove that PUT or DELETE is protected.

Start with safe read-only methods. For writes, use a disposable object and a harmless reversible change. For delete, refund, transfer, invite, role-change, email-change, account-recovery, or other consequential operations, do not execute the operation unless the program explicitly permits it and the test fixture makes the impact safe. A response-only test or owner-approved staging fixture may be preferable.

Do not send arbitrary undocumented methods merely to generate traffic. Use application behavior, API documentation, and observed client requests to select meaningful cases.

### Phase 5 — GraphQL and alternate transports

For GraphQL:

- Inventory queries and mutations that accept object IDs, global IDs, nested identifiers, or arrays of IDs.
- Compare Account A's baseline with Account B's request for a controlled object.
- Test nested relations and mutation inputs, not only the top-level resolver.
- Check whether a mutation reports success while the object remains unchanged, or returns partial/redacted data.
- Treat introspection as optional and policy-dependent; do not assume it is enabled or required to test authorization.

For WebSockets, mobile APIs, versioned endpoints, or other transports, reuse only documented or observed operations and controlled fixtures. Verify that the same authorization policy applies across transports; the mere existence of multiple transports is not a finding.

### Phase 6 — Response and state differential

Compare more than HTTP status:

- Response body and schema, including harmless owner-specific marker fields.
- Object owner, tenant, and permission-relevant fields.
- Content length and response timing only as secondary signals.
- Error messages, redirects, cache behavior, and response headers.
- A before/after read of the controlled object for a permitted state-changing test.

Interpret common outcomes cautiously:

| Observation | Interpretation |
|---|---|
| `200` with the controlled foreign marker or protected fields | Strong candidate; confirm policy and reproducibility |
| `200` with empty, redacted, or generic content | Not confirmed without evidence of unauthorized access |
| `403` or `404` | Usually denied; check expected behavior and avoid assuming a bypass |
| `302` to login or an access-denied page | Usually not a finding by itself |
| Error or timing difference only | Lead for investigation, not proof |
| Mutation says success but no controlled state change occurs | Not confirmed; investigate response semantics |
| A public object is accessible to both accounts | Not IDOR unless access should be restricted |

## 6. Safe automation design

Automation should assist comparison, not blindly exploit every identifier.

### Required controls

- **Scope gate:** refuse to run if the target is outside the supplied allowlist or authorization context is missing.
- **Dry-run by default:** show planned requests before sending them.
- **Read-only by default:** mutation and deletion checks require explicit opt-in and safe fixtures.
- **Bounded requests:** configurable low request limit, concurrency, and delay; no unbounded ID ranges.
- **Fixture-only mode:** prefer IDs explicitly supplied for Account A and Account B.
- **Secret redaction:** redact Authorization, Cookie, Set-Cookie, tokens, and personal fields in outputs.
- **Stop conditions:** stop on rate limiting, repeated server errors, unexpected real-user data, or scope ambiguity.
- **Evidence-based classification:** report candidates with confidence and reasons; do not call a finding confirmed based only on status code.
- **Reproducibility:** retain request templates and redacted evidence, not raw secrets or bulk response dumps.

### CLI examples (illustrative; verify tool availability first)

The following command names are examples from the current skill's proposed interface, not a guarantee that a matching executable or argument schema is implemented in every CyberStrike build. Before execution, inspect the tool registry and implementation, confirm the exact flags, and use the installed command's help output. Never invent a tool result.

```bash
# First verify that the tool exists and inspect its supported arguments.
attack_script idor_tester --help

# Example only: compare known controlled fixtures, with dry-run/read-only options
# added only if the actual tool implementation supports them.
attack_script idor_tester \
  --token-a "$ACCOUNT_A_TOKEN" \
  --token-b "$ACCOUNT_B_TOKEN" \
  --endpoints endpoints.txt \
  --json-output
```

Do not put literal tokens in shell history or source control. If the implementation does not support dry-run, allowlists, request limits, redaction, and safe mutation gating, do not use it for active automation until those controls are added.

## 7. Candidate prioritization and confidence

Prioritize testing based on protected data and meaningful actions, not identifier format alone:

- **High attention:** private documents, billing records, account settings, organization membership, tenant-scoped exports, private messages, and administrative objects.
- **Medium attention:** private project metadata, non-public attachments, team resources, and business records.
- **Lower attention:** intentionally public data or fields that do not cross an authorization boundary.

Use confidence labels separately from severity:

- **Unverified lead:** identifier pattern or suspicious response only.
- **Candidate:** cross-account response differs and merits manual inspection.
- **Confirmed:** the controlled foreign object is demonstrably accessible or changed contrary to the documented/observed policy, with reproducible evidence.
- **Not a finding:** public by design, same-owner access, no protected data/state change, or insufficient evidence.

Severity must follow the program's policy and demonstrated impact. Do not label every PII exposure, write operation, admin-looking route, or HTTP 200 as Critical. Consider sensitivity, scope, number of affected users demonstrated safely, required privileges, exploit preconditions, and actual confidentiality/integrity/availability impact. Do not infer mass exposure from a single controlled fixture.

## 8. Root-cause hypotheses to investigate

When reviewing source code or correlating behavior, look for:

1. A database lookup by object ID without a policy or ownership check.
2. Authentication middleware present without per-object authorization.
3. A caller-controlled `user_id`, `tenant_id`, `org_id`, or parent ID trusted without verifying membership.
4. Different authorization behavior between HTTP methods, API versions, background jobs, and transports.
5. Nested child objects authorized only by their ID, without verifying access to the parent.
6. GraphQL resolvers or bulk mutations that skip authorization for nested/individual objects.
7. Export, download, preview, notification, or job-status endpoints that do not re-check access.
8. Stale membership, cached authorization context, revoked grants, or expired invitations that remain usable.
9. Object properties that can be read or changed even when the caller can access only a subset of the object.
10. Cache keys that fail to separate user- or tenant-specific responses.

These are hypotheses to verify, not assumptions that a vulnerability exists.

## 9. False positives and pitfalls

- **Status-code bias:** a 200 response may contain no protected information.
- **Public resources:** public profiles, published documents, and intentionally shared links are not automatically IDOR.
- **Own-object tests:** changing an ID to another object owned by the same account does not establish cross-account access.
- **UUID assumptions:** a UUID is not an authorization control, but a known UUID is not proof of a flaw either.
- **Role confusion:** accessing an admin-only function may be BFLA rather than BOLA.
- **Property-level issues:** exposure or modification of one field may be object-property authorization rather than object-level authorization.
- **Shared resources:** verify expected collaboration, organization membership, and delegated permissions before reporting.
- **Caching:** distinguish a genuine server authorization failure from a cache issue; confirm using controlled accounts and safe cache behavior.
- **State changes:** a response message alone is insufficient; verify a harmless controlled object's state when permitted.
- **Over-enumeration:** do not collect large datasets to prove impact. One or a few controlled records can be enough.

## 10. Evidence and report quality gate

Before submitting a report, answer all of the following:

1. **What exact boundary failed?** Name the caller, object owner/tenant, action, and expected policy.
2. **What proves access?** Show the redacted request and the smallest response excerpt containing the harmless marker or protected field.
3. **What is the impact?** Describe confidentiality, integrity, or availability impact demonstrated by the test; distinguish observed impact from plausible worst-case impact.
4. **Can it be reproduced?** Include prerequisites, account roles, fixture setup, exact request sequence, and observed result.
5. **Were controls checked?** Confirm the object is not public, the test account does not have legitimate access, and the result is not only a status code or timing difference.
6. **Is the evidence safe?** Remove secrets and unrelated personal data. Do not attach bulk dumps or another user's real records.
7. **Is severity justified?** Map the demonstrated impact to the target program's policy and avoid unsupported claims.

### Suggested report template

- **Title:** Broken object-level authorization in [feature/endpoint]
- **Summary:** One or two sentences describing the missing authorization boundary.
- **Scope and prerequisites:** In-scope host, test roles, and controlled fixture.
- **Steps to reproduce:** Numbered, minimal steps using redacted requests.
- **Expected result:** Access should be denied or sensitive fields omitted.
- **Actual result:** What controlled object/data was accessible or changed.
- **Impact:** Demonstrated confidentiality, integrity, or availability consequence.
- **Evidence:** Redacted before/after requests and responses.
- **Limitations:** What was not tested; do not extrapolate beyond the evidence.

## 11. CyberStrike integration contract

The skill should guide the agent through the following workflow:

1. **Scope resolver** — confirm the target is in scope before any active request.
2. **Recon / endpoint inventory** — ingest discovered routes and observed requests without treating all IDs as vulnerable.
3. **Request normalizer** — identify candidate object references and preserve the original request template.
4. **Account/context manager** — associate each request with the correct test principal, role, tenant, and fixture.
5. **Test planner** — generate bounded cross-account comparisons, read-only first.
6. **Tool registry** — resolve the real installed tool and schema; do not assume the illustrative `attack_script` interface exists.
7. **Execution guard** — enforce allowlists, request budgets, secret redaction, and mutation safety gates.
8. **Response diff / state verifier** — compare semantic response content and controlled state, not only status codes.
9. **Finding validator** — apply false-positive checks and confidence gates before creating a finding.
10. **Evidence/report layer** — store minimal redacted evidence, reproducible steps, and severity rationale.
11. **Learning store** — save the endpoint pattern, authorization boundary, validation outcome, and remediation insight without saving tokens or victim data.

If a required component is missing, report the gap explicitly. Do not silently pretend a command, registry entry, database write, or agent handoff succeeded.

### Suggested structured result

```json
{
  "test_type": "idor_bola",
  "target": "https://in-scope.example",
  "endpoint_template": "/api/v1/documents/{document_id}",
  "method": "GET",
  "principal_a": "controlled-owner-account",
  "principal_b": "controlled-test-account",
  "boundary": "cross-account",
  "fixture_id": "REDACTED_TEST_FIXTURE",
  "status": "candidate",
  "confidence": "medium",
  "evidence": {
    "owner_baseline_captured": true,
    "cross_account_response_captured": true,
    "protected_marker_confirmed": false,
    "state_change_verified": false
  },
  "safety": {
    "in_scope": true,
    "read_only": true,
    "secrets_redacted": true
  },
  "notes": "Candidate only; manual validation required."
}
```

This is a proposed output contract, not a claim that the current CyberStrike database or runtime already accepts these exact fields. Align it with the actual finding schema before wiring it into code.

## 12. Related skills and escalation boundaries

- **`attack-jwt`** — check token validation and claims only when evidence indicates a token-related issue. Keep JWT findings distinct from object-authorization findings.
- **`attack-graphql`** — share GraphQL endpoint inventory and controlled object references; verify authorization at each resolver and nested relation.
- **Authentication / authorization bypass skills** — distinguish unauthenticated or function-level access from authenticated cross-object access.
- **Mass-assignment / object-property skills** — investigate field-level changes separately when an otherwise authorized object exposes protected properties.
- **Business-logic skills** — assess consequential workflows only in approved fixtures; do not execute real refunds, transfers, account recovery, role changes, or destructive actions.
- **Triage / report validation** — use the evidence gate and severity policy before creating a final finding.

Cross-skill chaining is a hypothesis-generation aid, not permission to perform account takeover, financial actions, bulk extraction, persistence, or destructive testing. Stop at the smallest safe proof of impact.

## Runtime verification-ledger discipline

When this skill is used by the CyberStrike agent, keep each hypothesis tied to one normalized asset, endpoint, and vulnerability class. Record meaningful strategies and variants through the verification-attempt workflow; an exact retry must not be counted as a new strategy. Continue with materially different, authorized checks while the hypothesis remains unresolved and each next test can change the conclusion. Do not impose an arbitrary fixed attempt ceiling; deduplicate exact retries and stop when evidence resolves the hypothesis, meaningful branches are exhausted, a prerequisite is unavailable, or scope/safety requires stopping. A timeout, blocked precondition, missing test account, weak response difference, or exhausted budget is **inconclusive**, never proof that the issue is a false positive.

Mark a hypothesis confirmed only with direct, durable evidence collected under valid preconditions. Mark it disproven only when valid negative controls and evidence contradict the same hypothesis. Stop earlier for scope ambiguity, unsafe impact, unexpected real-user data, or prohibited state changes. A VRT `tested_not_vulnerable` state must reference the matching evidence-backed disproof record; the skill's own execution notes are not a substitute for the runtime ledger.

## 13. References

- [OWASP API Security Top 10 2023 — API1: Broken Object Level Authorization](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/)
- [OWASP Web Security Testing Guide — API Broken Object Level Authorization](https://owasp.github.io/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/02-API_Broken_Object_Level_Authorization)
- [OWASP REST Assessment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/REST_Assessment_Cheat_Sheet.html)
- [PortSwigger Web Security Academy — Access Control](https://portswigger.net/web-security/access-control/idor)



## Targeted quality-loop enrichment (2026-10-19)

### Endpoint deduplication and state proof
Keep one endpoint record keyed by method + normalized route + parameter shape, with separate observations for every parameter, identity, tenant, role, and response context. Do not create one finding or route entry per swapped ID. For each candidate, preserve owner-object, cross-account control, cross-tenant control, and a known-invalid ID baseline; mutate only a controlled object reference and verify returned object identity or authoritative state. Compare reads, updates, deletes, bulk actions, nested objects, exports, and alternate transport only when actually supported. Hand off role-operation failures to BFLA and sensitive-field-only gaps to property authorization, keeping each distinct root cause separately evidenced.


## Cross-boundary comparison matrix

Use this matrix to make coverage explicit without spraying identifier guesses. Each row needs a real observed operation and a fixture controlled by the tester.

| Boundary | Safe comparison | What must be observed |
|---|---|---|
| Same role, different owner | Account B reads a synthetic object owned by Account A | The returned object marker/owner differs from B's own object and access is not intended |
| Tenant isolation | Test principal from tenant B requests a synthetic tenant-A fixture | Server-side tenant boundary is crossed, not just a changed status code |
| Parent/child relationship | Keep parent fixed, then change only child; reverse only if both fixtures are controlled | Authorization is checked against the correct parent and child relationship |
| Property-level | Submit one benign field change to an object the caller may otherwise access | Protected field changes despite field-level policy; distinguish from object-level BOLA |
| Bulk request | Use only a small explicit list of test-owned fixture IDs, mixing permitted and denied fixtures if safe | Every item is authorized independently; no real-data enumeration |
| Export/download/job | Reuse a test-owned export or download reference from normal UI traffic | Content or job result crosses the intended owner/tenant boundary |
| Revocation/state change | Change test-object membership/ownership through a supported workflow, then recheck access | Access changes (or incorrectly persists) relative to the documented policy |

### Request-template preservation

When normalizing a request, preserve method, route, content type, relevant headers, body shape, and auth context. Keep each distinct parameter as a separate candidate in the same endpoint note; do not duplicate the endpoint merely because it has several object IDs. Record whether the identifier is in the path, query, JSON, GraphQL variables, nested relation, header, or asynchronous job reference.

### Impact chain and handoff rules

- Object readable across owners/tenants → prove the smallest synthetic private marker, then route to report validation.
- JWT claim appears mutable → route to JWT verification only if the server's accepted principal/permissions change.
- API returns private fields while the base object is otherwise legitimately accessible → route to object-property authorization, not automatically BOLA.
- A lower role invokes a privileged operation on its own allowed object → route to function-level authorization; retain BOLA only if the object boundary also fails.
- A cross-tenant cached response is observed → investigate cache separation as a separate root cause; don't double-report one symptom without independent impact.

Record both the positive and negative controls, the principal/object/tenant tuple, and a state re-read for any allowed mutation. Stop at the minimum safe proof and never extrapolate a single fixture into mass exposure.
