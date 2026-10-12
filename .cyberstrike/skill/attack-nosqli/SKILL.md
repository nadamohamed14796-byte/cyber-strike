---
name: attack-nosqli
description: "Validate NoSQL query and operator injection by comparing scalar and structured inputs against controlled test data and authorization boundaries."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - nosqli
  - mongodb
  - operator-injection
  - authentication
  - api
tech_stack:
  - web
  - rest-api
  - graphql
  - mongodb
  - mongoose
  - couchdb
cwe_ids:
  - CWE-943
  - CWE-74
chains_with:
  - attack-sqli
  - attack-auth-bypass
  - attack-idor-automation
prerequisites: []
severity_boost:
  attack-auth-bypass: "Operator injection that changes an authentication decision can become a separately verified authentication-bypass finding."
---

# NoSQL Query Injection Validation

## Objective

Determine whether untrusted input is interpreted as query operators or executable query logic rather than an expected scalar. Keep validation limited to test accounts and synthetic documents; never enumerate unrelated users or collections.

## Testing Methodology

### Phase 1: Identify structured query surfaces

Map JSON bodies, nested filters, search endpoints, login forms, and GraphQL resolvers that may forward objects to a database. Record expected types from the schema and baseline normal scalar behavior. Headers and stack traces are hints only.

### Phase 2: Compare scalar and object types

On a test-only search or fixture endpoint, submit a normal scalar and then a harmless type-mismatched object or array. Observe schema errors and whether query semantics change. Do not use executable server-side JavaScript operators, regular-expression enumeration, or high-volume predicate loops.

### Phase 3: Check authentication with test identities

Use two accounts you control and credentials you created. Confirm malformed or wrong-type login input is rejected and does not issue a valid session or change identity unexpectedly. Do not attempt to log in as a named third-party user or target the first/admin record in a collection.

### Phase 4: Validate bounded data flow

Use a synthetic dataset with known expected results. Compare a known-match, known-no-match, and type-mismatched filter. Stop before collection enumeration, bulk extraction, writes, server-side scripting, or SSRF-to-database command chains.

### Phase 5: Trace root cause

If source is available, follow the value through decoding, schema validation, query construction, and authorization. Verify strict validation and ODM sanitization on nested filters and alternate API versions.

## What Constitutes a Finding

- **Candidate / lead:** a JSON field accepts an unexpected object, errors mention operators, or a scanner flags an unvalidated filter.
- **Confirmed finding:** type/operator changes reproducibly alter query semantics on synthetic fixtures or change authentication for an account the tester controls.
- **Impact-qualified finding:** a cross-account or authorization failure is reproduced using test-owned records and a least-privileged test account.
- **Not a finding:** object acceptance alone, an error message, or a changed status code without a stable semantic difference.

## Evidence Requirements

- Baseline and modified requests preserving JSON types and nesting.
- Expected versus observed synthetic document identifiers/counts; no real records.
- Tester account roles, tenant, timestamp, and whether a session was actually issued.
- Sanitized response and relevant schema/validation behavior.
- Never include raw credentials, user collections, token values, or third-party data.

## Tools

- **Burp Suite Repeater:** compare scalar, object, and invalid-type requests.
- **curl / jq:** preserve JSON types and inspect controlled fixture results.
- **OpenAPI/GraphQL schema viewer:** establish expected types and resolver contracts.
- **Source review:** verify operator filtering, ODM sanitization, and authorization checks.

## NoSQL Operator and Boundary Matrix

| Surface | Controlled check | Confirmation bar |
|---|---|---|
| Login JSON | Scalar versus invalid object on a tester-owned account | Unauthorized session or identity change is reproducible without valid credentials |
| Search/filter | Known-match, known-no-match, and type-mismatched fixture filter | Stable query-semantic change tied to the untrusted field |
| Nested operators | Review recursive validation and strict-schema behavior | Unexpected nested keys are rejected, not silently interpreted |
| MongoDB/Mongoose | Review filter sanitization and raw operator-enabled APIs | Reachable input affects a query; merely using MongoDB is irrelevant |
| CouchDB/document APIs | Compare selector validation with documented schema | Only synthetic documents establish impact |
| Internal data store | Confirm reachability only unless protocol testing is specifically authorized | No writes, replication changes, data dumps, or RCE chain by default |

**Mitigation / regression:** enforce exact input types, construct filters from allowlisted fields, reject unknown operators recursively, use supported ODM sanitization, and test the rejection of nested objects on every route.

## Verification and False Positives

- A search API may intentionally accept structured filters; compare with the documented schema.
- Type coercion may be legitimate; use known synthetic records and repeat the baseline.
- Login error text or status alone does not prove bypass; verify session issuance and test identity.
- Database errors can originate in validation middleware rather than query execution.
- Stop before accessing another tenant's data, iterating identifiers, scripting in the DB, or modifying service configuration.

## References

- [elementalsouls/Claude-BugHunter — skills/hunt-nosqli](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-nosqli/SKILL.md) — merged source.

- [uphiago/recon-skills — hunt-nosqli](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-nosqli)
- [elementalsouls/Claude-BugHunter — hunt-sqli (adjacent NoSQL content)](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-sqli)
- [OWASP — NoSQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html)
