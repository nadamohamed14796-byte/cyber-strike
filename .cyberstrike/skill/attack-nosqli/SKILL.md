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

- Python `httpx` or `curl`: repeat a captured, authorized request with one harmless input variation and a control.
- `jq` and `rg`: inspect saved JSON responses and authorized local query construction.
- `mongosh`: only for an explicitly authorized local/test database or source/configuration review.
- `python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt`: compare saved samples offline.

Verify the selected Python client, `jq --version`, and `mongosh --version` when applicable. Official docs: https://www.python-httpx.org/, https://jqlang.org/, https://www.mongodb.com/docs/mongodb-shell/. Never dump collections or modify/delete data.

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


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue with materially distinct, authorized checks while evidence can change the conclusion; deduplicate equivalent JSON encodings and retries. Stop when direct evidence resolves the hypothesis, meaningful branches are exhausted, a prerequisite is unavailable, or scope/safety requires stopping. Do not enumerate or extract production data.

Record each attempt: hypothesis, single changed variable, control/baseline, observed signal, interpretation, confidence and next branch. Prefer paired requests, controlled identities, synthetic records and independent corroboration; retain minimal sanitized evidence.

### Skill-specific hypothesis order

1. Capture a valid response and a known-no-match control for the same test-owned query context; normalize dynamic response fields before comparing.
2. Use benign type mismatches and paired true/false predicates to determine whether user input affects query logic; change one predicate or field per hypothesis.
3. Use only tightly bounded timing checks when permitted, with a small request count, explicit timeout, and a non-injection timing control to account for load and network variance.
4. Confirm a security consequence with synthetic records and a read-only query; do not use destructive operators, enumerate production collections, or dump document contents.
5. Record the exact input context, consistent differential, control result, and likely query boundary. Recommend schema/type validation and safe driver query APIs, then add regression tests.


### Verdict gates

- **Confirmed:** repeatable security impact against an explicitly in-scope resource is shown using a tester-controlled identity/fixture and a meaningful negative control.
- **Likely / needs corroboration:** independent observations support the hypothesis but impact/root cause remains uncertain.
- **Unconfirmed:** output is generic, cached, ambiguous, or detached from a security boundary.
- **Refuted / false positive:** a relevant negative control or valid product/security-policy explanation accounts for the signal. Document attempted branches rather than claiming to exhaust every theoretical variant.
- Status codes, banners, timing changes, error messages, or scanner alerts alone are not proof.

### Stop, cleanup, and handoff

Stop at scope ambiguity, real-user data, unexpected state changes, service degradation, secret exposure or a prohibited action. Clean disposable state, revoke temporary sessions/tokens where possible, and log cleanup status. Handoff scope proof, baseline, hypothesis, attempts used, impact, controls, verdict/confidence, sanitized evidence and any proven related-skill trigger; do not chain from a speculative association.

## References

- [elementalsouls/Claude-BugHunter — skills/hunt-nosqli](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-nosqli/SKILL.md) — merged source.

- [uphiago/recon-skills — hunt-nosqli](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-nosqli)
- [elementalsouls/Claude-BugHunter — hunt-sqli (adjacent NoSQL content)](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-sqli)
- [OWASP — NoSQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html)


## Targeted quality-loop enrichment (2026-10-19)

### Query-operator and data-boundary evidence
Identify whether user input is interpreted as a scalar, object, operator, regular expression, filter, or aggregation stage. Establish a normal test-account query and a known-invalid query, then vary the input type once while keeping identity and data constant. Use only a synthetic fixture and compare query semantics or returned fixture membership; never enumerate real records or dump collections. A syntax error or changed response size alone is ambiguous. Confirm that the server interprets the input as control structure and that the effect crosses a protected data/auth boundary. Route authentication effects to auth-bypass review, and generic untrusted-object binding to mass-assignment/schema review.


## Structured-input differential ledger

For each input, record its expected schema type and actual interpretation. Keep JSON structure explicit—string, number, boolean, null, array, and object are different test dimensions.

| Input contract | Safe comparison | What must be shown |
|---|---|---|
| Scalar username/search | Valid scalar vs wrong JSON type | Query semantics change beyond validation error |
| Nested filter | Documented filter object vs one unsupported nested key in a synthetic dataset | Server interprets untrusted key as query control rather than rejecting it |
| Operator-capable field | Known-match and known-no-match controls | Unauthorized fixture membership or authentication outcome changes |
| Aggregation/report filter | One small documented filter vs invalid type in staging | Query path is reachable and result differs semantically |
| Login/session | Valid owned credentials vs malformed-type input | Server issues a session for an identity without valid proof; status alone is insufficient |
| ODM/driver boundary | Source trace of input validation and query construction | Reachable untrusted value reaches a query sink without safe schema/type enforcement |

### Safe local JSON type inspection

```bash
jq -r 'paths(scalars) as $p | [($p | map(tostring) | join(".")), (getpath($p) | type)] | @tsv' request-redacted.json
```

Use a redacted request captured from your own test account. The command inventories scalar paths/types; it does not prove query injection.

### Chain routing

- Query semantics alter login identity → auth-bypass review, with a tester-owned identity and no real-user guessing.
- Query semantics expose another controlled object's fields → BOLA/property authorization as separate checks.
- Input is accepted as a structured model field but not interpreted as a query operator → mass-assignment/schema validation, not NoSQL injection.
- Only a parser error is observed → keep as a lead; do not infer database-wide access or code execution.

Persist input_json_path, expected_type, actual_type, known_match_control, known_no_match_control, candidate_result, synthetic_fixture_ids, session_issued, query_sink_evidence, and cleanup_status.


## Agent-executable CLI tooling, resources, and helper scripts

### Agent-usable CLI tools
- Python `httpx` or `requests`: repeat a captured, authorized request with one harmless input variation and preserve a control.
- `jq` and `rg`: inspect saved JSON responses and authorized local source for query construction and validation.
- `mongosh`: only for an explicitly authorized local/test database or source/configuration review; do not connect to production databases unless explicitly included in scope.
- Existing helper `python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt`: compare saved samples offline.
### Installation and verification
Verify the chosen Python client and `jq --version`; follow official docs at https://www.python-httpx.org/, https://jqlang.org/, and https://www.mongodb.com/docs/mongodb-shell/. If missing, use source review or a local fixture and record the limitation.
### Resources
- https://portswigger.net/web-security/nosql-injection
- https://owasp.org/www-project-web-security-testing-guide/
- https://www.mongodb.com/docs/manual/core/security/
### Proof and limits
Use harmless boolean/differential checks in an approved environment. Never dump collections, enumerate private records, or modify/delete data. A parse error alone is not proof.
