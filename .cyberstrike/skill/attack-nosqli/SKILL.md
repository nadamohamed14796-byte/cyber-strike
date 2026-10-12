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

## Scope

- Only test accounts and synthetic/fixture documents the tester owns or was provisioned for the engagement. Never run regex/operator probes designed to enumerate or exfiltrate real user records, even character-by-character.
- Never submit a client-controlled `$where`, `mapReduce`, `$function`, or other server-side-JavaScript/code-execution operator outside an explicitly authorized lab — these execute attacker-supplied code inside the database process and can cause denial of service or data loss.
- Treat any reachable internal data store (Redis, Elasticsearch, CouchDB admin UI) discovered via SSRF or direct exposure as out of scope for exploitation (`CONFIG SET`, `SLAVEOF`, scripted queries, index writes) unless the engagement explicitly authorizes that specific escalation.
- Automated tools (`nosqlmap` or equivalent) are for lab/approved-target use only, with attack modes limited to detection, never bulk dump, against production.

## Testing Methodology

### Phase 1: Identify structured query surfaces

Map JSON bodies, nested filters, search endpoints, login forms, and GraphQL resolvers that may forward objects to a database. Record expected types from the schema and baseline normal scalar behavior. Headers and stack traces are hints only.

### Phase 2: Compare scalar and object types

On a test-only search or fixture endpoint, submit a normal scalar and then a harmless type-mismatched object or array, cycling through the common operator classes one at a time: comparison (`$gt`, `$ne`, `$in`), pattern (`$regex`), and expression (`$expr`, `$text`) — each against a tester-owned record only. Also test the array-notation and encoding variants a naive denylist misses: `field[$ne]=value` in URL-encoded form data (PHP/Express bracket parsing), and a Unicode-escaped operator key (`{"$gt":""}`) where a literal `$gt` string is filtered. Observe schema errors and whether query semantics change. Do not use executable server-side JavaScript operators (`$where`, `$function`, `mapReduce`), regular-expression enumeration of real records, or high-volume predicate loops.

### Phase 3: Check authentication with test identities

Use two accounts you control and credentials you created. Confirm malformed or wrong-type login input (object-valued `username`/`password`, `$ne`/`$gt`/`$in` in place of a string) is rejected and does not issue a valid session or change identity unexpectedly. Do not attempt to log in as a named third-party user or target the first/admin record in a collection.

### Phase 4: Validate bounded data flow

Use a synthetic dataset with known expected results. Compare a known-match, known-no-match, and type-mismatched filter. If `$where` or another server-side-code operator appears reachable, confirm with a single short, strictly-timed delay probe in a lab/approved context only — never a data-dependent conditional against real records. Stop before collection enumeration, bulk extraction, writes, server-side scripting, or SSRF-to-database command chains (e.g., Redis `gopher://` `CONFIG SET`/`SLAVEOF`, Elasticsearch scripted queries).

### Phase 5: Trace root cause

If source is available, follow the value through decoding, schema validation, query construction, and authorization. Verify strict validation and ODM sanitization on nested filters and alternate API versions. Treat a denylist that only string-matches a literal `$` in the serialized body as a weak control — it both false-positives on ordinary strings beginning with `$` and misses bracket-notation, nested, or encoded operators.

## What Constitutes a Finding

- **Candidate / lead:** a JSON field accepts an unexpected object, errors mention operators, or a scanner flags an unvalidated filter.
- **Confirmed finding:** type/operator changes reproducibly alter query semantics on synthetic fixtures or change authentication for an account the tester controls.
- **Impact-qualified finding:** a cross-account or authorization failure is reproduced using test-owned records and a least-privileged test account.
- **Not a finding:** object acceptance alone, an error message, or a changed status code without a stable semantic difference.

## Impact

Severity tracks what the operator/query injection actually reaches, not merely that an object was accepted:

- **Low:** a type-mismatched object or operator is accepted and changes a non-sensitive query's structure, but no authentication or cross-account effect is demonstrated (e.g., a filter silently returns a different, still-benign result set on a synthetic fixture).
- **Medium:** blind confirmation of a server-side-JavaScript-capable operator (`$where`) via a lab-approved timing probe with no proven data exfiltration, or a reproducible query-semantic change that does not cross an authorization boundary.
- **High:** operator injection reliably returns another tester-controlled or synthetic record's data beyond the authorized fixture, or a `$regex`/`$in`-based side channel is shown capable of enumerating account identifiers.
- **Critical:** operator injection (`$gt`, `$ne`, `$regex`, `$in`) bypasses authentication and issues a valid session — especially when it authenticates as the first/admin record in a collection — or a `$where`/code-execution operator is confirmed reachable with server-side JavaScript execution, or the injection chains to an internal data store (Redis/Elasticsearch via SSRF) with write access.

State the exact operator and field, whether authentication was bypassed or a session issued, and whether the result set contained only tester-owned/synthetic data.

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
- **nosqlmap (or equivalent):** lab/approved-target automation only, detection-only attack modes against production.
- **Source review:** verify operator filtering, ODM sanitization, and authorization checks.

## NoSQL Operator and Boundary Matrix

| Surface | Controlled check | Confirmation bar |
|---|---|---|
| Login JSON | Scalar versus invalid object (`$gt`, `$ne`, `$in`, `$regex`) on a tester-owned account | Unauthorized session or identity change is reproducible without valid credentials |
| Search/filter | Known-match, known-no-match, and type-mismatched fixture filter | Stable query-semantic change tied to the untrusted field |
| Encoded/array-notation bypass | Bracket-form (`field[$ne]=x`) and Unicode-escaped operator key against a denylist that string-matches `$` | Confirms the sanitizer is incomplete, not merely theoretical |
| Nested operators | Review recursive validation and strict-schema behavior | Unexpected nested keys are rejected, not silently interpreted |
| `$where`/server-side JS | Single lab-approved timing probe only; never a data-dependent payload against real records | Consistent delay beyond jitter in an authorized context; otherwise candidate only |
| MongoDB/Mongoose | Review filter sanitization and raw operator-enabled APIs (e.g., `populate({match})` forwarding to `$where`) | Reachable input affects a query; merely using MongoDB is irrelevant |
| CouchDB/document APIs | Compare selector validation with documented schema | Only synthetic documents establish impact |
| Internal data store (Redis/Elasticsearch via SSRF) | Confirm reachability only unless protocol testing is specifically authorized | No writes, `CONFIG SET`/`SLAVEOF`, scripted queries, data dumps, or RCE chain by default |

**Mitigation / regression:** enforce exact input types, construct filters from allowlisted fields, reject unknown operators recursively, use supported ODM sanitization, and test the rejection of nested objects on every route.

## Verification and False Positives

- A search API may intentionally accept structured filters; compare with the documented schema.
- Type coercion may be legitimate; use known synthetic records and repeat the baseline.
- Login error text or status alone does not prove bypass; verify session issuance and test identity.
- Database errors can originate in validation middleware rather than query execution.
- A denylist that only string-matches `$` in the raw body can false-positive on ordinary user strings that happen to start with `$` (currency amounts, template placeholders) — confirm with an actual type-mismatched object, not the presence of a dollar sign.
- An authentication bypass that logs in as a *random* existing user (rather than a targetable admin/first record) is weaker evidence than one that reliably reaches a specific privileged account — note which was demonstrated.

## Adaptive Verification Contract (maximum 20 distinct hypotheses)

The 20-attempt budget is a ceiling for independent, evidence-producing hypotheses, not a quota for payload mutations. If a signal remains plausible, follow relevant branches up to the ceiling; stop early when impact is decisive, no relevant branch remains, or safety/scope limits apply. Cosmetic input changes with the same semantics are not separate attempts.

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

## Stop Conditions

- Stop before accessing another tenant's or user's real data, iterating identifiers beyond the tester's own fixtures, executing server-side scripting (`$where`, `mapReduce`), or modifying service configuration.
- Stop immediately if a probe returns a valid session for an account the tester does not control, or returns records outside the synthetic fixture set.
- Stop before pivoting through SSRF into an internal data store (Redis, Elasticsearch, CouchDB) for anything beyond a single reachability check, unless that escalation is explicitly authorized.
- Stop and reconfirm scope on rate-limiting, WAF/IPS blocking, or any service instability signal from repeated operator probes.

## Defensive Notes

Operator injection survives "we build a query object, not a string" because an untrusted value that is itself an object (`{"$gt": ""}`) is still interpreted as an operator by the driver — type-check and allowlist every field's expected scalar type before it reaches the query builder, and reject unknown operators recursively rather than denylisting the `$` character. Disable server-side JavaScript execution (`$where`, `mapReduce` with custom functions) where the application does not require it, since it is the highest-impact variant of this class. Bind data stores (MongoDB, Redis, Elasticsearch, CouchDB) to internal interfaces only, enforce authentication and least-privileged application accounts rather than admin/root credentials, and monitor for anomalous operator usage, slow/large queries, and unauthenticated access attempts at the database layer.

## References

- [elementalsouls/Claude-BugHunter — skills/hunt-nosqli](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-nosqli/SKILL.md) — merged source.

- [uphiago/recon-skills — hunt-nosqli](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-nosqli)
- [elementalsouls/Claude-BugHunter — hunt-sqli (adjacent NoSQL content)](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-sqli)
- [OWASP — NoSQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html)
