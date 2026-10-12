---
name: attack-sqli
description: "Validate SQL injection in scoped application inputs through controlled syntax, response-differential, and test-data checks without dumping production data."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - sqli
  - injection
  - database
  - api
  - validation
tech_stack:
  - web
  - rest-api
  - graphql
  - mysql
  - postgresql
  - mssql
  - sqlite
cwe_ids:
  - CWE-89
chains_with:
  - attack-nosqli
  - attack-auth-bypass
  - attack-graphql
prerequisites: []
severity_boost:
  attack-auth-bypass: "A verified query-injection flaw that changes an authentication decision may expand into a separate authentication-bypass finding."
---

# SQL Injection Validation

## Objective

Determine whether attacker-controlled input changes database query structure, then establish the narrowest reproducible impact. Use explicitly in-scope endpoints and test accounts with synthetic records.

## Testing Methodology

### Phase 1: Map scoped input surfaces

Confirm the exact host, endpoint, allowed methods, account context, and request budget. Inventory URL, JSON/form, path, header, and cookie inputs from normal application use. Prioritize search, filter, sort, reporting, lookup, and login parameters. Stack fingerprints are prioritization hints, not proof.

### Phase 2: Establish a clean baseline

Save a normal request and response. Record status, response length, stable fields, timing, and expected behavior. Repeat the baseline once on noisy endpoints. Use Repeater or equivalent and modify one input at a time.

### Phase 3: Probe syntax safely

On a read-only endpoint, compare a normal value with a single quote, double quote, or unmatched delimiter encoded for the input context. Look for a database-specific error or consistent parser difference. Do not use stacked statements, file read/write functions, or commands that change state.

### Phase 4: Confirm a differential

Where permitted, compare paired true/false predicates against a test-owned record, keeping every other field constant. Repeat a small number of times to exclude caching and jitter. Timing tests belong in a lab or explicitly approved test; use one short delay, strict timeouts, and no loops. A slow response alone is not confirmation.

### Phase 5: Validate minimum impact

Prefer source/configuration review, a program-provided dataset, or a synthetic row owned by the tester. Show only the minimum query-boundary failure. Do not enumerate schemas, dump tables, retrieve credentials, or attempt OS execution on production. Ask for explicit approval before any higher-impact proof.

## What Constitutes a Finding

- **Candidate / lead:** an error, response-size change, scanner alert, or timing anomaly follows a syntax probe.
- **Confirmed finding:** repeatable query-structure influence is established by a database-specific error plus an independent differential, a controlled fixture, or source tracing to an unsafe query.
- **Impact-qualified finding:** a synthetic record or operation demonstrates unauthorized access; do not infer database-wide access or RCE from a parser error.
- **Not reportable alone:** a generic 500, WAF block, isolated latency spike, or unverified scanner output.

## Evidence Requirements

- Sanitized baseline and probe request/response, including method, input encoding, and content type.
- Timestamp, endpoint, authentication role, and ownership of the test record.
- Paired results and repeated timing samples if timing is essential.
- Minimal synthetic/canary result and the boundary crossed.
- Redact cookies, tokens, personal data, connection strings, and database contents.

## Tools

- **Burp Suite Repeater:** controlled one-variable request comparisons.
- **curl:** reproducible single-request probes with explicit timeouts.
- **sqlmap:** use in an isolated lab or with explicit program approval; disable data enumeration and extraction for production checks.
- **Source/log review:** trace input to query construction and parameter binding without accessing production records.

## SQL Dialect and Confirmation Matrix

| Signal | Bounded validation | What it proves—and does not prove |
|---|---|---|
| SQL parser error | One delimiter probe and a baseline comparison | A parser path may be reached; not proof of data access |
| Boolean differential | Paired conditions against a test fixture | Stable query influence after excluding business-rule changes |
| Timing behavior | Lab/approved test with a short delay and control | Must exceed jitter consistently; one slow response is weak evidence |
| ORM/raw fragment | Review dynamic sort keys, aliases, JSON paths, and raw query APIs | Unsafe construction is a candidate until tied to reachable input |
| Second-order input | Use a disposable test record and observe the later processing path | Delayed query influence may exist; do not plant active payloads in shared data |
| GraphQL resolver | Test a controlled argument and test-owned object | Confirms only the tested resolver path |

**Mitigation / regression:** parameterize values, allowlist identifiers that cannot be bound, remove raw fragments built from untrusted data, use least-privilege DB accounts, and regression-test the exact endpoint and dialect.

## Verification and False Positives

- Framework validation errors and WAF pages can resemble database errors; compare fingerprints and a clean control.
- Result changes can arise from normalization, ranking, caching, or flags; use the same synthetic fixture.
- Latency spikes can be caused by network jitter, cold caches, or rate limiting; do not conclude time-based SQLi from one sample.
- A source-code grep hit is only a lead unless attacker-controlled data reaches the query sink.
- Stop at unexpected state changes, real data exposure, service instability, rate-limit warnings, or scope uncertainty.


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Use the 20-attempt budget as a ceiling for independent, evidence-producing hypotheses—not as a target number of payloads. If the finding remains plausible, follow distinct signal-led branches up to the ceiling; stop earlier when the effect is decisive, no relevant branch remains, or scope/safety limits apply. Cosmetic variants do not count as independent attempts.

Keep an attempt ledger: hypothesis, one variable changed, baseline/control, signal, interpretation, confidence and next branch. Use controlled identities/fixtures, independent corroboration, low-impact requests and minimum sanitized evidence.

### Skill-specific hypothesis order

1. Capture a normal valid request, an invalid-type/control request, and a known-no-match response for a test-owned resource before interpreting any differential.
2. Use paired benign Boolean predicates and minimal syntax-boundary values to test whether input reaches a database query; vary one parameter and one condition at a time.
3. Only use tightly bounded time-based checks when permitted, with explicit timeouts, a small number of observations, and a non-injection timing control to account for load/network noise.
4. Confirm the query boundary using synthetic data or a harmless predicate outcome; do not dump tables, extract credentials, modify records, or use destructive statements to demonstrate SQL injection.
5. Record the exact parameter, DB error or repeatable logical differential, negative control, and confidence. Recommend parameterized queries/ORM-safe binding and regression tests for the affected data type.


### Verdict gates

- **Confirmed:** repeatable impact at an explicit in-scope boundary is demonstrated with a controlled fixture/identity and relevant control.
- **Likely / needs corroboration:** multiple independent signals support the candidate but the effect or cause remains uncertain.
- **Unconfirmed:** signal is generic, timing/cache-dependent, or not tied to a security property.
- **Refuted / false positive:** a relevant control or valid product/security behavior explains the observation; preserve the test ledger rather than claiming all theoretical vectors were attempted.
- A status code, banner, parser error, timing fluctuation, version string, or scanner alert alone is not proof.

### Safety, cleanup, and handoff

Stop on scope ambiguity, unexpected state changes, sensitive data, service degradation, secret exposure or prohibited actions. Restore synthetic state and revoke temporary credentials/sessions where possible. Report scope proof, baseline, hypothesis, attempt count, impact, controls, verdict/confidence, sanitized evidence and cleanup status. Chain into another skill only after observing its required signal.

## References

- [uphiago/recon-skills — hunt-sqli](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-sqli)
- [elementalsouls/Claude-BugHunter — hunt-sqli](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-sqli)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
