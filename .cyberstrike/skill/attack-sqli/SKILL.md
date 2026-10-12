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

## Scope

- Only test explicitly in-scope hosts/endpoints, using test accounts or synthetic records the tester owns. Never run extraction against a parameter you have not confirmed targets a non-production or tester-owned dataset.
- Non-destructive, read-oriented checks only. Never send a tautology or payload that could reach an `UPDATE`, `DELETE`, `INSERT`, or stored-procedure side effect on real data — `' OR '1'='1` against a mass-update endpoint is a data-loss risk, not a detection probe.
- Full automated enumeration (`sqlmap --dbs --dump`, `INFORMATION_SCHEMA`/`sqlite_master`/catalog walks, `UNION`-based table dumps) is reserved for an isolated lab, a program-approved target, or a tester-owned synthetic fixture — never run unthrottled extraction against a shared production database.
- Out-of-band (OAST/DNS) payloads must use the engagement's own collaborator/callback infrastructure, never a third party's, and must not be left running unattended.
- Never attempt `xp_cmdshell`, `COPY ... FROM PROGRAM`, `LOAD_FILE`/`INTO OUTFILE`, or any other OS-interaction primitive outside an explicitly authorized, approved escalation step.

## Testing Methodology

### Phase 1: Map scoped input surfaces

Confirm the exact host, endpoint, allowed methods, account context, and request budget. Inventory URL, JSON/form, path, header, and cookie inputs from normal application use. Prioritize search, filter, sort, reporting, lookup, and login parameters. Also inventory non-obvious vectors that get stored and rendered later — `User-Agent`, `Referer`, `X-Forwarded-For`, profile/display-name fields — since these are common second-order injection points. Stack fingerprints (`X-Powered-By`, verbose error strings, ORM signatures) are prioritization hints, not proof.

### Phase 2: Establish a clean baseline

Save a normal request and response. Record status, response length, stable fields, timing, and expected behavior. Repeat the baseline once on noisy endpoints. Use Repeater or equivalent and modify one input at a time.

### Phase 3: Probe syntax safely

On a read-only endpoint, compare a normal value with a single quote, double quote, backtick, or unmatched comment/delimiter sequence encoded for the input context (URL-encoded, double-encoded, or Unicode-homoglyph quote where a WAF is suspected of filtering a literal `'`). Look for a database-specific error, a consistent parser difference, or a response-length/structure change. Also test the same probe in `ORDER BY`/sort parameters and in any field that becomes a column or table identifier — these cannot be parameterized by the application and are common gaps — but confirm only a parser-boundary reaction, never pivot to extraction here. Do not use stacked statements, file read/write functions, or commands that change state.

### Phase 4: Confirm a differential

Where permitted, compare paired true/false predicates against a test-owned record, keeping every other field constant. Repeat a small number of times to exclude caching and jitter. Timing tests belong in a lab or explicitly approved test; use one short delay, strict timeouts, and no loops. A slow response alone is not confirmation. Where in-band differentials are inconclusive and the engagement permits out-of-band testing, a single OAST payload (DNS/HTTP callback with a unique marker) against the engagement's own collaborator is stronger evidence than an extra timing sample, and works even when the application suppresses both errors and timing differences.

### Phase 5: Validate minimum impact

Prefer source/configuration review, a program-provided dataset, or a synthetic row owned by the tester. If a UNION path is viable on a tester-owned, read-only, row-reflecting endpoint, establish the column count by incrementing `ORDER BY`/`NULL` probes one column at a time rather than guessing — but stop once query-structure control is proven; do not pull real schema or data. Show only the minimum query-boundary failure. Do not enumerate schemas, dump tables, retrieve credentials, or attempt OS execution on production. Ask for explicit approval before any higher-impact proof.

## What Constitutes a Finding

- **Candidate / lead:** an error, response-size change, scanner alert, or timing anomaly follows a syntax probe.
- **Confirmed finding:** repeatable query-structure influence is established by a database-specific error plus an independent differential, a controlled fixture, or source tracing to an unsafe query.
- **Impact-qualified finding:** a synthetic record or operation demonstrates unauthorized access; do not infer database-wide access or RCE from a parser error.
- **Not reportable alone:** a generic 500, WAF block, isolated latency spike, or unverified scanner output.

## Impact

Severity tracks what query-structure control actually reaches, not the mere presence of a parser error:

- **Low:** a confirmed syntax/parser differential (error-based or boolean) on a non-sensitive, read-only endpoint with no demonstrated data access beyond the tester's own synthetic row — e.g., confirming that a sort parameter reaches raw SQL without extracting any other row.
- **Medium:** reliable extraction of non-sensitive metadata (database/engine version, table names, a tester-owned record's own fields) via UNION, boolean, or time-based blind technique, or a second-order injection confirmed on a tester-owned stored value with no proven path to other users' data.
- **High/Critical:** verified read or write access to other users'/tenants' data, authentication bypass via injected boolean/UNION logic, extraction of credentials or session tokens, or a query-injection primitive that chains to OS command execution (`xp_cmdshell`, `COPY ... FROM PROGRAM`, `LOAD_FILE`/`INTO OUTFILE`) — especially when reachable pre-authentication or from a low-privilege account against an over-privileged DB connection.

State the exact injection point, the database engine and query context (WHERE clause, ORDER BY/identifier position, stored-then-rendered second-order sink), and whether exploitation requires authentication, a specific role, or chaining with another finding (e.g., IDOR using extracted IDs).

## Evidence Requirements

- Sanitized baseline and probe request/response, including method, input encoding, and content type.
- Timestamp, endpoint, authentication role, and ownership of the test record.
- Paired results and repeated timing samples if timing is essential.
- Minimal synthetic/canary result and the boundary crossed.
- Redact cookies, tokens, personal data, connection strings, and database contents.

## Tools

- **Burp Suite Repeater:** controlled one-variable request comparisons.
- **curl:** reproducible single-request probes with explicit timeouts.
- **sqlmap:** use in an isolated lab or with explicit program approval; disable data enumeration and extraction for production checks (never run bare `--dbs`/`--dump` against a live, shared database).
- **Burp Suite Intruder:** bounded, low-concurrency payload sweeps for column-count or boolean-differential enumeration on a tester-owned record only.
- **OAST/collaborator client (Burp Collaborator or equivalent):** out-of-band confirmation when in-band error/boolean/timing signals are suppressed or inconclusive; use only the engagement's own listener.
- **Source/log review:** trace input to query construction and parameter binding, dynamic `ORDER BY`/identifier construction, and ORM raw-query or raw-fragment APIs (e.g., Django `.extra()`/`.values()` with unescaped keys, Sequelize/Mongoose raw operators) without accessing production records.

## SQL Dialect and Confirmation Matrix

| Signal | Bounded validation | What it proves—and does not prove |
|---|---|---|
| SQL parser error | One delimiter probe and a baseline comparison | A parser path may be reached; not proof of data access |
| Boolean differential | Paired conditions against a test fixture | Stable query influence after excluding business-rule changes |
| Timing behavior | Lab/approved test with a short delay and control | Must exceed jitter consistently; one slow response is weak evidence |
| Out-of-band (OAST) | DNS/HTTP callback with a unique marker via the engagement's own collaborator | Confirms execution even when errors/timing are suppressed; requires outbound network egress from the DB host |
| ORM/raw fragment | Review dynamic sort keys, aliases, JSON paths, and raw query APIs | Unsafe construction is a candidate until tied to reachable input (e.g., Django JSONField key used as unescaped column alias, CVE-2024-42005; Mongoose `populate({match})` forwarding to `$where`, CVE-2024-53900) |
| Identifier/ORDER BY position | Probe a sort/column/table-name parameter that cannot be bound as a value | Confirms the identifier path is unparameterized; does not by itself prove data exposure |
| Second-order input | Use a disposable test record and observe the later processing path | Delayed query influence may exist; do not plant active payloads in shared data |
| GraphQL resolver | Test a controlled argument and test-owned object | Confirms only the tested resolver path |

**Mitigation / regression:** parameterize values, allowlist identifiers that cannot be bound, remove raw fragments built from untrusted data, use least-privilege DB accounts, and regression-test the exact endpoint and dialect.

## Verification and False Positives

- Framework validation errors and WAF pages can resemble database errors; compare fingerprints and a clean control.
- Result changes can arise from normalization, ranking, caching, or flags; use the same synthetic fixture.
- Latency spikes can be caused by network jitter, cold caches, or rate limiting; do not conclude time-based SQLi from one sample.
- A source-code grep hit is only a lead unless attacker-controlled data reaches the query sink.
- A WAF-block page (403/406, vendor challenge body) can resemble a database error at a glance; diff the actual body against both a clean control and a known-benign 403 before calling it a SQLi signal.
- A validated/allowlisted identifier (sort key, column alias) that is merely unescaped is not yet a finding until a value outside the allowlist is shown to reach the query — generic table/column fuzzing against production can itself cause data loss, so confirm on a synthetic fixture first.

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

## Stop Conditions

- Stop at unexpected state changes, real data exposure, service instability, rate-limit warnings, or scope uncertainty.
- Stop immediately if a probe returns rows, fields, or counts that are not attributable to the tester's own synthetic record — do not continue extracting "to see how far it goes."
- Stop and reconfirm scope before any payload that could reach `INSERT`/`UPDATE`/`DELETE`, a stored procedure with side effects, or file/OS-interaction functions (`xp_cmdshell`, `LOAD_FILE`, `COPY ... FROM PROGRAM`).
- Stop sqlmap or Intruder runs that exceed the agreed request budget or trigger WAF/IPS blocking; escalate for approval rather than tuning around the block.

## Defensive Notes

Parameterized queries/prepared statements close the vast majority of this class, but they do not cover identifiers — table names, column names, and `ORDER BY` direction must be resolved through a server-side allowlist, never built from raw input. ORMs reduce but do not eliminate risk: raw-fragment escapes (`.extra()`, raw `$where`/`populate(match)` operators, string-built HQL/JPQL) reintroduce the same flaw and should be flagged in code review as high-risk surface. Run application database accounts with least privilege (no `FILE`, `xp_cmdshell`, or superuser rights) so that a confirmed injection cannot escalate to file read/write or OS execution, and monitor for anomalous query patterns (unexpected `UNION`, `INFORMATION_SCHEMA`/catalog access, repeated syntax-error bursts) at the database or WAF layer as a detective control.

## References

- [uphiago/recon-skills — hunt-sqli](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-sqli)
- [elementalsouls/Claude-BugHunter — hunt-sqli](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-sqli)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [PortSwigger Web Security Academy — SQL injection](https://portswigger.net/web-security/sql-injection)
