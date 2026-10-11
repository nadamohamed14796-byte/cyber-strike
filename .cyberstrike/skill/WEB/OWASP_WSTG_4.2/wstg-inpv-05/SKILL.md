---
name: wstg-inpv-05
description: "Testing for SQL Injection"
category: input-validation
owasp_id: WSTG-INPV-05
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [injection, input-validation, sqli, database, wstg, inpv]
tech_stack: [http, sql, mysql, postgresql, mssql, oracle]
cwe_ids: [CWE-89]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-sqli/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-sqli/SKILL.md"
  - "https://portswigger.net/web-security/sql-injection"
---

# WSTG-INPV-05: SQL Injection

## Objective

Determine whether untrusted input changes the structure or semantics of a database query, and whether that behavior exposes or modifies data beyond the caller's authorization. Use minimal, non-destructive validation.

## Preconditions and safety

Confirm the endpoint and permitted test class. Start with read-only queries and harmless syntax probes. Do not dump tables, access other users' records, alter/delete data, invoke database file or command features, or run expensive time-delay payloads on production. Use a lab/staging environment for intrusive confirmation.

## Procedure

1. **Map input to query behavior.** Identify parameters in query strings, forms, JSON bodies, headers, sort/filter fields, and nested API arguments. Record the expected type and baseline response.
2. **Capture a baseline.** Save a redacted request, response, timing, and relevant application behavior. Change one input at a time.
3. **Test syntax handling.** Use small, harmless quoting or type-boundary variations and compare response semantics. A generic 500 or WAF block is not proof of SQL injection.
4. **Check boolean differentials.** Where permitted, compare equivalent true/false conditions against a read-only endpoint and verify a stable, explainable response difference. Exclude caching and application validation as alternate causes.
5. **Check error behavior carefully.** Database-specific error messages may aid diagnosis but do not justify retrieving sensitive data. Record only the minimal sanitized error evidence.
6. **Assess blind behavior safely.** Time-based tests can affect availability and should be limited to an approved lab or explicit low-rate production allowance. Prefer controlled, bounded comparisons over repeated delay payloads.
7. **Identify database family cautiously.** Use consistent behavioral evidence rather than assuming a database from framework banners or error wording.
8. **Confirm impact without data extraction.** Demonstrate query manipulation on a synthetic/test record or controlled boolean behavior. Do not dump rows, credentials, schema contents, or other tenants' data.
9. **Review variants.** Database-specific skills `wstg-inpv-05.1` through `wstg-inpv-05.8` cover Oracle, MySQL, SQL Server, PostgreSQL, Access, NoSQL, ORM, and client-side SQL cases; use them only when evidence supports that technology.

## Common false positives

- Input validation rejects a quote and returns a generic error.
- A response difference comes from caching, rate limiting, or WAF behavior.
- A database error appears in logs but user input does not control query structure.
- Scanner output lacks a repeatable semantic differential.
- A SQLi hypothesis is actually NoSQL, ORM, or client-side injection.

## Evidence and output

Record endpoint, parameter, request context, baseline/test pair, database-family confidence, repeatability, authorization context, safe impact proof, cleanup status, and confidence. Recommend parameterized queries, safe ORM APIs, least-privilege database accounts, and server-side allowlists for identifiers that cannot be parameterized.
