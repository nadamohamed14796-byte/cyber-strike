---
name: wstg-inpv-05
description: "Testing for SQL Injection"
category: input-validation
owasp_id: WSTG-INPV-05
version: "1.2.0"
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

Determine whether untrusted input changes the structure or semantics of a database query, and whether that behavior violates authorization or data integrity. Use the smallest safe proof; do not extract database contents or perform destructive operations.

## Preconditions and safety

- Confirm endpoint, test class, request budget, and whether blind/time-based checks are allowed.
- Start with read-only routes and a test account. Use a lab/staging environment for intrusive confirmation.
- Do not dump tables, enumerate credentials, access other tenants' records, alter/delete data, invoke database file/command features, or run expensive delay payloads against production.
- Stop on instability, elevated latency, throttling, unexpected data, or ambiguous scope.
- Redact secrets and personal data from all saved requests and error output.

## Procedure

### 1. Map inputs and establish a baseline

1. Identify candidate values in query strings, path parameters, form fields, JSON bodies, headers, sort/filter expressions, and nested API arguments.
2. Record the expected type, validation rule, and baseline response for each candidate.
3. Change one input at a time and preserve a redacted baseline/test pair.
4. Note whether the parameter should be a value or an identifier/operator. Sort columns and SQL fragments often need allowlisting rather than value parameterization.

### 2. Test syntax and validation behavior

- Use a small, harmless set of quote/type-boundary variations to learn whether the input is rejected, normalized, or changes response semantics.
- Distinguish application validation errors, WAF blocks, generic 500 responses, and database-generated errors.
- Do not infer SQL injection from a single error message or status code.
- Check whether the same field is handled consistently across equivalent API routes and methods that are in scope.

### 3. Check controlled boolean differentials

- Only where permitted, compare two read-only requests that differ in a single logical condition and should otherwise return equivalent results.
- Use a controlled record set and compare stable semantics such as result count or a known test marker, not response length alone.
- Repeat only enough to rule out caching, personalization, pagination, and transient backend behavior.
- Do not use conditions intended to retrieve rows belonging to other users or tenants.

### 4. Review error-based signals

- Record only the minimum sanitized error evidence needed to identify a likely query-construction problem.
- Do not provoke verbose database output to extract table names, data, or credentials.
- Check whether errors expose implementation details to unauthenticated users and whether the same issue is reproducible with a benign input.
- Treat a database banner or framework name as a weak clue, not proof of the database engine.

### 5. Handle blind and time-based hypotheses cautiously

- Prefer non-timing behavioral evidence or a local lab with controlled database fixtures.
- Production timing tests require explicit permission, a strict request budget, and low-impact timing bounds; do not issue repeated long-delay probes.
- Account for network variance, queuing, caches, and asynchronous work before attributing latency to database execution.
- Stop immediately if latency rises or the service becomes unstable.

### 6. Identify query construction and database family

- Determine whether the application uses parameterized queries, a query builder, an ORM, or string concatenation where evidence is available.
- Review code or query logs only when authorized and accessible.
- Use multiple consistent signals before naming a database family.
- Route NoSQL, ORM-specific, client-side SQL, and database-specific behavior to a focused skill only when the evidence supports it.

### 7. Confirm impact without extraction

- Demonstrate a controlled semantic difference using a synthetic record or a read-only endpoint.
- Show the expected behavior, the minimal changed input, and the observed difference.
- Do not dump rows, enumerate schema, retrieve secrets, modify data, or chain the issue into file access or command execution.
- State what is confirmed and what remains untested.

### 8. Cleanup and retest

Restore synthetic state if any permitted write was necessary. After a fix, repeat the same minimal request pair and confirm that input is treated as data and that errors no longer disclose internals.

## Common false positives

- Input validation rejects a quote and returns a generic error.
- A response difference comes from caching, pagination, rate limiting, or WAF behavior.
- A database error appears in logs but input does not control query structure.
- Scanner output lacks a repeatable semantic differential.
- The issue is NoSQL, ORM, or client-side injection rather than SQL injection.
- A time difference is within normal network variance.

## Evidence contract

Record endpoint, parameter, authentication/authorization context, redacted baseline/test pair, observed semantic difference, error behavior, repeatability, database-family confidence, safe impact proof, cleanup status, and confidence. Never include extracted database rows or credentials.

## Remediation guidance

Use parameterized queries and safe ORM APIs for values, allowlist identifiers/operators that cannot be parameterized, enforce least-privilege database accounts, avoid verbose production errors, and add regression tests for each affected query path.
