---
name: wstg-inpv-05.7
description: "Testing for ORM Injection"
category: input-validation
owasp_id: WSTG-INPV-05.7
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: []
chains_with: []
prerequisites: []
severity_boost: {}
---
# WSTG-INPV-05.7 — ORM and Dynamic Query Injection (Evidence-Led)

## Objective
Assess whether user-controlled input alters an ORM-generated query, filter, or sort operation outside the intended semantics. An ORM, filter parameter, or SQL-like error alone does not prove injection.

## Scope and safety
- Confirm persisted scope for the exact endpoint and canonical target workspace before active requests.
- Use captured requests and approved replay tools with a stable baseline and safe negative control.
- Never use destructive statements, query system catalogs, extract password/hash fields, or enumerate records. Use read-only endpoints and test-owned fixtures.

## Safe test approach
1. Identify the likely ORM/query sink from source review, analyzer evidence, stack traces, or documented filter/sort semantics.
2. Capture a normal query and a known-no-match query for a test-owned resource.
3. Test one bounded variation relevant to the observed parser: invalid field name, unsupported sort key, type mismatch, or a harmless boolean condition. Do not mix multiple operators or inject stacked statements.
4. Compare status, response structure, result count, and errors. Confirm the behavior is attributable to query construction and not ordinary validation.
5. If no safe control can distinguish the hypothesis, stop and preserve the candidate as inconclusive.

## Evidence and reporting
Record request ID, input point, why an ORM sink is plausible, baseline/control, actual result, valid preconditions, and limitations. Use `verification_attempt` and `validate_finding`. A decisive confirmation may stop early; a false-positive/disproven verdict requires 20 distinct valid evidence-backed attempts and matching contradictory checks. Duplicates and invalid preconditions do not count.

Report only demonstrated impact with minimal redacted evidence. Never include credentials, personal data, database dumps, or destructive query output.
