---
name: wstg-inpv-05.4
description: "Testing for SQL Injection - PostgreSQL"
category: input-validation
owasp_id: WSTG-INPV-05.4
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: []
chains_with: []
prerequisites: []
severity_boost: {}
---
# WSTG-INPV-05.4 — PostgreSQL Injection (Evidence-Led)

## Objective
Assess whether captured input reaches a PostgreSQL query unsafely. PostgreSQL-specific errors and syntax are clues, not proof.

## Scope and preconditions
- Confirm the exact endpoint and canonical target workspace with persisted scope before active requests.
- Use captured requests, approved replay tools, a stable baseline, and a safe negative control.
- Test PostgreSQL-specific behavior only when evidence makes it plausible. Do not query system catalogs or user tables, use `pg_read_file`, `COPY` file operations, extensions for command execution, stacked statements, network callbacks, or data extraction.

## Safe test approach
1. Preserve the original request ID, response shape, and expected behavior.
2. If a PostgreSQL sink is plausible, use a minimal constant/boolean comparison with a controlled false counterpart against a test-owned, read-only fixture.
3. Change one relevant input at a time. Do not use delay loops, file operations, or an automated dump/exploitation mode.
4. Treat PostgreSQL error text, status changes, or response-length/timing differences as leads. Rule out validation, caching, WAF/CDN, and generic errors.
5. If no safe control distinguishes query evaluation, stop and record the limitation; do not extract data or escalate to OS execution.

## Evidence and reporting
Record request ID, candidate input, why PostgreSQL is plausible, baseline/control, actual result, valid preconditions, and limitations. Use `verification_attempt` and `validate_finding`. A decisive confirmation may stop early; a false-positive/disproven verdict requires 20 distinct valid evidence-backed attempts and matching contradictory checks. Duplicates and invalid preconditions do not count.

Report only demonstrated impact with minimal redacted evidence. Never include credentials, personal data, database dumps, file contents, or command output.
