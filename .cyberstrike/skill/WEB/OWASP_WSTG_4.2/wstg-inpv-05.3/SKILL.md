---
name: wstg-inpv-05.3
description: "Testing for SQL Injection - SQL Server"
category: input-validation
owasp_id: WSTG-INPV-05.3
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: []
chains_with: []
prerequisites: []
severity_boost: {}
---
# WSTG-INPV-05.3 — SQL Server Injection (Evidence-Led)

## Objective
Assess whether captured input reaches a SQL Server query unsafely. SQL Server error strings and syntax are clues, not proof.

## Scope and preconditions
- Confirm the exact endpoint and canonical target workspace with persisted scope before active requests.
- Use captured requests, approved replay tools, a stable baseline, and a safe negative control.
- Test SQL Server-specific behavior only when evidence makes MSSQL plausible. Do not use `xp_cmdshell`, `OPENROWSET`, linked-server access, stacked statements, system catalogs, file operations, network callbacks, OS commands, or data extraction.

## Safe test approach
1. Preserve the original request ID, response status/body shape, and expected behavior.
2. If a SQL Server sink is plausible, compare a harmless constant/boolean condition with its controlled false counterpart on a test-owned, read-only fixture.
3. Change one input at a time. Use short, bounded tests only; do not run time-delay loops or a generic payload battery.
4. Treat SQL Server error text or a changed status as a lead. Establish that the difference is attributable to query evaluation rather than validation, caching, WAF/CDN, or a generic exception.
5. Do not escalate a query signal to command execution or data extraction. If safe controls are unavailable, mark the result inconclusive.

## Evidence and reporting
Record the request ID, candidate input, why MSSQL is plausible, baseline/control, actual result, valid preconditions, and limitations. Use `verification_attempt` and `validate_finding`. A decisive confirmation may stop early; a false-positive/disproven verdict requires 20 distinct valid evidence-backed attempts and matching contradictory checks. Duplicates and invalid preconditions do not count.

Report only demonstrated impact with minimal redacted evidence. Never include credentials, personal data, database dumps, or OS command output.
