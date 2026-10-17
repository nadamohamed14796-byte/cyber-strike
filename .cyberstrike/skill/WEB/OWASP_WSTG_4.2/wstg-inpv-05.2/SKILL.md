---
name: wstg-inpv-05.2
description: "Testing for SQL Injection - MySQL"
category: input-validation
owasp_id: WSTG-INPV-05.2
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: []
chains_with: []
prerequisites: []
severity_boost: {}
---
# WSTG-INPV-05.2 — MySQL SQL Injection (Evidence-Led)

## Objective
Assess whether a captured input reaches a MySQL/MariaDB query unsafely. A MySQL error or parameter name alone is not proof.

## Scope and preconditions
- Confirm the exact endpoint and canonical target workspace with persisted scope before active requests.
- Use captured requests, approved replay tools, a stable baseline, and a safe negative control.
- Test MySQL-specific syntax only when evidence makes MySQL plausible. Never query `information_schema`, user tables, credentials, files, or network services. Do not use `SLEEP` loops, `LOAD_FILE`, `INTO OUTFILE`, stacked statements, OS execution, or data extraction.

## Safe test approach
1. Record the normal request/response and expected behavior.
2. When a database sink is plausible, use a minimal constant/boolean comparison against a test-owned, read-only fixture. Change one relevant input only.
3. Compare true/false outcomes with the baseline. Repeat only to resolve a concrete ambiguity; do not run a broad payload matrix.
4. Treat MySQL error text, 500 responses, and response-length/timing differences as leads. Rule out validation, caching, WAF/CDN, and generic errors.
5. If no safe control distinguishes query evaluation, stop and record the hypothesis as inconclusive rather than extracting data.

## Evidence and reporting
Record request ID, input point, why MySQL is plausible, baseline/control, actual result, valid preconditions, and limitations. Use `verification_attempt` and `validate_finding`. A decisive confirmation may stop early; a false-positive/disproven verdict requires 20 distinct valid evidence-backed attempts and matching contradictory checks. Duplicates and invalid preconditions do not count. If safe testing cannot satisfy the bar, retain `INCONCLUSIVE / NEEDS REVIEW`.

Report only demonstrated impact with minimal redacted evidence; never include credentials, personal data, or database dumps.
