---
name: wstg-inpv-05.5
description: "Testing for SQL Injection - MS Access"
category: input-validation
owasp_id: WSTG-INPV-05.5
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: []
chains_with: []
prerequisites: []
severity_boost: {}
---
# WSTG-INPV-05.5 — Microsoft Access SQL Injection (Evidence-Led)

## Objective

Assess whether a captured input reaches an Access/Jet/ACE query unsafely. Database-specific error strings and syntax are clues, not proof.

## Preconditions and scope

- Confirm the exact endpoint and canonical target workspace are authorized by persisted scope before active requests.
- Use the captured request through an approved replay tool with a stable baseline and safe negative control.
- Test Access-specific behavior only when evidence suggests the Jet/ACE engine. Do not query `MSysObjects`, user tables, credentials, or files; do not use stacked statements or destructive queries.

## Safe test approach

1. Preserve the original request ID, status, response shape, and relevant error text.
2. If Access is plausible, use a minimal syntax/boolean comparison with constants only. A harmless `IIF` expression may help distinguish query evaluation when applied to a test-owned, read-only fixture.
3. Compare a normal condition with a controlled false condition while changing only one input. Do not use `UNION` to retrieve system/catalog/table data.
4. Treat a JET/ODBC error, 500 response, or changed response length as a lead. Rule out generic validation and error handling with controls.
5. Stop if the sink is not evidenced or no safe distinction remains. Do not escalate to data extraction to prove impact.

## Evidence and reporting

Record the request ID, candidate input, why Access is plausible, baseline/control, actual result, valid preconditions, and limitations. Use `verification_attempt` for each meaningful executed test and `validate_finding` for the ten-check assessment.

A decisive confirmation may stop early. A false-positive/disproven verdict requires 20 distinct valid evidence-backed attempts and matching contradictory checks. Duplicates, unexecuted ideas, and invalid scope/setup do not count. If this cannot safely be completed, keep `INCONCLUSIVE / NEEDS REVIEW`.

Report only demonstrated impact with minimal redacted evidence. Never include tokens, credentials, personal data, or extracted database records.
