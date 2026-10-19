---
name: wstg-inpv-05.1
description: "Testing for SQL Injection - Oracle"
category: input-validation
owasp_id: WSTG-INPV-05.1
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: []
chains_with: []
prerequisites: []
severity_boost: {}
---
# WSTG-INPV-05.1 — Oracle SQL Injection (Evidence-Led)

## Objective

Assess whether an observed input reaches an Oracle SQL/PLSQL query unsafely. Oracle-specific errors and syntax can guide a hypothesis, but an error or parameter name alone is not proof.

## Preconditions and scope

- Confirm the canonical target workspace and persisted authorization scope for the exact endpoint before active requests. Stop if scope is missing, ambiguous, invalid, or denied.
- Use the captured request, an approved replay tool, a stable baseline, and a safe negative control.
- Select Oracle-specific checks only when response/source/analyzer evidence makes Oracle plausible. Do not assume Oracle from a generic 500.
- Never query `v$version`, system catalogs, user tables, credentials, files, or network services. Do not use `UTL_HTTP`, stacked queries, file-write, command execution, or data extraction.

## Safe test approach

1. Capture the normal response, request ID, content type, status, and relevant body shape.
2. If an Oracle sink is plausible, use one minimal syntax/boolean comparison against a test-owned fixture, such as a harmless constant expression involving `DUAL`. Keep the application operation read-only and the result bounded.
3. Compare the normal condition and a controlled false condition while changing only one input. Repeat only when it resolves a concrete ambiguity; do not run a broad payload matrix.
4. Treat Oracle error text, status changes, timing, or response-length differences as leads. Rule out validation, WAF/CDN, caching, and generic exception behavior.
5. If a safe distinguishing control is unavailable, record the hypothesis as inconclusive rather than extracting data to prove it.

## Evidence and reporting

Record the exact request ID, selected input point, Oracle-specific evidence, baseline/control, actual result, valid preconditions, and limitations. Use `verification_attempt` for each meaningful executed test and `validate_finding` for the ten-check assessment.

A decisive confirmation may stop early. A false-positive/disproven verdict requires resolved checks, multiple evidence-backed contradictions including a primary contradiction, matching valid attempt outcomes, and a durable evidence-backed DISPROVEN ledger outcome for the exact finding; no fixed attempt count applies. Duplicates, unexecuted ideas, and invalid scope/setup do not count. If this cannot safely be completed, keep `INCONCLUSIVE / NEEDS REVIEW`.

Report only demonstrated impact and minimal redacted evidence. Never include tokens, credentials, personal data, or extracted database records.
