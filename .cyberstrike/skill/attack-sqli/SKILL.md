---
name: attack-sqli
description: "Assess suspected SQL injection with minimal non-destructive probes and evidence-based validation"
category: "web-application"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [sqli, database, input-validation, blind-injection]
tech_stack: [http, sql, web, api]
prerequisites:
  - "Authorized endpoint and permission for injection testing"
  - "A low-impact test plan and a clear stop condition"
chains_with: [attack-web-enumeration, attack-triage-validation, attack-evidence-hygiene, attack-report-writing]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-sqli/SKILL.md"
---

# SQL Injection (SQLi)

## When to use

Use when user-controlled input appears to affect a database-backed query, filter, sort expression, search function, report, or API resolver. Route document-database operator testing to a dedicated NoSQL skill when available.

## Preconditions and safety

Confirm that injection testing is allowed. Prefer a staging environment or disposable records. Do not dump tables, extract credentials, alter records, use destructive statements, or run expensive time-delay payloads against production. Keep request volume low and stop if the service degrades.

## Procedure

1. **Map the input.** Record endpoint, method, content type, parameter, auth role, and expected data type.
2. **Capture a baseline.** Save a minimal request and normal response, including response time and relevant response fields.
3. **Use harmless syntax probes.** Compare normal input with a minimally altered quote or type boundary. Observe database-specific errors, consistent response changes, or safe boolean differences without requesting sensitive rows.
4. **Separate application errors from database behavior.** Check whether validation, caching, WAF responses, or generic exception handling could explain the result.
5. **Choose the least invasive confirmation.** Prefer a controlled boolean condition or a lab/staging reproduction. Avoid data extraction, write operations, stacked statements, and long delays on live targets.
6. **Repeat once under comparable conditions.** Control for network jitter, warm caches, and rate limiting. Do not interpret a single latency spike as proof.
7. **Identify the query context.** Distinguish SQL syntax, ORM raw-fragment use, stored/second-order behavior, and a separate NoSQL operator issue.
8. **Capture minimum evidence.** Include baseline and altered request, response comparison, timing conditions if relevant, and why the result demonstrates query influence.
9. **Stop after sufficient proof.** Do not extract data to prove a root cause when a safe differential already establishes it.

## Verification

A finding requires reproducible evidence that input changes query semantics or exposes a database-specific behavior beyond ordinary validation errors. A quote causing HTTP 500 alone is not sufficient. State the exact demonstrated capability and avoid claiming data access or code execution unless separately and safely proven.

## Pitfalls

- Treating any server error as SQLi.
- Using expensive blind timing loops on production.
- Confusing SQL injection with NoSQL operator injection or application-level filtering.
- Relying on one noisy timing measurement.
- Escalating to database dumps or state-changing payloads unnecessarily.

## Remediation guidance

Use parameterized queries, safe ORM APIs, allowlists for identifiers and sort fields, least-privilege database accounts, and generic client-facing errors with protected server-side logging.

## CyberStrike integration contract

Verify the real request runner, rate limiter, finding schema, and tool registry before automation. The skill must not perform bulk extraction or destructive queries.

## Attribution

Adapted from Claude-BugHunter hunt-sqli: https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-sqli/SKILL.md
