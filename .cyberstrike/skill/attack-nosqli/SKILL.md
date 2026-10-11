---
name: attack-nosqli
description: "Assess NoSQL query injection with bounded, schema-aware validation"
category: "web-application"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [nosqli, mongodb, query-injection, api]
tech_stack: [mongodb, json, http, api]
prerequisites:
  - "Authorized endpoint and test account"
  - "A harmless test record and bounded request plan"
chains_with: [attack-sqli, attack-api-misconfig, attack-graphql, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-nosqli/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
---

# NoSQL Injection Assessment

## When to use

Use when JSON or query parameters may be interpreted as database operators, filters, aggregation expressions, or query fragments rather than plain values.

## Safety gate

Use a test account and synthetic records. Do not attempt to dump collections, bypass authentication against real accounts, alter production data, or issue expensive aggregation queries.

## Procedure

1. Capture a baseline request and identify which fields are expected to be scalar values.
2. Determine how the application serializes user input into the query; review client/server code when available.
3. Test one field at a time with harmless type changes and invalid operator-shaped values, within the endpoint's documented schema.
4. Compare validation errors and result semantics. A parser error alone does not prove injection.
5. Where permitted, use a synthetic record to check whether a user-controlled condition changes the intended filter or authorization predicate.
6. Confirm whether the query can return records outside the intended criteria using only test data.
7. Avoid timing-heavy or resource-intensive queries. Stop if the endpoint becomes unstable.
8. Recommend parameterized query construction, strict schemas, operator allowlists, and server-side authorization independent of query filters.

## Pitfalls

- JSON objects may be valid input for a documented filter API.
- A response containing more fields can be due to serialization differences.
- Authentication bypass requires a demonstrated security boundary failure.
- Do not test destructive update/delete operators on live data.

## Verification

Record the field, expected schema, minimal input difference, baseline and altered results, test-data boundary, and impact. Use `attack-sqli` for SQL-based backends.
