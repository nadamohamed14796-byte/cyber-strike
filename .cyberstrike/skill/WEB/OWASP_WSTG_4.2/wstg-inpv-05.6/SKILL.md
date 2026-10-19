---
name: wstg-inpv-05.6
description: "Testing for NoSQL Injection"
category: input-validation
owasp_id: WSTG-INPV-05.6
version: "1.0.0"
author: cyberstrike-official
tags: [injection, input-validation, xss, sqli, wstg, inpv]
tech_stack: []
cwe_ids: []
chains_with: []
prerequisites: []
severity_boost: {}
---
# WSTG-INPV-05.6 — NoSQL Injection (Evidence-Led)

## Objective
Determine whether caller-controlled JSON/query values alter a NoSQL query or filter unexpectedly. Operator-shaped JSON and authentication endpoints are clues, not proof.

## Scope and safety
- Confirm persisted scope for the exact endpoint and canonical target workspace before active requests.
- Use captured requests, approved replay tools, a stable baseline, and test-owned records/accounts.
- Never use JavaScript execution operators such as `$where`, enumerate accounts, extract documents/secrets, or run destructive database commands. Do not spray operator payloads at real login endpoints.
- If an auth-bypass hypothesis cannot be tested using a test-owned account or isolated fixture, stop and ask for a safe test setup.

## Safe test approach
1. Identify a plausible NoSQL sink from source/analyzer evidence, query semantics, or a discriminating parser response. JSON input alone is not enough.
2. Establish normal behavior using a known test-owned record and a known-no-match control.
3. Where the sink is plausible, change one harmless filter/field type at a time and compare with the baseline. Prefer read-only search/filter endpoints and bounded responses.
4. For authentication behavior, use only a test-owned account and one controlled comparison with known test credentials. Do not enumerate usernames or attempt broad operator-based login bypass.
5. Treat a changed result count, generic 500, or accepted object as a lead. Confirm that query semantics changed and that access policy was violated; rule out validation, caching, and expected filter behavior.

## Evidence and reporting
Record request ID, candidate input, evidence for the NoSQL sink, baseline/control, actual result, valid preconditions, and limitations. Use `verification_attempt` and `validate_finding`. A decisive confirmation may stop early; A false-positive/disproven verdict requires resolved checks, multiple evidence-backed contradictions including a primary contradiction, matching valid attempt outcomes, and a durable evidence-backed DISPROVEN ledger outcome for the exact finding; no fixed attempt count applies. Duplicates and invalid preconditions do not count.

Report only demonstrated impact with minimal redacted evidence. Never include tokens, credentials, personal data, or extracted documents.
