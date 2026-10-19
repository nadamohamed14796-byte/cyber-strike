---
name: attack-information-disclosure
description: "Assess unintended disclosure of sensitive application, infrastructure, diagnostic, and account data with minimal evidence and a clear confidentiality boundary."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - information-disclosure
  - sensitive-data
  - errors
  - metadata
  - privacy
tech_stack:
  - web
  - rest-api
  - graphql
  - cloud
  - linux
cwe_ids:
  - CWE-200
  - CWE-209
  - CWE-497
chains_with:
  - attack-source-leak
  - attack-phpinfo-exposure
  - attack-flask-werkzeug
  - attack-exchange-owa
  - attack-zimbra
prerequisites: []
severity_boost:
  attack-source-leak: "Source/configuration exposure is a distinct information-disclosure class when non-public code or secrets are actually readable."
---

# Information Disclosure Assessment

## Objective

Determine whether an in-scope endpoint, response, file, or diagnostic surface exposes information that should not be available to the requesting identity. Distinguish public metadata from sensitive content, and retain the smallest sanitized evidence necessary.

## Testing Methodology

### Phase 1: Define the expected confidentiality boundary

Confirm the route, asset, user role, and program policy. Identify what is intentionally public, authenticated-only, tenant-bound, admin-only, or secret. Record normal anonymous and authorized responses before exploring candidate leaks.

### Phase 2: Inventory likely disclosure surfaces

Review verbose errors, stack traces, API response fields, debug pages, headers, source maps, metadata endpoints, public archives, log/backup candidates, and cloud/object storage paths justified by observed evidence. Use a small allowlisted path set; don't mass-download files or enumerate user records.

### Phase 3: Use negative controls and verify content

Compare candidate responses to a random nonexistent path and a known public route. Check content signatures, response bodies, MIME types, and whether a gateway/SPA returns the same page for everything. A 200 status, server banner, or route existence alone is not confirmation.

### Phase 4: Assess sensitivity and access requirements

Classify the exposed field or artifact: public identifier, internal path, personal data, secret, private document, customer record, or operational metadata. Confirm whether it is truly non-public and available to an unintended role. Do not access further records just to estimate the population.

### Phase 5: Capture minimum proof

Use a synthetic/test record or a short sanitized snippet that establishes the data class and access boundary. For secrets, capture the key name/type and only a non-reusable truncation if necessary; do not test, replay, or print full credentials.

### Phase 6: Trace the source and recommend a scoped fix

Where source/config is available, identify which serializer, error handler, storage policy, logging route, or authorization guard exposed the detail. Recommend the narrowest remediation and a regression test for anonymous/low-role requests.

## What Constitutes a Finding

- **Candidate / lead:** unusual metadata, verbose error, unexpected response field, accessible file, or scanner-reported disclosure.
- **Confirmed finding:** non-public information is reproducibly returned to an unauthorized in-scope identity and its sensitivity/policy boundary is established.
- **Impact-qualified:** the specific exposed data type and consequence are demonstrated without unnecessary collection.
- **Not a finding alone:** generic server banner, public API schema, harmless path/version hint, public data, or a 200 response without sensitive content.

## Evidence Requirements

- Exact scoped route/file, method, timestamp, requesting role, and baseline/negative control.
- Sanitized response excerpt showing the field or content class, with secrets and personal data redacted.
- Expected access policy and observed authorization behavior.
- Root-cause pointer (serializer, exception handler, storage rule, or route guard) where available.
- Never attach complete logs, backups, databases, private keys, session tokens, or unnecessary customer data.

## Tools

- **Burp Suite / curl:** compare anonymous and authenticated responses.
- **jq / JSON parser:** inspect schema and redact sensitive values.
- **File signature utilities:** distinguish genuine archives/config files from catch-all responses.
- **Source review / vendor docs:** determine whether the disclosed field is intended and how to remove it safely.

## Disclosure Classification Matrix

| Data class | Typical sensitivity | Evidence bar |
|---|---|---|
| Public version/banner | Low; often intentional | Usually informational unless it enables a verified vulnerable configuration |
| Internal paths/stack traces | Context-dependent | Show a non-public detail with practical security significance |
| User/account PII | High depending on fields/policy | Prove access boundary with test accounts; redact values |
| Logs/backups/source/config | Potentially high | Confirm genuine artifact and only the minimum sensitive marker |
| Secrets/API keys | High | Show secret type/location, redact value, do not test it |
| Tenant/private documents | High | Use synthetic/test-owned records; do not enumerate real users |
| Cloud/storage metadata | Context-dependent | Establish unintended access and identify whether data is meant to be public |

**Mitigation:** minimize response fields, enforce authorization at the data layer, disable verbose production errors, protect logs/backups/source maps, remove diagnostic routes, and add negative authorization regression tests.

## Verification and False Positives

- SPA catch-all routes, CDN error pages, and WAF responses can mimic file exposure; compare content with a negative control.
- A field can be public by design; establish data sensitivity and the intended audience.
- A scanner signature, version hint, or stack trace fragment does not imply code execution.
- Don't infer mass exposure from one record and don't request more records to prove scale.
- Stop immediately if real secrets or unrelated personal data appear; minimize evidence and follow the program's disclosure process.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue materially distinct, authorized checks while evidence can change the conclusion; deduplicate cosmetic variants and exact retries. Stop when direct evidence resolves the hypothesis, meaningful branches are exhausted, prerequisites are unavailable, or scope/safety requires stopping. Program rate limits and production-safety constraints remain mandatory.

Track each attempt as: hypothesis, one changed variable, baseline/control, observed signal, interpretation, confidence, and next branch. Use controlled identities or synthetic resources, preserve only minimal evidence, and redact secrets.

### Skill-specific hypothesis order

1. Capture the candidate response and a random nonexistent-path/control response from the same host, session, and cache context; normalize dynamic IDs, timestamps, and request IDs before comparing.
2. Check the exact exposed artifact class (stack trace, source map, config, metadata, backup, debug endpoint, or response field) and whether the content includes data that should be private.
3. Establish whether the artifact is public by design, generated sample data, a soft-404, or shared-cache content before escalating its significance.
4. Read only the minimum benign evidence needed to establish sensitivity; never bulk-download files, follow exposed secrets into other services, or retain credentials in logs.
5. Report the precise sensitive field/artifact, unauthenticated or over-privileged access path, control response, and remediation; redact secrets and use a safe regression test.


### Verdict gates

- **Confirmed:** repeatable security impact is shown against an in-scope resource using a tester-controlled identity or fixture, with a meaningful control.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause is not yet established.
- **Unconfirmed:** observations are ambiguous, cached, generic, or not tied to a security boundary.
- **Refuted / false positive:** a relevant negative control or valid policy/implementation explanation accounts for the observation; document the attempts instead of claiming all imaginable variants were exhausted.
- Do not treat status codes, error text, response length, decoded tokens, static findings, or UI state alone as proof.

### Stop, cleanup, and handoff

Stop at scope uncertainty, unrelated sensitive data, unexpected production changes, service degradation, secret exposure, or prohibited actions. Restore disposable state and revoke test tokens/sessions where possible. Return the scope proof, baseline, hypothesis, attempt count, impact, controls, confidence/verdict, sanitized evidence pointers, relevant handoff signal and cleanup status. Chain into another skill only when its trigger is present.

## References

- [uphiago/recon-skills — redteam/hunt-information-disclosure](https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-information-disclosure/SKILL.md) — Information disclosure source.

- [OWASP — Information Exposure Through Error Messages](https://owasp.org/www-community/Improper_Error_Handling)
- [OWASP — Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- [CWE-200 — Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)


## Targeted quality-loop enrichment (2026-10-19)

### Confidentiality proof and data minimization
Classify the candidate bytes before expanding: public documentation, synthetic fixture, ordinary metadata, personal/sensitive data, credential material, or control-plane information. Verify that the response is not already intentionally public through the product UI or documentation and use a relevant anonymous/low-role control. Preserve only a small redacted excerpt or marker proving the boundary; do not dump directories, entire logs, customer records, or secret values. A filename, stack trace, or secret-looking pattern is not impact by itself. Route source maps and repository artifacts to source-leak review, metrics endpoints to metrics exposure, and property-level over-disclosure to API property authorization.


## Practical tooling, references, and helper scripts (2026-10-19)

### Tools that fit this skill
- Browser DevTools, Burp Proxy/Repeater/Comparer, and curl to replay one observed request; use only runtime-exposed integrations.
- Treat CLIs as optional until locally verified. Prefer read-only checks; state-changing tests require permission and a disposable fixture.

### Primary resources
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) — test methodology.
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — controlled labs.
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/cheatsheets/) — mitigation.

### Small reusable helper
    python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt
Compares local artifacts offline with heuristic redaction; no requests are sent and sanitization is not guaranteed.

### Evidence and hand-off
- Keep cookies, tokens, reset links, private user data, and secret values out of notes, global research storage, and Git commits. Keep private originals local; share only reviewed derivatives.
- Mark outcomes confirmed, disproven, or still hypothetical. Record tool errors and coverage gaps rather than inventing results.

Compare baseline and control, vary one meaningful property, and record alternative explanations before confirming a lead.
