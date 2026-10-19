---
name: recon-error-log-mining
description: "Discover exposed application error logs and evaluate disclosure of internal paths, stack traces, queries, and secret-like material with minimal evidence."
category: "recon"
version: "1.0.0"
author: "cyberstrike-official"
tags: [information-disclosure, error-logs, debug, secrets-hygiene, PHP]
tech_stack: [HTTP, PHP, WordPress, Linux]
cwe_ids: [CWE-200, CWE-532]
chains_with: [attack-information-disclosure, attack-source-leak, attack-phpinfo-exposure, recon-methodology]
prerequisites:
  - "A confirmed in-scope web application"
severity_boost:
  high: "An exposed log contains a demonstrably active secret or sensitive user data with material impact, verified without using the secret."
---

# Exposed Error-Log Analysis

## Objective

Find publicly retrievable error/debug logs and determine whether they disclose meaningful internal information. Prioritize classification and minimal proof over bulk downloading or harvesting sensitive records.

## Testing Methodology

### 1. Discover likely log locations

Use passive source references, robots/sitemap entries, repository paths, framework conventions, and a small set of likely public paths. Common patterns include error_log, debug.log, framework log directories, and CMS debug outputs. Treat a 200 response only as a candidate.

### 2. Confirm the response is a real log

Compare a small bounded byte range with a random nonexistent path. Check for repeated timestamps, recognizable error prefixes, stack-trace structure, log-level labels, and consistent content-type behavior. Exclude SPA fallback pages, generic error templates, and CDN cache artifacts.

### 3. Bound collection

Use HEAD or range requests when supported, impose strict byte/time limits, and avoid downloading large files. Preserve a short sanitized excerpt sufficient to establish the issue. Do not bulk-ingest or index customer records, credentials, or personal data.

### 4. Classify disclosed material

Classify findings into internal filesystem paths and deployment layout; stack traces, framework versions, and component names; SQL statements or schema names; internal hostnames/IPs; email addresses and user identifiers; secret-like strings, tokens, cookies, database connection strings, or signing material; and user-submitted data accidentally logged.

Treat pattern matches as candidates only. Never test a discovered credential against a service; confirm validity through an owner-provided verification channel or metadata that does not expose or use the secret.

### 5. Determine reachability and impact

Establish whether unauthenticated users can retrieve the log, whether it is current, and whether the content reveals a meaningful attack path. A path or version disclosure may be informational; a live secret or sensitive record can raise severity, but must be handled with minimal evidence and immediate redaction.

### 6. Identify root cause

Check production debug settings, web-server deny rules, deployment packaging, log rotation and permissions, public static-file mappings, backup/sync jobs, and CMS plugin/theme behavior. Recommend removing logs from web roots and preventing future writes to publicly served locations.

## What Constitutes a Finding

- A real log is retrievable by an unauthorized user and contains non-public information.
- Impact is based on the exact disclosed content and its sensitivity, not the file name or byte size.
- A valid secret should not be copied into a report; identify the secret type, location, and minimal redacted fingerprint instead.
- A generic error page, empty log, public sample log, or stale benign stack trace may not justify a security finding.

## Evidence Requirements

- URL, retrieval timestamp, response status/content type, and bounded byte range.
- Sanitized excerpt showing log structure and one representative disclosure.
- Random-path/soft-404 control.
- Secret values, personal data, cookies, tokens, and customer content must be redacted.
- Note whether the file is current and whether sensitive material was validated without using it.

## Tools

- curl with timeouts, byte ranges, and output-size limits.
- file, grep, and Python parsers for log-format classification.
- Burp Suite for request/response evidence and cache comparison.
- Secret scanners in local-only mode on sanitized excerpts; do not upload target logs to third-party scanning services.

## Log Disclosure Matrix

| Data class | Example signal | Potential impact | Safe proof |
|---|---|---|---|
| Internal paths | Absolute application/deployment paths | Supports targeted follow-on analysis | One sanitized path |
| Stack traces | Framework call stack and source line | Reveals code paths and versions | Short redacted stack excerpt |
| SQL details | Query template/table names | Schema disclosure or query behavior insight | Redacted query fragment |
| Internal network metadata | Private hostnames/IPs | Architecture disclosure | One address with context |
| Secret-like values | Token/password/API-key pattern | Potential unauthorized access | Type, location, redacted fingerprint only |
| Personal/customer data | Emails, IDs, request bodies | Privacy/confidentiality exposure | Minimal redacted sample |
| Debug configuration | Verbose errors, environment values | Increases information leakage | Exact setting/output with secrets removed |

## Verification and False Positives

- Compare the candidate to a random path on the same host.
- Confirm the body is a log, not a cached page or generic SPA shell.
- Check timestamps and repetition before claiming current exposure.
- Pattern-matched tokens can be placeholders, expired, or synthetic; do not assert validity without safe corroboration.
- Do not download whole multi-gigabyte logs or validate credentials by attempting login.
- If evidence contains secrets, stop collection, redact immediately, and follow the engagement's sensitive-data handling process.


## Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. there is no fixed hypothesis-count ceiling; continue distinct, decision-relevant hypotheses while authorized, and stop when evidence or a real safety/policy boundary resolves the branch. Prefer passive sources first, deduplicate candidates, and use active checks only when the asset and activity are explicitly in scope.

### Evidence record and confidence

For each candidate, preserve normalized asset, source/provenance, observation time, scope proof, resolver/HTTP/tool and relevant version, raw-evidence location, corroborating source, negative control, attribution confidence, next action, and related-skill trigger. Separate **asset confidence** (is it related to the organization?) from **security confidence** (is a vulnerability demonstrated?).

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. C1/C2 are not confirmed vulnerabilities.

### Skill-specific next steps

1. Confirm the candidate log/debug artifact is publicly reachable and in scope; request a random-path or equivalent inaccessible-resource control to detect generic error pages.
2. Identify log type, time range, and application ownership from minimal metadata first. Distinguish harmless stack traces from live session material, credentials, personal data, or internal-only request details.
3. Collect only a few sanitized lines necessary to prove exposure. Do not download full logs, test credentials found in logs, or follow tokens into other services.
4. Check whether output is cached, generated per request, intentionally public, or requires an authenticated role; verify the access boundary using your own test session if applicable.
5. Report exact URL/role, sensitive categories, minimal redacted proof, and remediation for access control, secret rotation, log redaction, and cache invalidation.


### Deduplication and stop rules

Normalize case, trailing dots, scheme/port, redirects, canonical names and resolved addresses before deduplication. Detect wildcard DNS, shared hosting, CDN/edge responses, soft-404s and stale records before ranking counts. Stop on exclusions, ownership ambiguity, unexpected sensitive data, throttling, instability or boundaries requiring further permission. Never claim ownership or register dangling resources.

### Handoff format

Return candidates with scope/provenance, confidence level, evidence path, deduplication key, negative control, priority rationale, safe next step and trigger for any linked attack skill. Promote a candidate to active testing only after scope and attribution are confirmed; promote it to a finding only after the relevant attack skill verifies the security boundary.

## References

- Source merged: [uphiago/recon-skills — recon/error-log-mining/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/error-log-mining/SKILL.md)
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)


## Targeted quality-loop enrichment (2026-10-19)

### Log validation without collecting secrets
First confirm the response is a real log artifact rather than a generic debug page or synthetic sample. Inspect a small, bounded excerpt and immediately redact access tokens, session IDs, email addresses, internal URLs, query data, and personal information. Record file/source, exposure path, timestamp, response access policy, and the minimum sensitive marker needed to establish the boundary. Do not recursively crawl or download all logs. Separate a stack trace from a log containing secrets or customer records; a discovered secret must not be tested or used. Route source/build paths to source-leak, metrics data to metrics exposure, and detailed exception disclosure to triage with a specific demonstrated impact statement.
