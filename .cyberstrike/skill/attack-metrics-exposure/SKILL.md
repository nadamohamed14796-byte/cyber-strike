---
name: attack-metrics-exposure
description: "Assess exposed metrics, health, debug, tracing, and observability endpoints for sensitive metadata and authorization failures."
category: "infrastructure-security"
version: "1.0.0"
author: "CyberStrike contributors"
tags: [metrics, prometheus, observability, debug, information-disclosure, cloud]
tech_stack: [http, prometheus, openmetrics, otel, kubernetes, cloud]
chains_with: [attack-information-disclosure, cloud-assessment, k8s-assessment, attack-api-noauth-hunt, attack-triage-validation]
sources:
  - "https://prometheus.io/docs/operating/security/"
  - "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html"
  - "https://owasp.org/www-project-api-security/"
---

# Metrics and Observability Exposure Assessment

## Objective
Determine whether metrics, health, debug, tracing, profiling, or diagnostic endpoints reveal sensitive internal topology, tenant identifiers, software state, operational secrets, or privileged controls to an unauthorized principal.

## Discovery
Look for observed routes such as /metrics, /actuator/prometheus, /health, /readyz, /debug, /pprof, /trace, and vendor-specific telemetry paths. Treat names as discovery hints, not proof of exposure. Respect the program's scan policy and avoid broad path brute force.

## Validation procedure
1. Capture an unauthenticated baseline for an in-scope endpoint and classify response type, authentication state, and content without dumping sensitive values.
2. Determine whether the route is meant to be public, internal-only, network-restricted, or authenticated. Use configuration or owner-provided documentation where available.
3. Inspect metadata categories: hostnames, service names, environment labels, cloud resource IDs, tenant/user labels, internal URLs, deployment versions, queue names, and high-cardinality labels that could contain user data.
4. Treat token-like values as secrets: record a redacted fingerprint and location, never copy or use the value.
5. Assess whether diagnostics enable privileged state changes or expensive profiling. Do not trigger CPU/heap dumps, unbounded traces, or high-load queries against production.
6. Compare the same endpoint across public and authorized admin contexts; verify whether internal labels are intended to be visible and whether sensitive values are actually present.
7. Confirm that the exposure creates a concrete security consequence, such as leaking internal service topology that supports a demonstrated trust-boundary issue or exposing credentials. Do not extrapolate impact from labels alone.

## Low-impact capture
```bash
curl -sS -D metrics.headers -o metrics.body "$IN_SCOPE_METRICS_URL"
# Review locally and redact label values before persistence or sharing.
head -n 40 metrics.body
```
Only use against an explicitly authorized endpoint. Do not save unredacted bodies in Git or a shared report.

## Chaining and remediation
Metrics exposure may amplify a separately confirmed SSRF/cloud/IAM finding by revealing a reachable internal service, but the follow-up must be separately authorized. Chain to cloud or Kubernetes assessment only when ownership and scope are verified, to information-disclosure triage for exposed sensitive fields, and to API-no-auth testing when an API route is unexpectedly public. Recommend authentication, network access controls, minimized labels, secret-free telemetry, and explicit endpoint exposure policy.

## False positives
- The endpoint is deliberately public and contains only approved aggregate metrics.
- Labels are synthetic or low sensitivity.
- A version string is not linked to an affected reachable vulnerability.
- A health response reveals only availability, with no restricted detail.
- A secret detector matches a non-secret label or sample value.

## Output
Record route, exposure context, access control, metadata classes, redacted examples, data sensitivity, demonstrated impact, confidence, cleanup, and specific remediation.


## Targeted quality-loop enrichment (2026-10-19)

### Metric sensitivity and cardinality control
Capture only a small sample of the metrics endpoint and redact label values before persistence; labels may contain tenant IDs, emails, routes, tokens, or other high-cardinality data. Determine whether the endpoint is intentionally public, restricted to internal networks, or accidentally exposed by reverse proxy configuration. Compare anonymous versus authorized access and confirm whether the content discloses sensitive operational topology or customer identifiers, rather than reporting a generic metrics path. Avoid scraping all time series or inducing load. Chain to information disclosure for proven sensitive labels, or cloud/configuration review when access policy is the root cause.


## Evidence normalization

Keep a small redacted sample and record the endpoint, expected audience, principal, label names, data classes, access decision, and time of observation. Avoid retaining entire metric dumps. A label name may indicate a possible privacy issue, but report only when the value or access boundary is actually sensitive and the endpoint is exposed contrary to policy.

Separate metrics, health/readiness, tracing, profiling, debug output, and administrative controls because they have different risk and operational impact. Review configuration and read-only evidence first; do not trigger heavy profiles or diagnostic dumps on a live service. Any follow-up must use an approved synthetic fixture and the minimum proof necessary.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Use curl/browser DevTools for a single authorized request, jq for local JSON, Burp for authentication-context comparison, and Prometheus `promtool` when Prometheus configuration/rules are part of the authorized assessment.

### Installation and setup
Kali/Debian: `sudo apt update && sudo apt install curl jq`. Get Prometheus/`promtool` only from https://prometheus.io/download/ and follow the official version-specific setup. Avoid scraping or bulk-downloading production metrics unless the program explicitly permits it. Tool installation does not authorize a test.

### Primary resources
- [Prometheus documentation](https://prometheus.io/docs/) — metrics formats and access patterns.
- [OWASP Information Exposure Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Information_Exposure_Cheat_Sheet.html) — impact context.
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) — disclosure verification.

### Reusable helper
`python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt` compares sanitized responses already saved locally; it sends no request.

### Result handling
Record the metric names and exposure context without copying secrets or personal data; distinguish public operational metadata from genuinely sensitive data.

## Agent-executable CLI tooling, resources, and helper scripts

Use agent-executable CLI tools and local scripts; browser interfaces, extensions, and interactive intercepting proxies are not dependencies. Check tool presence/version and official documentation before running it; only process data the operator is authorized to inspect.

### Recommended tools
- curl — single read-only metadata request
- jq — parse metrics exposition/JSON
- rg — locate high-signal metric names in saved output
- Python — redact labels and summarize cardinality locally

### Resources
- https://prometheus.io/docs/prometheus/latest/querying/api/
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids; verify project maintenance, license, and supported behavior from official sources.

### Helper-script contract
Capture only minimal sanitized metrics metadata. Check whether sensitive labels, environment names, or internal topology are exposed without enumerating large metric sets or collecting customer-specific labels.

Keep raw artifacts separate from normalized output. Preserve provenance, timestamp, tool/version, detector/rule, error state, confidence, redaction, and evidence path. Use JSON/JSONL when useful and test redaction on local fixtures.

### Handoff
Return actual commands and versions, inputs/outputs, records processed, redaction status, errors, confidence, limitations, and next skill. Never include live secrets in notes or reports.
