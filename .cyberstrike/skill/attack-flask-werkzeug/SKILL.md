---
name: attack-flask-werkzeug
description: "Assess Flask/Werkzeug debug-page exposure, traceback disclosure, and configuration risk without invoking the interactive console on production."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - flask
  - werkzeug
  - debugger
  - python
  - traceback
  - information-disclosure
tech_stack:
  - python
  - flask
  - werkzeug
  - web
  - wsgi
cwe_ids:
  - CWE-215
  - CWE-489
  - CWE-209
chains_with:
  - attack-rce
  - attack-information-disclosure
  - attack-cors
prerequisites: []
severity_boost:
  attack-rce: "Werkzeug debug-console exposure can imply code execution only if interactive evaluation is enabled and separately validated in an authorized lab."
---

# Flask and Werkzeug Debugger Exposure

## Objective

Identify production debug-mode pages, traceback/source disclosure, and insecure console configuration. Use non-destructive endpoints and source/config review; never submit commands or attempt console execution on a live target.

## Testing Methodology

### Phase 1: Confirm Flask/Werkzeug safely

Review headers, error templates, known app routes, and public assets. Trigger a predictable harmless error only if the test rules allow it, and no more than needed. A generic HTTP 500 is not proof of Werkzeug.

### Phase 2: Capture minimal traceback evidence

If the debugger page appears, capture only framework identification, relevant sanitized path/line context, and exposed configuration indicators. Avoid collecting entire environment, secrets, source files, or session information.

### Phase 3: Assess debugger state from configuration

Review source/deployment settings for debug=True, environment variables, and console/eval configuration. A debugger page may disclose stack traces while the interactive console is disabled; treat those as separate impact levels.

### Phase 4: Check route and origin behavior

Verify whether error responses are authenticated, cacheable, or subject to broad CORS. Inspect headers and browser behavior; do not construct a cross-origin page to collect a debugger secret or send diagnostic data externally.

### Phase 5: Validate in isolated test environment

If console code execution needs confirmation, reproduce the same Flask/Werkzeug version and settings in a local container with no secrets/network access. Use a harmless fixed marker only in that lab and confirm whether eval is enabled.

### Phase 6: Recommend and verify remediation

Disable debug mode in production, use a production WSGI server, avoid detailed errors, protect debug endpoints, and verify that a controlled malformed request returns a generic response after remediation.

## What Constitutes a Finding

- **Candidate / lead:** a 500 response includes Flask/Werkzeug markers, frame stack, source snippet, or console state.
- **Confirmed information disclosure:** an unauthenticated in-scope request exposes non-public internal paths/source/configuration that exceeds intended error detail.
- **Confirmed RCE:** only if a controlled isolated/explicitly authorized test demonstrates that the interactive console executes server-side code; do not prove this against production by sending commands.
- **Not a finding:** ordinary 500 JSON error, public framework banner, or debugger endpoint name without unsafe enabled behavior.

## Evidence Requirements

- Exact scoped path, timestamp, status, content type, and sanitized screenshot/body.
- Minimal traceback snippet and whether source paths or secrets were actually disclosed; never include secret values.
- Relevant config evidence for debug/eval state and tested version.
- Note whether code-execution behavior was lab-only or not tested.

## Tools

- **Browser DevTools / curl:** capture error-page behavior and headers.
- **Source/config review:** locate Flask debug settings and WSGI deployment mode.
- **Containerized lab:** reproduce the same version/settings without production secrets or network egress.
- **HTML parser:** distinguish debugger templates from generic error pages.

## Werkzeug Debug Exposure Matrix

| Signal | Potential impact | Confirmation |
|---|---|---|
| Generic 500 | Usually error handling only | No finding without sensitive detail or unsafe behavior |
| Full traceback/path | Internal path and architecture disclosure | Capture minimal non-public path/source evidence |
| Source context | Application code disclosure | Demonstrate non-public source exposure without bulk copying |
| Debugger secret string | Internal debugger metadata | Does not prove interactive code execution by itself |
| Console disabled | Debug error-page disclosure may remain | Confirm eval is disabled using config/lab only |
| Console/eval enabled | High-risk execution surface | Lab/authorized harness demonstrates execution; never invoke on production |
| Broad CORS on error | May expose error details cross-origin | Browser proof with synthetic/non-sensitive marker; no exfiltration |

**Mitigation:** disable debug mode in production, serve through a production WSGI server, keep debugger out of public routes, suppress stack details, and add a generic-error regression test.

## Verification and False Positives

- Many frameworks produce traceback-like JSON without exposing source or a console.
- The Werkzeug secret alone is not enough to prove RCE; console/eval and trust conditions matter.
- A console returning 400/404 is ambiguous; do not try command payloads against production.
- CORS headers on an error page do not automatically make its contents sensitive.
- Stop before accessing local files, reading environment variables, executing code, or exfiltrating debugger output.

## References

- [uphiago/recon-skills — Flask/Werkzeug assessment](https://github.com/uphiago/recon-skills/blob/main/recon/flask-werkzeug-attack/SKILL.md) — merged framework-specific source.

- [uphiago/recon-skills — flask-werkzeug-attack](https://github.com/uphiago/recon-skills/tree/main/recon/flask-werkzeug-attack)
- [Flask — Debugging Application Errors](https://flask.palletsprojects.com/en/stable/debugging/)
- [Werkzeug — Debugger](https://werkzeug.palletsprojects.com/en/stable/debug/)
