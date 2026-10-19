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


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue materially distinct, authorized checks while evidence can change the conclusion; deduplicate cosmetic encodings and exact retries. Stop when direct evidence resolves the hypothesis, relevant branches are exhausted, prerequisites are unavailable, or scope/safety requires stopping. Program rules and production-safety constraints remain mandatory.

Maintain an attempt ledger: hypothesis, single changed variable, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer controlled identities, synthetic resources and paired requests. Preserve sanitized evidence and minimize data collected.

### Skill-specific hypothesis order

1. Verify the deployed Flask/Werkzeug stack and environment from reliable evidence, then baseline normal errors, redirects, cookies, and route behavior.
2. Check whether debug mode, interactive debugger, development server, verbose tracebacks, or source artifacts are reachable; use a deliberately invalid benign request and compare a random-path control.
3. Review proxy trust, host validation, secure cookie flags, session signing configuration, and route authorization only where the deployed topology makes the setting relevant.
4. Use controlled accounts to test route and object access; do not attempt debugger-console execution or forge production session secrets as a way to demonstrate impact.
5. Report verified configuration or authorization behavior, not a guessed framework version. Include the precise production-safe setting change and a regression check.


### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture and a relevant control.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause remains uncertain.
- **Unconfirmed:** response is ambiguous, cached, generic, or not linked to a security boundary.
- **Refuted / false positive:** an applicable negative control or valid policy explanation accounts for the signal. Record the attempt ledger rather than claiming every theoretical variant was exhausted.
- A 2xx status, error difference, header, schema/documentation exposure, scanner alert, or UI-only state is not proof by itself.

### Stop, cleanup, and handoff

Stop on scope ambiguity, unexpected real-user data, unexpected production state changes, service degradation, credential exposure, or a prohibited action. Restore disposable state and revoke temporary tokens/sessions where possible. Handoff target and scope proof, baseline, hypothesis, attempts used, impact, negative controls, verdict/confidence, sanitized evidence pointers, linked-skill signal, and cleanup status. Invoke a related skill only when its triggering signal is observed.

## References

- [uphiago/recon-skills — Flask/Werkzeug assessment](https://github.com/uphiago/recon-skills/blob/main/recon/flask-werkzeug-attack/SKILL.md) — merged framework-specific source.

- [uphiago/recon-skills — flask-werkzeug-attack](https://github.com/uphiago/recon-skills/tree/main/recon/flask-werkzeug-attack)
- [Flask — Debugging Application Errors](https://flask.palletsprojects.com/en/stable/debugging/)
- [Werkzeug — Debugger](https://werkzeug.palletsprojects.com/en/stable/debug/)


## Targeted quality-loop enrichment (2026-10-19)

### Debugger and deployment confirmation
Differentiate a generic Flask traceback from the interactive Werkzeug debugger and from a sanitized error page. Record whether the debug console is actually enabled, exposed, and reachable; never attempt to execute code in a live console. Confirm debug configuration through authorized source/config review or a disposable staging environment, and preserve only a redacted excerpt. Check proxy trust, environment separation, and error-handler consistency across routes. A framework fingerprint or stack trace alone should remain an informational lead unless sensitive data or an unsafe interactive console is directly demonstrated. Recommend disabling debug in production and adding a deployment regression check.


## Practical tooling, references, and helper scripts (2026-10-19)

### Tools that fit this skill
- Browser DevTools, Burp Proxy/Repeater/Comparer, and curl to replay one observed request; use only runtime-exposed integrations.
- Treat CLIs as optional until locally verified. Prefer read-only checks; state-changing tests require permission and a disposable fixture.

### Primary resources
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) — test methodology.
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — controlled labs.
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/cheatsheets/) — mitigation.
- - [Official platform documentation](https://flask.palletsprojects.com/en/stable/web-security/) — verify actual defaults.

### Small reusable helper
    python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt
Compares local artifacts offline with heuristic redaction; no requests are sent and sanitization is not guaranteed.

### Evidence and hand-off
- Keep cookies, tokens, reset links, private user data, and secret values out of notes, global research storage, and Git commits. Keep private originals local; share only reviewed derivatives.
- Mark outcomes confirmed, disproven, or still hypothetical. Record tool errors and coverage gaps rather than inventing results.

Compare baseline and control, vary one meaningful property, and record alternative explanations before confirming a lead.
