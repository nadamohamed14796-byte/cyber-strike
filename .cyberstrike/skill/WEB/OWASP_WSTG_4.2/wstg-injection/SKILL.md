---
name: wstg-injection
description: Evidence-led input validation and injection testing for authorized web applications
tags: [injection, sqli, xss, ssti, xxe, command-injection, ldap, wstg]
version: "1.1"
---

# Evidence-Led Input Validation and Injection Testing

## Non-negotiable operating contract

This is a methodology reference, not a requirement to test every input or every class.

1. Confirm the canonical target workspace and persisted authorization scope. Reuse the run's existing scope decision for this unchanged target origin; if no decision exists yet, call `scope_check` once with the exact URL and canonical `target_url` before active testing. Do not repeat it for every endpoint or payload. Active request tools still enforce persisted scope for each exact URL. If scope is missing, ambiguous, invalid, or denied, stop active testing.
2. Use the captured request and response, analyzer findings, source evidence, and prior observations to form one specific hypothesis. A parameter, free-text field, header, JSON body, or reflected value alone is not proof of an injection sink.
3. Choose only the relevant class and input location. Use `inject_probe` only for those selected classes, then confirm a meaningful lead with `http_replay` and a baseline/negative control.
4. Use harmless markers and test-owned fixtures. Never extract real records, dump schemas, read system files, execute commands, access cloud metadata/internal services, or trigger destructive or financial side effects to prove a finding.
5. Distinguish an observed signal from an exploitable result. Reflection, a parser error, a status change, or timing variation alone is not confirmation; rule out benign explanations and establish the relevant security impact.
6. Log every meaningful attempt with its actual observation, unique variation, strategy, and valid preconditions. Duplicate variations, planned-but-unrun tests, and tests with invalid scope/identity/setup do not count. A final false-positive/disproven verdict requires direct contradictory evidence under valid preconditions plus the matching contradictory checks in `validate_finding`; no fixed attempt count applies. If evidence is insufficient or relevant safe checks are exhausted, keep the result `INCONCLUSIVE / NEEDS REVIEW`. A decisive confirmation may stop early.

## Selecting a hypothesis

Use the following signals to decide whether a class is relevant. These are indicators, not automatic proof.

| Class | Evidence that may justify a targeted test | Safe confirmation principle |
|---|---|---|
| SQL / NoSQL injection | A plausible database/query sink, query-related source evidence, or a discriminating database/parser error | Compare a harmless true/false condition or controlled fixture result against a stable baseline; do not enumerate or extract data |
| XSS | A value reaches a browser-rendered HTML/attribute/script/URL context | Use a unique inert marker first; establish context and encoding. Use a benign execution canary only where explicitly authorized and safe |
| SSTI | Evidence of server-side template evaluation or a known rendering path | Use a non-destructive arithmetic expression such as `{{7*7}}` only where a template sink is plausible; compare with literal baseline |
| Command injection | Evidence that the value reaches an OS command or process invocation | Prefer source/configuration review or a harmless fixed-output canary in a controlled test environment; never run system commands or exfiltrate output |
| XXE | An XML parser processes attacker-controlled XML and external entities may be enabled | Use a controlled local test fixture or authorized canary. Never read local files or contact internal/metadata services |
| LDAP / XPath | Evidence the backend builds LDAP filters or XPath expressions from the input | Use a safe boolean/control comparison specific to the identified parser; do not assume a JSON REST parameter reaches either parser |
| Header / parameter pollution | Evidence that duplicate or alternate values are interpreted inconsistently across a trust boundary | Compare a captured baseline with a minimal, non-destructive variation and document which component consumed which value |

## Workflow

### 1. Establish the baseline

- Read the exact captured request, response, response content type, redirects, cookies, and session/identity context.
- Identify the input location and whether the value reaches the relevant parser or output context.
- Record normal status, body shape, relevant headers, timing, and any state change.
- Confirm scope and the approved replay tool before sending a mutation.

### 2. Probe only the supported class

- Call `inject_probe` with only the selected class(es) and exact input points when needed.
- Treat tool output as leads, not findings. A reflection flag, error signature, or boolean difference can be caused by validation, WAF/CDN behavior, caching, or unrelated application logic.
- Do not run a blanket sweep across all parameters. If the sink is not supported by evidence, stop and state what is missing.

### 3. Confirm with a control

- Replay the captured request through `http_replay`, changing one relevant factor at a time.
- Preserve required session/CSRF semantics; use a unique benign marker and a negative control.
- Verify that the effect is repeatable, tied to the candidate input, and not explained by cache, WAF, content negotiation, stale state, or tool artifacts.
- Avoid aggressive timing tests, deep query expansion, blind high-volume probes, or repeated payload variations without a discriminating reason.

### 4. Record the result honestly

For each candidate, preserve:
- Observed signal and exact request ID / evidence reference.
- Hypothesis and why the chosen class is relevant.
- Baseline, variation, negative control, and actual result.
- Scope/identity/setup validity and any missing precondition.
- Confirmed impact, benign explanation, or unresolved question.

Use `validate_finding` for the required ten-check assessment. Do not infer a pass/fail from missing evidence. A missing security header, reflected input, error response, or blocked payload does not itself prove a vulnerability. A tool attempt is not a confirmed finding.

## Stop conditions

Stop active testing when scope or authorization is unclear, a safe control is unavailable, the test risks real user data or irreversible state, the relevant sink is not reached, or no meaningful safe hypothesis remains. Preserve the limitation as blocked/inconclusive rather than working around it.

