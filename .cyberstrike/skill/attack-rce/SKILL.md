---
name: attack-rce
description: "Assess suspected server-side command or code execution through bounded source-to-sink review and non-destructive confirmation gates."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - rce
  - command-injection
  - code-injection
  - execution
  - validation
tech_stack:
  - web
  - linux
  - windows
  - java
  - nodejs
  - python
  - php
  - dotnet
cwe_ids:
  - CWE-78
  - CWE-94
chains_with:
  - attack-ssti
  - attack-deserialization
  - attack-file-upload
  - attack-ssrf
prerequisites: []
severity_boost:
  attack-deserialization: "Unsafe deserialization raises to RCE only when a reachable execution path is independently verified."
  attack-file-upload: "Upload weaknesses become RCE only if a server-side interpreter/process executes the content in an authorized test."
---

# Remote Code and Command Execution Assessment

## Objective

Distinguish actual server-side execution from errors, reflection, template evaluation, or file-write behavior. Default to code/configuration review; any command execution requires explicit authorization for that exact action.

## Testing Methodology

### Phase 1: Establish authorization and stop conditions

Verify the exact endpoint, component, test account, and rules of engagement. Command execution, callbacks, file writes, interpreter launches, and internal-service access are high-risk. If a harmless execution proof is not explicitly permitted, do not deliver executable payloads; document source/configuration evidence and request approval.

### Phase 2: Map candidate execution sinks

Inspect shell invocation APIs, dynamic evaluation, template engines, expression languages, job runners, build hooks, report converters, plugins, and user-controlled interpreter options. Trace untrusted values through escaping, argument arrays, environment variables, and authorization checks.

### Phase 3: Capture normal behavior

Record response, job status, error behavior, and latency for ordinary inputs. Change one field at a time. Avoid shell metacharacter chains, reverse shells, web shells, persistence, and commands that read files or enumerate the host.

### Phase 4: Use a controlled proof gate

Prefer static source proof, an isolated staging instance, or a vendor-provided canary. If explicitly authorized, demonstrate only the smallest harmless fixed result that cannot access files, network, processes, secrets, or mutable state. Arithmetic evaluation proves a template/expression context, not arbitrary OS command execution.

### Phase 5: Document reachable impact

Record process identity, permission boundary, sandbox/container limits, and remote reachability only when already exposed by the approved proof. Do not pivot to privilege escalation, lateral movement, secret harvesting, persistence, or destructive commands without separate authorization.

## What Constitutes a Finding

- **Candidate / lead:** input reaches an execution-related API, an error suggests expression parsing, or a scanner reports command injection.
- **Confirmed execution:** an approved harmless canary is attributable to the tested input in an isolated/authorized environment, or review-only source tracing proves a reachable unsafe path.
- **Template evaluation is not automatically RCE:** distinguish expression evaluation from host command execution.
- **Not a finding:** reflected command text, generic 500s, stack traces, latency spikes, or a vulnerable library with no reachable path.

## Evidence Requirements

- Exact sanitized request, baseline, response/job state, timestamp, and test role.
- Source-to-sink trace, relevant API call and escaping path, or approved canary result.
- Process/sandbox context only as established by the approved proof; no host inventory or secrets.
- Separate demonstrated impact from hypothetical follow-on impact.

## Tools

- **Burp Suite / curl:** bounded single-request comparisons.
- **Semgrep / language-native search:** find execution sinks and trace data flow.
- **Staging container/test harness:** reproduce without production side effects.
- **Application logs:** corroborate an approved canary when logs are in scope.

## Execution Primitive and Proof Matrix

| Primitive | Safe first step | Confirmation limit |
|---|---|---|
| Shell command construction | Review shell APIs and argument separation | No chaining or host-enumeration commands |
| Expression/eval API | Trace input; test an inert expression in a lab | Arithmetic evaluation alone is not RCE |
| Template engine | Use a test-owned preview with an inert expression | SSTI and OS command execution are distinct |
| Job/build runner | Inspect authorization and use a sandbox dummy job | No production deploy or outbound call without permission |
| Deserialization | Review accepted types and dependency exposure | No gadget-chain execution on production |
| Upload/processor | Inspect storage and processing pipeline | Never upload a web shell or active server script |
| Internal management surface | Confirm scope and access control | Do not chain SSRF to execution absent explicit approval |

**Mitigation / regression:** avoid shell calls where native APIs exist, pass arguments as arrays, use strict allowlists, sandbox workers, remove unsafe deserialization/evaluation, and regression-test the reachable input path.

## Verification and False Positives

- Expression evaluation, template rendering, and shell execution are different capabilities.
- A 500 error, malformed output, or timing shift is not proof of execution.
- Static matches may be unreachable or wrapped in safe argument handling.
- Severity must reflect demonstrated sandbox and privilege boundaries, not hypothetical host access.
- Do not run reverse shells, persistence, destructive commands, internal scans, or secret-reading commands as a default PoC.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue with materially distinct, authorized branches while evidence can change the conclusion; deduplicate cosmetic variants and exact retries. Stop when direct evidence resolves the hypothesis, meaningful branches are exhausted, a prerequisite is unavailable, or scope/safety requires stopping. Never exceed the explicitly authorized proof boundary or turn validation into post-exploitation.

Keep an attempt ledger: hypothesis, one variable changed, baseline/control, signal, interpretation, confidence and next branch. Use controlled identities/fixtures, independent corroboration, low-impact requests and minimum sanitized evidence.

### Skill-specific hypothesis order

1. Confirm the exact in-scope component and input boundary, then establish a harmless baseline and a negative-control value before any validation attempt.
2. Use a non-destructive proof only in a test/lab or explicitly approved endpoint; prefer an inert marker or benign arithmetic result over shell commands, filesystem access, or network callbacks.
3. If command execution is specifically authorized, constrain proof to a fixed benign command with a unique nonce, hard timeout, no persistence, no credential access, and no external side effect.
4. Do not install tools, create users, read secrets, establish shells, alter files, or chain to post-exploitation. Stop immediately if impact exceeds the agreed proof.
5. Capture the minimum sanitized request/result, establish repeatability with a negative control, and recommend the exact input-validation/API separation/patch fix with a regression test.


### Verdict gates

- **Confirmed:** repeatable impact at an explicit in-scope boundary is demonstrated with a controlled fixture/identity and relevant control.
- **Likely / needs corroboration:** multiple independent signals support the candidate but the effect or cause remains uncertain.
- **Unconfirmed:** signal is generic, timing/cache-dependent, or not tied to a security property.
- **Refuted / false positive:** a relevant control or valid product/security behavior explains the observation; preserve the test ledger rather than claiming all theoretical vectors were attempted.
- A status code, banner, parser error, timing fluctuation, version string, or scanner alert alone is not proof.

### Safety, cleanup, and handoff

Stop on scope ambiguity, unexpected state changes, sensitive data, service degradation, secret exposure or prohibited actions. Restore synthetic state and revoke temporary credentials/sessions where possible. Report scope proof, baseline, hypothesis, attempt count, impact, controls, verdict/confidence, sanitized evidence and cleanup status. Chain into another skill only after observing its required signal.

## References

- [uphiago/recon-skills — hunt-rce](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-rce)
- [elementalsouls/Claude-BugHunter — hunt-rce](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-rce)
- [OWASP — OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)


## Targeted quality-loop enrichment (2026-10-19)

### Execution boundary and proof discipline
Map the input-to-execution path, process identity, sandbox/container boundary, and downstream effect before testing. Prefer static/source evidence and an isolated lab; use an inert observable proof such as a controlled marker or test harness log, never commands that read secrets, change persistence, fetch payloads, or affect neighboring systems. Separate template evaluation, command construction, deserialization, file processing, and a vulnerable dependency because each requires a different root cause. A delay, error string, or reflected command text alone is not RCE. If only a reachable sink is shown, mark it as a candidate; confirm execution with a safe fixture, then state exactly the demonstrated authority and stop.


## Source-to-sink code-review checklist

Run static search only on an authorized source tree. Treat matches as candidates and trace whether user-controlled input reaches the sink, what validation occurs, and which execution context is actually used.

```bash
rg -n --glob '*.{js,ts,py,php,java,cs,go,rb}' \
  'child_process|execSync|spawn\(|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|os\.system|subprocess\.(run|Popen|call)|shell=True|eval\(|new Function|Process\.Start' .
```

Review wrappers, argument arrays, shell flags, environment-variable expansion, template context, sandboxing, and reachability. A sink match without attacker-controlled data flow is not a vulnerability.

### Proof-classification matrix

| Evidence | Classification |
|---|---|
| Dangerous API exists in source but input cannot reach it | Not confirmed; document why unreachable |
| User input reaches a command API with safe argument separation/allowlist | Review the actual argument semantics; do not assume RCE |
| Inert template expression is evaluated | Template/expression injection candidate, not automatically OS RCE |
| Approved harmless canary is attributable to the exact input in a lab | Confirm only the demonstrated execution primitive |
| Error/latency/response reflection without execution proof | Unconfirmed lead |
| Static analysis flags an unsafe API without data-flow evidence | Candidate for manual tracing |

### Chain discipline

- Template evaluation → SSTI review; OS execution is a separate proof requirement.
- Deserialization sink → deserialization review; do not attempt gadget execution on production.
- File upload/processor → upload review; no web shells or active server scripts.
- URL-consuming input → SSRF review only if server-side fetch is demonstrated.
- Confirmed command execution does not authorize host discovery, credential access, persistence, or lateral movement. Stop at the agreed harmless proof.

Record source_file_line, input_source, transformations, sink_api, argument_mode, validation, sandbox_context, approved_proof_type, observed_result, negative_control, and cleanup_status.


## Tool installation and optional tooling (2026-10-19)

### Agent-usable tools and purpose
- `rg` — trace candidate source-to-sink flows in an authorized local source tree.
- `semgrep` — run relevant static rules against a local checkout; findings are leads until data flow is confirmed.
- `curl` or Python `httpx` — reproduce a captured, permitted request with a benign marker only.
- `strace` or platform-native process logs — investigate behavior in a disposable local reproduction, not on production without explicit approval.
- `python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt` — compare saved redacted responses offline; it sends no requests.

### Installation and verification
Install Semgrep using https://semgrep.dev/docs/getting-started/ and verify with `semgrep --version`. Verify `rg --version` and `curl --version`; verify Python httpx with `python3 -c "import httpx; print(httpx.__version__)"` when selected. Use official OS package sources or upstream instructions. If unavailable, record the missing dependency and continue with source review or a disposable lab; do not claim the check ran.

### Primary resources
- https://portswigger.net/web-security/os-command-injection
- https://semgrep.dev/docs/
- https://owasp.org/www-project-web-security-testing-guide/
- https://cwe.mitre.org/data/definitions/78.html

### Safety and result handling
Browser UI, browser extensions, and interactive proxies are not agent dependencies. Do not use destructive commands, persistence, file reads, environment dumps, or credential access as proof. A sink match, error, delay, or reflected input is not proof of execution. Confirm only approved harmless behavior, preserve minimal redacted evidence, and stop.
