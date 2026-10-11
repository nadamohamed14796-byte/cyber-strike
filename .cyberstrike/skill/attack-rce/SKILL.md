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

## References

- [uphiago/recon-skills — hunt-rce](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-rce)
- [elementalsouls/Claude-BugHunter — hunt-rce](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-rce)
- [OWASP — OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
