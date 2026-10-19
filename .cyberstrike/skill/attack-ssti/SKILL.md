---
name: attack-ssti
description: "Assess server-side template injection using harmless expressions and engine-aware validation"
category: "web-application"
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [ssti, templates, injection, server-side, validation]
tech_stack: [http, java, python, php, nodejs, dotnet]
cwe_ids: [CWE-1336]
chains_with: [attack-prototype-pollution, attack-triage-validation]
prerequisites:
  - "Authorized template-rendering endpoint"
  - "Harmless arithmetic/string marker and non-destructive validation plan"
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-ssti/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
  - "https://portswigger.net/web-security/server-side-template-injection"
---

# Server-Side Template Injection (SSTI) Assessment

## Objective

Determine whether user-controlled input is interpreted as template syntax on the server, then establish the reachable impact without executing destructive actions or exposing secrets.

## Safety gates

Use harmless expressions first. Do not execute shell commands, read server files, access environment variables, trigger callbacks, or attempt RCE against production systems. If impact validation requires code execution, use an isolated lab or explicitly approved staging environment.

## Procedure

### 1. Identify template contexts

Look for user-controlled values rendered in email templates, document generation, reports, notifications, page templates, CMS fields, and server-side preview features. Capture the baseline output and determine whether the value is escaped, inserted as text, or parsed as template syntax.

### 2. Use harmless expressions

Test a small arithmetic or string expression appropriate to the suspected template syntax, changing only one input at a time. Compare the rendered output with the literal input and the expected expression result. Avoid engine-specific payload chains until the engine is reasonably identified.

### 3. Fingerprint conservatively

Use benign syntax differences and error behavior to narrow the engine family. Do not rely on a stack trace or framework banner alone. Avoid large payloads, recursive loops, expensive expressions, and error-triggering payloads that may affect availability.

### 4. Confirm server-side evaluation

Verify that the server evaluates the expression rather than the browser or a client-side template engine. Repeat with a unique marker and confirm the output path. If only a parser error is observed, classify the result as a lead until evaluation is demonstrated.

### 5. Determine impact safely

Check whether template context exposes untrusted data, permits unintended logic, or reaches privileged objects. Do not attempt file reads, command execution, secret extraction, or outbound callbacks on production. Use an isolated environment to demonstrate higher-impact engine capabilities with a harmless proof.

### 6. Remediation guidance

Recommend context-appropriate escaping, avoiding dynamic template construction from untrusted input, sandboxing, least-privilege template context, and patched template dependencies. Input filtering alone is not a robust substitute for safe rendering.

## Common false positives

- Client-side JavaScript evaluates the expression.
- The input is reflected literally.
- Error text names a template engine but no expression is evaluated.
- A framework version is identified without a reachable vulnerable sink.
- A harmless expression works but no security-relevant context is exposed.

## Output contract

Return `input_sink`, `baseline_output`, `expression_test`, `server_side_evaluation`, `engine_confidence`, `reachable_context`, `impact_confirmed`, `environment`, `confidence`, and redacted evidence.

## Targeted quality-loop enrichment (2026-10-19)

### Template evaluation vs ordinary reflection
Identify where the value is inserted (HTML escaping, template expression, server-side preview, email/PDF renderer) and establish a normal literal baseline. Use inert arithmetic/string expressions in a disposable fixture to distinguish server-side evaluation from reflection or client-side rendering; do not use file-read, process-execution, or environment-dumping payloads. Repeat with one template context at a time and compare rendered output, not just error codes. A confirmed evaluated expression does not automatically prove RCE; demonstrate only the minimum permitted impact and keep greater capabilities hypothetical until safely proven in an isolated lab. Route parser serialization to deserialization/XXE as appropriate and record the rendering context for remediation.

## Agent-executable CLI tooling, resources, and helper scripts

Use CLI tools and local test harnesses the agent can invoke directly; browser UI, extensions, and interactive intercepting proxies are not dependencies. Verify tool availability/version, official documentation, license, and request impact before use.

### Recommended tools
- A local template-engine fixture for identifying expression evaluation
- Semgrep — local source/configuration clues when source is available
- curl/Python requests — minimal controlled inputs
- jq — structured output comparison

### Resources
- https://portswigger.net/web-security/server-side-template-injection
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/vavkamil/awesome-bugbounty-tools

Use the upstream community list only to discover candidates. Confirm tool maintenance, provenance, dependencies, and supported usage from official sources.

### Helper-script contract
Keep payloads non-destructive and engine-specific. Separate reflected text from server-side expression evaluation; do not attempt command execution or filesystem access on production systems.

Helpers must accept explicit paths, preserve native evidence, write normalized output separately, redact sensitive values, record timestamps and tool versions, handle malformed inputs, and include local fixtures.

### Handoff
Return the tool/version, command, input/output artifact references, control result, failures, confidence, and limitations. A candidate signal is not a confirmed finding.
