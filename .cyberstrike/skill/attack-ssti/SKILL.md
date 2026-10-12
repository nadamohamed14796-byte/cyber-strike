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
