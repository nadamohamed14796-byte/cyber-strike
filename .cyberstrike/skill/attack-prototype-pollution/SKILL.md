---
name: attack-prototype-pollution
description: "Assess JavaScript prototype pollution in client and server object-processing paths using inert markers"
category: "web-application"
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [prototype-pollution, javascript, nodejs, object-merge, validation]
tech_stack: [javascript, nodejs, browser, json]
cwe_ids: [CWE-1321]
chains_with: [attack-ssti, attack-xss, attack-triage-validation]
prerequisites:
  - "Authorized application or isolated test environment"
  - "A harmless marker and a way to observe only test-owned state"
sources:
  - "https://github.com/uphiago/recon-skills"
  - "https://portswigger.net/web-security/prototype-pollution"
---

# JavaScript Prototype Pollution Assessment

## Objective

Determine whether attacker-controlled input modifies an object's prototype or prototype-related properties in a way that changes security-relevant behavior. A suspicious key, parser acceptance, or local console result alone does not prove impact.

## Scope and safety

Use a local lab or a dedicated test account. Start with inert properties and avoid payloads that execute commands, alter privileged settings, affect other tenants, or persist changes globally. Do not attempt RCE gadget chains on production systems.

## Procedure

### 1. Identify merge and parsing paths

Review URL/query parsing, JSON body handling, recursive merge utilities, configuration loaders, object assignment, and dependency versions. Search code and traffic for `__proto__`, `constructor`, `prototype`, and nested object merges. Treat strings as indicators, not proof.

### 2. Establish a baseline

Record the normal response and relevant behavior before submitting any marker. Determine whether the candidate path is client-side or server-side, and whether data is merged into ordinary objects or a safer structure.

### 3. Test an inert marker

In a local or controlled environment, use a unique harmless property through one input path at a time. Check whether the marker appears only in the submitted object or also affects a newly created unrelated object or downstream logic. Avoid mutating shared application state in a live multi-user environment.

### 4. Trace the gadget or sink

If pollution is observed, identify a concrete property that changes security-relevant behavior: authorization defaults, template options, URL handling, or another documented sink. Do not assume XSS or RCE from pollution alone. Validate downstream impact separately with `attack-xss` or the relevant approved skill.

### 5. Compare client and server behavior

For browser code, inspect whether the pollution is limited to the current page/context and whether it affects a real sink. For Node.js/server paths, use staging or a test harness to verify process-level impact without touching production users or secrets.

### 6. Review dependency and remediation context

Record the affected merge function/library and version evidence. Prefer safe data structures, schema allowlists, explicit key rejection for dangerous prototype-related keys, and patched dependencies. A dependency version alone is not a finding.

## Common false positives

- The input contains `__proto__` but the parser treats it as an ordinary own property.
- Pollution is confined to a test object and reaches no security-relevant sink.
- A scanner reports a payload without observing state change.
- An XSS/RCE gadget is hypothesized but not demonstrated.
- A dependency version is old but the vulnerable code path is not reachable.

## Evidence and output

Return `input_path`, `runtime_context`, `marker_used`, `baseline_behavior`, `prototype_effect_confirmed`, `affected_sink`, `security_impact`, `cleanup_status`, `confidence`, and redacted evidence. Keep production secrets and target data out of logs.

## Related skills

- `attack-xss` — validate client-side execution separately.
- `attack-ssti` — template/server-side sinks, if applicable.
- `attack-triage-validation` — establish impact and rule out false positives.
