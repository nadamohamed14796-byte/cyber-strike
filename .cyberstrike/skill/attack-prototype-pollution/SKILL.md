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


## Targeted quality-loop enrichment (2026-10-19)

### Pollution-to-gadget proof
Identify the input parser or merge/clone operation, the exact property path, and the affected object scope (local object, browser prototype, server process, or shared request state). In a disposable harness or test account, inject an inert marker into one prototype-sensitive property and verify persistence and downstream reads. Distinguish harmless object mutation from a reachable gadget that changes authorization, output encoding, request routing, or code paths. Do not pollute a shared production process or attempt RCE. Route client-side sources/sinks to DOM-XSS review only when the polluted property reaches an executable sink; route server-side consequences to the relevant framework/input-validation specialist.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Use Burp for request correlation, browser DevTools or Burp DOM Invader to inspect client-side source/sink behavior, and Node.js in an isolated lab to understand server-side object behavior. Static grep is only a discovery aid.

### Installation and setup
- [Burp Suite](https://portswigger.net/burp) — install via PortSwigger; DOM Invader is available in supported Burp browser/testing workflows, documented at https://portswigger.net/burp/documentation/desktop/tools/dom-invader .
- [Node.js](https://nodejs.org/en/download/) — install a supported release for owned source/lab tests.
- [Semgrep](https://semgrep.dev/docs/getting-started/) — optional static rules; do not interpret a rule match as a reachable vulnerability.
Only test controlled input and disposable objects; don't set global process state on a live service.

### Primary resources
- [PortSwigger prototype pollution](https://portswigger.net/web-security/prototype-pollution) — browser/server patterns.
- [MDN JavaScript prototypes](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Inheritance_and_the_prototype_chain) — language semantics.
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) — impact confirmation.

### Reusable helper
`python3 .cyberstrike/skill/scripts/js_endpoint_inventory.py ./javascript` extracts conservative route candidates from already-collected local assets; it does not execute JS.

### Result handling
Separate a controllable prototype property from impact. Verify an application-relevant authorization, execution, or integrity consequence with a reversible controlled test.
