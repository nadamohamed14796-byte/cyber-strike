---
name: attack-nodejs
description: "Assess Node.js web services for middleware-order, request-validation, session, file, and server-side sink defects using controlled API flows and source review."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - nodejs
  - express
  - fastify
  - koa
  - middleware
  - api
tech_stack:
  - nodejs
  - express
  - fastify
  - koa
  - javascript
  - typescript
cwe_ids:
  - CWE-20
  - CWE-200
  - CWE-285
  - CWE-78
chains_with:
  - attack-prototype-pollution
  - attack-sqli
  - attack-nosqli
  - attack-rce
  - attack-ssrf
  - attack-file-upload
prerequisites: []
severity_boost:
  attack-prototype-pollution: "Prototype-pollution impact requires a reachable unsafe gadget or security decision change; object mutation alone is not RCE."
---

# Node.js Service Security Assessment

## Objective

Review Node.js service boundaries across Express/Fastify/Koa middleware, parsers, cookies/sessions, file access, and async handlers. Test only known in-scope routes with synthetic data; map findings to the specific API and runtime/version.

## Testing Methodology

### Phase 1: Identify framework and middleware stack

Use package locks, route registration, response headers, and source entrypoints to identify Express/Fastify/Koa, authentication middleware, body parsers, and relevant libraries. Avoid exact-version claims from headers alone.

### Phase 2: Review middleware ordering and error paths

Check whether authorization runs on every sensitive route before side effects, including alternate methods, nested routers, async callbacks, and error handlers. A validation error may occur before auth; send a minimal well-formed test request before concluding access is missing.

### Phase 3: Validate input types and model binding

Check JSON object/array/scalar handling, unknown properties, file names, path joins, and URL inputs. Reuse class-specific SQLi/NoSQLi/prototype-pollution/upload skills where appropriate rather than duplicating their payload banks. Prefer source-to-sink review and harmless values.

### Phase 4: Review sessions, cookies, and trust headers

Inspect cookie options, proxy trust settings, Host/X-Forwarded-* handling, origin checks, and session rotation. Compare expected and actual URL reconstruction in a controlled setup; never use malicious Host headers to send recovery emails or poison production cache.

### Phase 5: Inspect server-side sinks and deserialization

Review child_process/eval, template engines, dynamic require, file read/write, archive extraction, and unserialize/JSON parser wrappers. Do not execute commands, read secrets, or write files on production; validate deeper behavior in a disconnected lab.

### Phase 6: Verify API authorization and async job boundaries

Use two test identities and a synthetic resource to compare route/tenant access, including queued jobs and result-download endpoints. A job ID should remain tied to owner and tenant. Avoid enumerating IDs or reading any non-test job output.

### Phase 7: Confirm root cause and regression

Trace the route, middleware, schema, service, and sink. Document a minimal failing request and the server-side control that should deny it. Clean up synthetic records and stop at the smallest confirmed effect.

## What Constitutes a Finding

- **Candidate / lead:** middleware/configuration smells, unexpected object types, verbose stack trace, route mismatch, or scanner alert.
- **Confirmed finding:** a reproducible in-scope input crosses an authentication, authorization, data-validation, or execution boundary and changes a controlled test outcome.
- **Not a finding:** framework presence, public source bundle, status-only differences, unused dependency, or dangerous API that is unreachable or receives trusted constants.

## Evidence Requirements

- Node.js/framework version evidence and exact route/handler.
- Baseline versus modified request, test role, timestamp, and resulting state.
- Source-to-sink trace or sanitized server error that proves root cause.
- No session tokens, environment secrets, customer records, or host file content.

## Tools

- **Source search / Semgrep:** trace middleware, parsers, and server-side sinks.
- **Burp Suite / curl:** replay one route with controlled values.
- **npm audit / lockfile review:** correlate dependencies to current advisories without assuming reachability.
- **Node test harness/container:** reproduce risky parsing/sink behavior with synthetic data.

## Node.js Request and Sink Matrix

| Surface | Review | Confirmation |
|---|---|---|
| Middleware | Router order, async guards, error handlers | Restricted test operation actually succeeds without auth |
| Body parser / DTO | Nested object types, mass assignment, parser limits | Protected property/query semantics change in a fixture |
| Proxy headers | trust proxy, Host and forwarded header use | A security-relevant destination/policy changes in controlled test |
| Sessions/cookies | flags, rotation, tenant binding | Prior test session retains access contrary to policy |
| File/URL inputs | path normalization, URL fetch, upload storage | Test-owned canary crosses intended file/network/origin boundary |
| Child process/eval | attacker input reaches an executable sink | restricted-to-lab harmless proof and reachable source-to-sink |
| Async jobs | owner/tenant binding on job creation/result | Another test identity accesses only synthetic job output |

**Mitigation:** validate schemas explicitly, use framework-native safe APIs, secure middleware ordering, restrict proxy trust, rotate sessions, sandbox job workers, and add route-level authorization regression tests.

## Verification and False Positives

- Parser/WAF errors can precede authentication; use a valid minimal request to map middleware order.
- A dependency vulnerability is not exploitable unless the vulnerable code path is reachable and prerequisites apply.
- Request URL/Host variations may be normalized by a proxy; confirm the origin's actual interpretation.
- Do not use prototype pollution, command execution, deserialization gadgets, file writes, or SSRF payloads on production when a non-destructive validation is sufficient.


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

The 20-attempt budget is a ceiling for independent, evidence-producing hypotheses, not a quota for payload mutations. If a signal remains plausible, follow relevant branches up to the ceiling; stop early when impact is decisive, no relevant branch remains, or safety/scope limits apply. Cosmetic input changes with the same semantics are not separate attempts.

Record each attempt: hypothesis, single changed variable, control/baseline, observed signal, interpretation, confidence and next branch. Prefer paired requests, controlled identities, synthetic records and independent corroboration; retain minimal sanitized evidence.

### Skill-specific hypothesis order

Choose independent, low-impact verification branches already supported by this skill's coverage matrix.

### Verdict gates

- **Confirmed:** repeatable security impact against an explicitly in-scope resource is shown using a tester-controlled identity/fixture and a meaningful negative control.
- **Likely / needs corroboration:** independent observations support the hypothesis but impact/root cause remains uncertain.
- **Unconfirmed:** output is generic, cached, ambiguous, or detached from a security boundary.
- **Refuted / false positive:** a relevant negative control or valid product/security-policy explanation accounts for the signal. Document attempted branches rather than claiming to exhaust every theoretical variant.
- Status codes, banners, timing changes, error messages, or scanner alerts alone are not proof.

### Stop, cleanup, and handoff

Stop at scope ambiguity, real-user data, unexpected state changes, service degradation, secret exposure or a prohibited action. Clean disposable state, revoke temporary sessions/tokens where possible, and log cleanup status. Handoff scope proof, baseline, hypothesis, attempts used, impact, controls, verdict/confidence, sanitized evidence and any proven related-skill trigger; do not chain from a speculative association.

## References

- [uphiago — hunt-nodejs](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-nodejs)
- [Claude-BugHunter — hunt-nodejs](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-nodejs)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [Node.js Security Best Practices](https://nodejs.org/en/learn/getting-started/security-best-practices)
