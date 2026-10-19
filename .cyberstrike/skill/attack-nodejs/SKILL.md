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


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue with materially distinct, authorized branches while evidence can change the conclusion; deduplicate equivalent requests and retries. Stop when direct evidence resolves the hypothesis, relevant branches are exhausted, a prerequisite is unavailable, or scope/safety requires stopping. Production safety and program rules remain mandatory.

Record each attempt: hypothesis, single changed variable, control/baseline, observed signal, interpretation, confidence and next branch. Prefer paired requests, controlled identities, synthetic records and independent corroboration; retain minimal sanitized evidence.

### Skill-specific hypothesis order

1. Identify the actual Node.js framework and entry points (Express/Koa/Fastify or custom) from confirmed evidence, and map the middleware order relevant to the candidate route.
2. Check parsing/validation, error handling, path/host trust, cookie/session policy, and route authorization one layer at a time; use a malformed but benign request and a random-path control.
3. Where prototype pollution, deserialization, template rendering, or file operations are plausible, begin with inert markers and a test-owned fixture rather than command execution or data extraction.
4. Compare server-side policy across API and UI routes using controlled identities; confirm object ownership and schema validation independently of client-side controls.
5. Report only a reproducible server-side consequence and include framework-specific safe configuration/code remediation plus the exact negative-control regression test.


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


## Targeted quality-loop enrichment (2026-10-19)

### Middleware and parser differential
Record the exact route, middleware order, body parser, validation schema, session attachment, proxy trust configuration, async job handoff, and storage sink. Compare valid baseline input with one harmless type/boundary mutation at a time; verify the operation and persisted state, not just a stack trace. Check alternate content types, duplicate parameters, nested objects, and error paths only where the server accepts them. A route-level guard may be bypassed by a second mounted transport, so map both UI and API traffic. Route duplicate-query parse differences to server-side parameter pollution, sensitive writable fields to mass assignment, and URL-fetch behavior to SSRF.


## Practical source-to-sink search and route inventory

Run against the authorized local source tree. Search is for triage; inspect surrounding code and reachability before classifying a finding.

```bash
rg -n --glob '*.{js,mjs,cjs,ts,tsx}' \
  'app\.(get|post|put|patch|delete|use)|router\.(get|post|put|patch|delete|use)|setTrustProxy|trust proxy|child_process|eval\(|new Function|innerHTML|path\.join|fetch\(' src .
```

Normalize duplicate route registrations by method + route template + middleware chain. Trace body parsing, authentication, authorization, validation, handler, service, and side effect in that order. A route declaration alone does not show that middleware is missing.

### Node-specific review matrix

| Component | Review | Confirmation |
|---|---|---|
| Express router | Mounted router order, inherited middleware, error handlers | Controlled request reaches protected handler without required guard |
| Fastify | Hooks, schema validation, encapsulation, route config | Guard is absent from the actual encapsulated route |
| Koa/custom middleware | Composition order and async error paths | Security check is skipped on an observed path |
| Proxy trust | Trust proxy configuration and forwarded headers | Actual client/authority decision changes, not just logged value |
| File/path APIs | Path resolution and ownership check | Test-owned fixture crosses its intended directory/object boundary |
| Async job | Job owner/tenant metadata and result download | A second test identity can read only the synthetic job result |
| Dependencies | Lockfile version and reachable vulnerable call site | Advisory prerequisites and affected call path both match |

Persist framework_version_source, route_template, middleware_chain, parser_schema, input_source, sink_or_side_effect, principal, test_fixture, negative_control, observed_state, and cleanup_status.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Use Node.js/npm for an authorized source checkout, `npm audit` for dependency advisories, Semgrep for targeted source rules, and Burp/browser DevTools for runtime validation.

### Installation and setup
- [Node.js download and installation](https://nodejs.org/en/download/) — select a supported release.
- [npm audit documentation](https://docs.npmjs.com/cli/commands/npm-audit) — check dependencies without blindly applying fixes.
- [Semgrep installation](https://semgrep.dev/docs/getting-started/) — use official instructions.
Run dependency changes on a disposable checkout first; review lockfile changes. A dependency advisory does not automatically mean the application is exploitable.

### Primary resources
- [Node.js security best practices](https://nodejs.org/en/learn/getting-started/security-best-practices) — runtime/application controls.
- [OWASP NodeGoat](https://owasp.org/www-project-nodegoat/) — controlled learning application.
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) — application-level checks.

### Reusable helper
`python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt` compares sanitized response artifacts without sending requests.

### Result handling
Record package name/version, advisory, reachability, and the application's actual use of the affected code. Keep security claims proportional to evidence.

## Agent-executable CLI tooling, resources, and helper scripts

Prefer CLI tools, local static analysis, and repeatable test harnesses. Browser interfaces, browser extensions, and interactive intercepting proxies are not dependencies. Verify versions, official installation guidance, license, and dependency provenance before running tools.

### Recommended tools
- Semgrep — JavaScript/TypeScript source patterns
- npm audit — dependency advisories
- retire.js — known vulnerable browser-side dependencies
- Node test runner — deterministic local regression fixtures

### Resources
- https://semgrep.dev/docs/
- https://docs.npmjs.com/cli/commands/npm-audit
- https://github.com/RetireJS/retire.js
- https://nodejs.org/api/test.html
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are for discovery only; use official framework and tool docs for current behavior.

### Helper-script contract
Preserve package-lock hash, package/version/advisory, source path, and test fixture. Avoid installing dependencies from untrusted sources just to analyze a target; use local source and lockfiles first.

Keep raw evidence separate from normalized output. Preserve package/version, rule/advisory ID, source path, tool/version, timestamps, error state, confidence, and redaction. Use deterministic local fixtures and JSON/JSONL output where useful.

### Handoff
Return commands actually executed, tool versions, input/output artifacts, checks passed/failed, limitations, and next skill. Do not present a static-analysis warning as a confirmed runtime vulnerability.
