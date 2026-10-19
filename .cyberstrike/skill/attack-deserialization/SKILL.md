---
name: attack-deserialization
description: "Assess unsafe object deserialization by tracing untrusted serialized data into type reconstruction and execution-capable gadget paths without triggering production payloads."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - deserialization
  - serialization
  - rce
  - java
  - dotnet
  - python
  - php
tech_stack:
  - java
  - dotnet
  - python
  - php
  - ruby
  - nodejs
  - web
cwe_ids:
  - CWE-502
chains_with:
  - attack-rce
  - attack-file-upload
  - attack-ssrf
prerequisites: []
severity_boost:
  attack-rce: "Deserialization raises to RCE only when an execution path is independently established in an authorized harness."
---

# Insecure Deserialization Assessment

## Objective

Determine whether attacker-influenced serialized data is reconstructed into unsafe types or triggers dangerous side effects. Identify format and trust boundary; do not deliver public gadget chains or executable object payloads to production.

## Testing Methodology

### Phase 1: Inventory serialization boundaries

Inspect cookies, hidden fields, API bodies, queue messages, import/export files, cache entries, and RPC endpoints. Identify format and decoder from headers, code, manifests, and safe samples. A Base64 prefix or serialization signature is only a lead.

### Phase 2: Trace integrity and type controls

Review whether data is signed/authenticated before deserialization, whether type metadata allows arbitrary classes, and whether custom constructors/hooks execute during reconstruction. Identify who can modify the serialized bytes and which trust boundary supplies them.

### Phase 3: Probe parser behavior with inert input

Use an application-generated test sample and then a malformed or harmless data-only structure. Observe validation and tamper rejection. Do not generate or submit gadget chains, pickle reducers, ViewState gadget payloads, JNDI lookups, or execution-triggering objects against production.

### Phase 4: Confirm in an isolated harness

Reproduce with the same version/configuration in local or staging using a harmless marker object and disabled network egress. Mount no secrets or host paths. Distinguish parsing, object construction, side effect, and code execution.

### Phase 5: Assess blast radius and fix

Trace the deserialization principal, permissions, sandbox, and dependency version. Check whether signed input can still express unsafe types. Do not pivot from a deserialization candidate into host command execution.

## What Constitutes a Finding

- **Candidate / lead:** serialized bytes are user-modifiable, an unsafe decoder is reachable, or type metadata is accepted without integrity protection.
- **Confirmed vulnerability:** a reproducible untrusted-data path bypasses integrity/type restrictions or constructs an unsafe type in a controlled harness.
- **Confirmed RCE:** requires separately approved evidence of execution; deserialization alone is not proof of RCE.
- **Not a finding:** a magic prefix, Base64 blob, dependency match, or parser error without a reachable unsafe path.

## Evidence Requirements

- Format identification and a redacted sample generated from a tester-owned account.
- Endpoint, role, timestamp, parser/runtime version, and integrity-control result.
- Source-to-sink path and relevant configuration/dependency versions.
- Isolated harness reproduction and sanitized event/output; no production gadget payloads or target data.
- Explicitly distinguish deserialization, side effects, and RCE.

## Tools

- **Source search / Semgrep:** locate deserialize/unserialize/load APIs and type hooks.
- **SBOM/dependency review:** identify affected runtime and library versions.
- **Burp Repeater:** compare application-generated and malformed data-only samples.
- **Isolated harness:** reproduce with egress disabled and synthetic data.

## Serialization Format and Risk Matrix

| Format | Review focus | Safe proof |
|---|---|---|
| Java native serialization | ObjectInputStream filters, allowed classes, integrity | Source/config review or benign object in an isolated harness |
| .NET BinaryFormatter/ViewState | Legacy formatter, MAC/signature, key handling | Version/config evidence; no gadget generation against production |
| Python pickle | Whether untrusted bytes reach pickle.load(s) | Static data flow or sandboxed marker fixture; no reducer payload |
| PHP serialize/unserialize | Magic methods and attacker-controlled object graphs | Test-owned sample and source review; no gadget-chain execution |
| Ruby Marshal | Untrusted load paths and gem hooks | Isolated harness only |
| JSON/data-only formats | Custom type tags and polymorphic constructors | Test schema/type allowlist and tamper rejection |

**Mitigation / regression:** prefer data-only formats, authenticate before parsing, disable unsafe polymorphic typing, allowlist required types, isolate parser workers, and test malformed/tampered samples.

## Verification and False Positives

- Serialized-looking data may be inert, signed, encrypted, or never decoded by the server.
- A vulnerable dependency is not proof the affected code path is reachable.
- Parser errors show input handling, not unsafe object creation or RCE.
- Do not trigger outbound JNDI/DNS, file writes, commands, or persistent side effects against production.
- Stop when type behavior is established; use an isolated harness for deeper impact proof.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Treat the attempt budget as a ceiling for evidence-producing hypotheses, not a quota for payload variants. When a candidate remains plausible, branch to the next independent hypothesis without an arbitrary fixed ceiling; stop earlier when evidence is decisive, the remaining hypotheses are not relevant, or safety/scope limits apply. Cosmetic variants of the same request do not count as independent attempts.

Keep a ledger per attempt: hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired comparisons and controlled test identities. Preserve evidence, redact secrets, and avoid unrelated data.

### Skill-specific hypothesis order

1. Identify the exact serialized input boundary and format from application traffic or documentation; capture a valid request and establish the normal parse/validation response first.
2. Use benign malformed types and inert marker values to learn parser behavior without invoking operating-system commands, filesystem access, or external callbacks.
3. Test whether type selection, object construction, or nested fields bypass validation or authorization, changing one structural feature per hypothesis.
4. Confirm a security consequence using a harmless property/value in a test-owned fixture; parser exceptions, library fingerprints, and stack traces alone do not prove unsafe deserialization.
5. Preserve sanitized input/output and the affected component/version only when verified. Stop before execution-oriented gadget chains or data access unless a controlled lab and explicit rules of engagement specifically authorize them.


### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture, with a relevant control and a clear trust-boundary failure.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause is not established.
- **Unconfirmed:** the signal is ambiguous, cached, generic, or not tied to a security boundary.
- **Refuted / false positive:** a relevant negative control, valid authorization explanation, or repeatable contradictory evidence explains the signal. Record the attempts; do not claim every theoretical variant was exhausted.
- Status, banners, stack traces, response length, endpoint existence, tool alerts, or frontend state are not sufficient on their own.

### Stop, cleanup, and handoff

Stop at scope boundaries, unexpected real-user data, production side effects, rate-limit/availability degradation, secret exposure, or prohibited action. Clean up disposable state, revoke temporary sessions/tokens when possible, and record status. Return target/scope evidence, baseline, hypothesis, attempts used, impact, controls, verdict/confidence, sanitized evidence, handoff signal, and cleanup status. Trigger a chained skill only when its signal is observed.

## References

- [uphiago/recon-skills — hunt-deserialization](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-deserialization)
- [elementalsouls/Claude-BugHunter — hunt-deserialization](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-deserialization)
- [OWASP — Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)


## Targeted quality-loop enrichment (2026-10-19)

### Parser boundary and inert proof
Identify the exact serialized format, trust source, signature/integrity wrapper, and parser version before choosing a test. First compare valid application-generated input with a malformed but inert structure in a lab/staging fixture; observe parser errors and type handling without gadget payloads, command execution, or access to host files. A stack trace or acceptance of a new object type is only a lead until the security boundary and consequence are reproduced. If untrusted data comes from a partner API or webhook, route the ingestion boundary to unsafe API consumption; if only XML external entities are implicated, route to XXE. Do not treat deserialization RCE as proven without a safe isolated demonstration and direct evidence.


## Practical tooling, references, and helper scripts (2026-10-19)

### Tools that fit this skill
- Browser DevTools, Burp Proxy/Repeater/Comparer, and curl for a replay of one observed request. Verify optional CLIs locally and use only tools exposed by the current runtime.
- Treat CLIs as optional until locally verified; prefer read-only checks. State-changing tests require permission and a disposable fixture.

### Primary resources
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) — test methodology.
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — controlled labs.
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/) — mitigation guidance.

### Small reusable helper
    python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt
Compares local artifacts offline and heuristically redacts common secrets; it sends no requests and cannot prove complete sanitization.

### Evidence and hand-off
- Keep cookies, tokens, reset links, private user data, and secret values out of notes, global research storage, and Git commits. Keep private originals local; share only reviewed derivatives.
- Mark outcomes confirmed, disproven, or still hypothetical. Record tool errors and coverage gaps rather than inventing results.

Compare a known-good baseline with a control, vary one meaningful property, and record alternative explanations before calling a lead confirmed.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Use Burp Repeater for controlled format/type variations and Semgrep for source patterns where authorized code is available. Confirm the serialization format and trust boundary before considering engine-specific lab tooling.

### Installation and setup
- [Burp Suite](https://portswigger.net/burp) — official request inspection.
- [Semgrep](https://semgrep.dev/docs/getting-started/) — optional static analysis.
- Use a disposable local vulnerable lab when engine-specific tooling is needed; inspect source and dependency provenance before installing payload generators.
Do not run gadget chains or command-execution payloads against production to prove a parser issue. Prefer safe type-confusion or integrity markers within approved fixtures.

### Primary resources
- [PortSwigger insecure deserialization](https://portswigger.net/web-security/deserialization) — lab methodology.
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) — defensive patterns.
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) — confirmation and evidence.

### Reusable helper
Run python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt to compare sanitized local artifacts.

### Result handling
Record input format, parser/library/version, controlled marker, observable state/behavior, and plausible mitigation. Parser errors or a suspicious serialized field alone are not proof of code execution.
