---
name: attack-grpc
description: "Assess gRPC service exposure, authentication, authorization, reflection, and message validation using scoped test clients and synthetic requests."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - grpc
  - protobuf
  - api
  - authorization
  - schema
tech_stack:
  - grpc
  - protobuf
  - http2
  - go
  - java
  - dotnet
cwe_ids:
  - CWE-306
  - CWE-285
  - CWE-20
chains_with:
  - attack-bfla
  - attack-idor-automation
  - attack-schema-enumeration
prerequisites: []
severity_boost:
  attack-bfla: "An exposed gRPC method becomes BFLA when a lower-privilege test identity invokes a function the server should deny."
---

# gRPC Service Security Assessment

## Objective

Map and validate gRPC methods, message constraints, TLS, authentication, and authorization in an explicitly scoped service. Use test accounts and disposable records; do not mass-call methods or invoke destructive RPCs.

## Testing Methodology

### Phase 1: Confirm scope and transport

Establish exact hostname/port, TLS expectations, public/internal status, and methods in scope. Confirm authority and HTTP/2 routing; do not scan adjacent infrastructure.

### Phase 2: Inventory service methods

Use published proto files, client bundles, API docs, or explicitly permitted reflection. Record service/method, message schema, auth requirements, and read/mutate behavior. Reflection alone is not a vulnerability.

### Phase 3: Establish baselines

For safe read methods, capture one valid request and one malformed/missing-field variant. Use synthetic identifiers and note gRPC status/trailers and server-side identity.

### Phase 4: Test authorization and validation

Replay a harmless method as a lower-privilege test account and vary one object identifier or type. Use disposable records for writes only when permitted. Check backend authorization, not just gateway policy.

### Phase 5: Review metadata and TLS

Check error disclosure, metadata handling, and TLS validation. Redact credentials and never send live tokens outside the approved client.

## What Constitutes a Finding

- **Candidate / lead:** reflection is available, method appears unguarded, or malformed protobuf yields a server error.
- **Confirmed finding:** unauthorized test identity invokes a protected method, accesses another tester-owned fixture, or bypasses documented validation.
- **Not a finding:** reflection alone, expected gRPC status, or malformed request correctly rejected.

## Evidence Requirements

- Target service/port, TLS state, service/method, client version, timestamp.
- Sanitized request and gRPC status/trailers; redact metadata and credentials.
- Role and synthetic object ownership with expected/observed outcome.
- Identify proto provenance and whether inventory came from docs or reflection.

## Tools

- **grpcurl:** invoke specific in-scope methods with bounded timeouts.
- **grpcui:** explore documented test services where permitted.
- **protoc/proto files:** inspect message and service schemas.
- **HTTP/2-aware proxy:** capture gateway behavior where supported.

## gRPC Method Coverage Matrix

| Surface | Review | Evidence |
|---|---|---|
| Reflection | Is introspection intended and limited? | Exposure alone is informational absent policy violation |
| Unary read RPC | Identity/object authorization | Same synthetic object under two test roles |
| Mutating RPC | State and permission checks | Disposable record and post-state verification |
| Streaming RPC | Authentication and per-message validation | Small controlled stream; no stress testing |
| Metadata | Token handling/error details | Redacted capture only |
| TLS/HTTP2 | Certificate validation and plaintext exposure | Handshake evidence for scoped endpoint |

**Mitigation:** restrict reflection where appropriate, require TLS, authenticate/authorize each method, validate messages at trust boundaries, and test method-level access.

## Verification and False Positives

- A gateway may expose only a documented subset of service methods; validate policy and actual routing.
- Reflection does not imply method access.
- Invalid protobuf rejection is normal, not DoS proof.
- Stop before large streams, high concurrency, resource exhaustion, or unauthorized state-changing RPCs.


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Treat the attempt budget as a ceiling for independent, evidence-producing hypotheses, not a payload quota. If the candidate remains plausible, follow the next signal-led branch up to 20 distinct hypotheses; stop sooner when impact is decisive, no relevant branch remains, or scope/safety limits apply. Cosmetic encodings of the same request do not count as separate attempts.

Maintain an attempt ledger: hypothesis, single changed variable, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer controlled identities, synthetic resources and paired requests. Preserve sanitized evidence and minimize data collected.

### Skill-specific hypothesis order

1. Confirm the in-scope host, transport (TLS/plaintext), and gRPC service/method names from allowed client traffic or published protos; do not scan unrelated ports.
2. Establish valid and unauthenticated baselines for one read-only method, then compare an expired token and a least-privileged test identity.
3. Check method-level authorization and object ownership using only synthetic identifiers; when reflection is enabled, distinguish intentional development discovery from exposed sensitive capability.
4. Validate input constraints with benign type/length boundary values and low request volume; do not send oversized messages or high-rate streams that could exhaust resources.
5. Capture sanitized status/trailers, method, principal, request schema/version, and control result. Confirm the denied operation is genuinely forbidden and propose a method-level policy regression test.


### Verdict gates

- **Confirmed:** repeatable security impact is demonstrated against an explicitly in-scope resource using a tester-controlled identity or fixture and a relevant control.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause remains uncertain.
- **Unconfirmed:** response is ambiguous, cached, generic, or not linked to a security boundary.
- **Refuted / false positive:** an applicable negative control or valid policy explanation accounts for the signal. Record the attempt ledger rather than claiming every theoretical variant was exhausted.
- A 2xx status, error difference, header, schema/documentation exposure, scanner alert, or UI-only state is not proof by itself.

### Stop, cleanup, and handoff

Stop on scope ambiguity, unexpected real-user data, unexpected production state changes, service degradation, credential exposure, or a prohibited action. Restore disposable state and revoke temporary tokens/sessions where possible. Handoff target and scope proof, baseline, hypothesis, attempts used, impact, negative controls, verdict/confidence, sanitized evidence pointers, linked-skill signal, and cleanup status. Invoke a related skill only when its triggering signal is observed.

## References

- [uphiago — hunt-grpc](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-grpc)
- [Claude-BugHunter — hunt-grpc](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-grpc)
- [gRPC Authentication Guide](https://grpc.io/docs/guides/auth/)
