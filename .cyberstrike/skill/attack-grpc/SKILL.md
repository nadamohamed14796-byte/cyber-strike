---
name: attack-grpc
description: "Assess authorized gRPC services for exposure, authentication, authorization, and input validation"
category: "api"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [grpc, protobuf, api, authorization, reflection]
tech_stack: [grpc, http2, protobuf, tls]
prerequisites:
  - "Explicitly in-scope gRPC host and permitted test methods"
  - "Approved client tooling, proto definitions or reflection permission, and a controlled account"
chains_with: [attack-idor-automation, attack-api-misconfig, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-grpc/SKILL.md"
---

# gRPC API Assessment

## When to use

Use when reconnaissance identifies gRPC, HTTP/2 services, protobuf definitions, gRPC-Web, or a service that exposes reflection.

## Scope and safety

Confirm host, port, service names, permitted methods, rate limits, and whether test mutations are allowed. Begin with reflection or documented methods only when permitted. Do not enumerate unrelated internal services or invoke state-changing RPCs without explicit authorization.

## Procedure

1. **Identify the protocol.** Record TLS/HTTP2 behavior, content type, server name, and whether the endpoint is standard gRPC or gRPC-Web.
2. **Discover the interface safely.** Use supplied `.proto` files or permitted server reflection. If reflection is disabled, do not treat that as a vulnerability.
3. **Inventory RPC methods.** For each method, note whether it is read-only, state-changing, administrative, streaming, or sensitive.
4. **Establish authentication behavior.** Compare an allowed unauthenticated read-only call with a controlled authenticated call. Never replay another user's credentials.
5. **Check authorization per method and object.** With two controlled accounts if allowed, compare access to objects each account owns. Change one object reference at a time and verify semantic results, not just status codes.
6. **Check validation and resource limits.** Use bounded, schema-valid edge cases, missing required fields, and modest size variations. Avoid oversized messages or high-rate streaming tests that could degrade service.
7. **Check errors and metadata.** Record whether errors disclose internal paths, stack traces, or sensitive metadata. Redact tokens and authorization headers.
8. **Validate findings.** Confirm an actual authorization boundary, data exposure, or unsafe state change. Reflection availability and verbose errors alone require context and impact assessment.

## Pitfalls

- HTTP/2 support does not prove gRPC.
- A method name such as `AdminUpdate` does not prove that the caller can invoke it.
- Reflection may be intentionally enabled for internal development.
- Do not infer impact from a gRPC status alone.

## Verification

Capture the service/method, caller role, request schema, redacted metadata, expected policy, observed semantic effect, and a repeatable low-impact check. Stop if proof would access real user data or change another tenant's state.
