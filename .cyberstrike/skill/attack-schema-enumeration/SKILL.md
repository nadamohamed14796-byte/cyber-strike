---
name: attack-schema-enumeration
description: "Assess API schema discoverability and verify whether introspection, documentation, or operation metadata exposes an actual restricted capability."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - api
  - schema
  - graphql
  - openapi
  - introspection
  - authorization
tech_stack:
  - graphql
  - rest-api
  - openapi
  - grpc
  - web
cwe_ids:
  - CWE-200
  - CWE-285
chains_with:
  - attack-graphql
  - attack-grpc
  - attack-bfla
  - attack-information-disclosure
prerequisites: []
severity_boost: {}
---

# API Schema and Operation Enumeration Assessment

## Objective

Inventory exposed GraphQL/OpenAPI/gRPC schema information and distinguish documentation exposure from a security-boundary failure. Schema visibility may be intended; report only a documented policy violation or an independently verified unauthorized operation.

## Testing Methodology

### Phase 1: Identify schema sources

Check in-scope application bundles, OpenAPI/Swagger documents, GraphQL schema endpoints, protobuf files, and gRPC reflection only when the program permits it. Do not brute-force schema paths or enumerate adjacent services.

### Phase 2: Compare anonymous and authenticated visibility

Capture the intended public schema, then compare with a tester-owned authenticated role if available. Record whether the schema itself contains sensitive internal data or merely lists operation names and types.

### Phase 3: Map operations to access policy

For each sensitive mutation or operation, identify documented required roles and a known harmless test fixture. Do not invoke state-changing operations merely because schema metadata reveals them.

### Phase 4: Validate the operation boundary independently

Use a controlled low-privilege test identity to attempt one permitted read-only operation or synthetic-record check. Confirm server-side authorization and authoritative state. Schema introspection alone is not proof that hidden operations can be executed.

### Phase 5: Assess implementation and remediation

Review schema/docs publishing policy, GraphQL resolver guards, gRPC method-level checks, and API gateway filtering. Recommend protecting sensitive docs where appropriate, while enforcing authorization at every operation regardless of visibility.

## What Constitutes a Finding

- **Candidate / lead:** anonymous introspection/docs are enabled or a schema includes privileged operation names.
- **Confirmed information disclosure:** schema metadata contains non-public sensitive fields or internal operational details contrary to policy.
- **Confirmed access-control finding:** a separately tested operation succeeds for an unauthorized identity; schema visibility is supporting context, not the vulnerability itself.
- **Not a finding:** public OpenAPI docs, GraphQL introspection alone, protobuf/reflection availability alone, or discovering a mutation that still enforces authorization.

## Evidence Requirements

- In-scope schema URL/source, timestamp, account role, and authorization policy context.
- Minimal schema excerpt with sensitive names/data redacted when necessary.
- For access control, exact safe operation and test-object before/after or response evidence.
- Explicitly separate metadata exposure from confirmed operation authorization.

## Tools

- **GraphQL tooling:** inspect a bounded schema subset and test-owned operations.
- **OpenAPI parser:** list methods and schema contracts without sending every operation.
- **grpcurl/protoc:** inspect scoped service schemas where reflection/docs are permitted.
- **Source review:** map operation names to guards/permissions and mutation handlers.

## Schema Exposure Decision Matrix

| Surface | Exposure meaning | Confirmation |
|---|---|---|
| OpenAPI/Swagger | Lists operation contracts | Only a policy violation or sensitive field disclosure is a finding |
| GraphQL introspection | Describes types/queries/mutations | Must separately validate resolver auth |
| gRPC reflection | Lists services and method descriptors | Method-level access remains the key control |
| Internal-only fields | Reveals hidden names/types | Sensitivity and intended audience must be established |
| Privileged operation name | Indicates a possible admin function | No impact unless operation boundary fails |
| Schema plus BFLA/IDOR | Helps map a real authorization flaw | Test-owned identities/resources prove restricted access |

**Mitigation:** apply documentation visibility policy, avoid placing secrets in schema descriptions, and enforce authentication/object/function authorization in every resolver, controller, and RPC method.

## Verification and False Positives

- Documentation may be intentionally public to support integration developers.
- A schema shows contract, not whether an operation is callable by the current role.
- Gateway errors can block routes even when a schema lists them; verify actual routing within scope.
- Stop before broad mutation enumeration, real record access, or destructive method execution.

## References

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [GraphQL — Introspection](https://graphql.org/learn/introspection/)
- [OpenAPI Specification](https://spec.openapis.org/oas/latest.html)
- [gRPC Server Reflection](https://grpc.io/docs/guides/reflection/)
