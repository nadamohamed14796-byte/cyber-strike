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

## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue with materially distinct, authorized checks while evidence can change the conclusion; deduplicate equivalent queries and retries. Stop when direct evidence resolves the hypothesis, relevant branches are exhausted, a prerequisite is unavailable, or scope/safety requires stopping. Respect program limits and avoid broad enumeration.

Keep an attempt ledger: hypothesis, one variable changed, baseline/control, signal, interpretation, confidence and next branch. Use controlled identities/fixtures, independent corroboration, low-impact requests and minimum sanitized evidence.

### Skill-specific hypothesis order

1. Identify the actual schema mechanism from normal traffic/documentation (GraphQL introspection, OpenAPI, gRPC reflection, or framework route metadata) and confirm it is in scope.
2. Use the smallest read-only query or metadata request to learn reachable operations; bound response size, depth, and request frequency, and avoid recursively enumerating object data.
3. Compare anonymous and test-role visibility of schema metadata separately from access to actual fields/methods; exposed documentation may be intentional and does not prove a data-access weakness.
4. Check whether discovered sensitive operations enforce server-side authorization with a test-owned object and harmless canary, rather than calling every operation.
5. Return normalized operation names, source/provenance, auth requirements, confidence, and relevant next-skill triggers. Redact arguments and stop if results reveal secrets or unrelated private data.

### Verdict gates

- **Confirmed:** repeatable impact at an explicit in-scope boundary is demonstrated with a controlled fixture/identity and relevant control.
- **Likely / needs corroboration:** multiple independent signals support the candidate but the effect or cause remains uncertain.
- **Unconfirmed:** signal is generic, timing/cache-dependent, or not tied to a security property.
- **Refuted / false positive:** a relevant control or valid product/security behavior explains the observation; preserve the test ledger rather than claiming all theoretical vectors were attempted.
- A status code, banner, parser error, timing fluctuation, version string, or scanner alert alone is not proof.

### Safety, cleanup, and handoff

Stop on scope ambiguity, unexpected state changes, sensitive data, service degradation, secret exposure or prohibited actions. Restore synthetic state and revoke temporary credentials/sessions where possible. Report scope proof, baseline, hypothesis, attempt count, impact, controls, verdict/confidence, sanitized evidence and cleanup status. Chain into another skill only after observing its required signal.

## References

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [GraphQL — Introspection](https://graphql.org/learn/introspection/)
- [OpenAPI Specification](https://spec.openapis.org/oas/latest.html)
- [gRPC Server Reflection](https://grpc.io/docs/guides/reflection/)

## Targeted quality-loop enrichment (2026-10-19)

### Schema existence versus operation exposure
Record where the schema came from (public docs, authenticated route, source bundle, introspection, or client descriptor), which principal could read it, and which operations/fields are executable. Compare the same harmless operation across anonymous and controlled roles, then check object/property permissions separately. A schema or introspection response may be intended for developer tooling and does not prove data access. Prioritize undocumented write operations, privileged mutations, deprecated versions, and fields that cross tenant boundaries. Route object references to IDOR, field-level visibility/mutation to API property authorization, cost controls to API resource consumption, and stale versions to shadow-API/inventory review.

## Schema-to-operation trace

Create an inventory row for each discovered operation, but do not call every operation just because it appears in a schema.

| Source | Extract | Validate next |
|---|---|---|
| OpenAPI | Path, method, operationId, security requirements, request/response schema | Compare declared security with runtime on a harmless observed route |
| GraphQL | Query/mutation/subscription names, argument types, field types | Test resolver authorization under controlled roles |
| gRPC/protobuf | Service, RPC method, input/output types, reflection availability | Verify method-level auth only if reflection/RPC tests are in scope |
| JavaScript/mobile client | Actually used operations and field names | Compare observed traffic with published schema; do not infer server support from dead code |
| Error/validation output | Type/field names returned by normal invalid requests | Treat as discovery metadata until actual operation behavior is tested |

### OpenAPI security inventory helper

For a locally saved, authorized OpenAPI JSON file, list paths and declared security without making network requests.

```python
import json
from pathlib import Path

spec = json.loads(Path("openapi.json").read_text())
global_security = spec.get("security", [])
for path, methods in sorted(spec.get("paths", {}).items()):
    for method, operation in sorted(methods.items()):
        if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
            continue
        effective = operation.get("security", global_security)
        print(method.upper(), path, "operationId=", operation.get("operationId"),
              "security_declared=", bool(effective))
```

This reports declared metadata only. It does not prove runtime enforcement, and OpenAPI permits an operation-level security override (including an empty list) that must be interpreted according to the API's intended public/private contract.

### Handoff and deduplication

Deduplicate operations by protocol + method/operation + normalized route/schema version. Keep separate findings only when there is a distinct violated control or impact. Record schema_source, schema_version, visibility_policy, operation_id, declared_security, runtime_auth_result, field_sensitivity, object_policy_result, and next_skill_trigger. If schema parsing fails, preserve the parse error and source provenance; do not label the schema absent.

## Agent-executable CLI tooling, resources, and helper scripts

### Tools and purpose
- `graphql-inspector` — compare GraphQL schemas and report changes when a schema is available.
- `graphql-cop` — optional configuration checks against an explicitly authorized GraphQL endpoint; verify current project maintenance and options first.
- `jq` and `yq` — inspect local JSON/YAML/OpenAPI schema artifacts.
- `python3 .cyberstrike/skill/scripts/normalize_urls.py urls.txt` — normalize locally collected API/schema URLs; it does not contact them.
- Python `httpx` or `curl` — retrieve a documented schema endpoint only when permitted, preserving response and auth context.

### Installation and verification
Follow official docs at https://github.com/GraphQLInspector/graphql-inspector, https://github.com/dolevf/graphql-cop, https://jqlang.org/, and https://github.com/mikefarah/yq. Verify selected binaries with `--version` or `--help`; check the project README for current commands before use. If unavailable, inspect the schema locally and record the gap. Never upload private schemas or traffic to untrusted online viewers.

### Resources
- https://owasp.org/API-Security/editions/2023/en/0x00-header/
- https://portswigger.net/web-security/graphql
- https://spec.graphql.org/
- https://github.com/OAI/OpenAPI-Specification

### Result handling
Use documented or observed APIs and approved schema endpoints only. Record schema source, access context, timestamp, and whether the exposed schema yields a practical security consequence. Public introspection alone may be expected behavior and is not automatically a vulnerability.
