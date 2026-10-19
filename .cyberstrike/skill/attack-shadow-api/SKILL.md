---
name: attack-shadow-api
description: "Identify undocumented, deprecated, version-drifted, and orphaned API surfaces in authorized programs and validate security-control parity."
category: "api-security"
version: "1.0.0"
author: "CyberStrike contributors"
tags: [api, shadow-api, zombie-api, versioning, inventory, authorization]
tech_stack: [rest, graphql, openapi, swagger, gateway, mobile]
chains_with: [attack-web-recon, attack-api-noauth-hunt, attack-schema-enumeration, attack-idor-automation, attack-triage-validation]
sources:
  - "https://owasp.org/www-project-api-security/"
  - "https://owasp.org/www-project-web-security-testing-guide/"
  - "https://spec.openapis.org/oas/latest.html"
---

# Shadow and Zombie API Assessment

## Goal
Build a defensible inventory of undocumented, deprecated, orphaned, or version-drifted API surfaces. An undocumented route responding is not itself a vulnerability.

## Workflow
1. Collect permitted passive evidence from first-party JavaScript and source maps, OpenAPI/Swagger documents, public changelogs, SDKs, mobile traffic supplied by the owner, API gateway route lists available to the tester, and archived URLs allowed by program rules.
2. Normalize candidates by host, method, path template, version, content type, auth context, source, and last-seen evidence. Preserve distinct methods and parameter shapes.
3. Classify each route as current/documented, undocumented active, deprecated, version-drifted, tenant-specific, staging-only, stale, or unverified. Do not infer liveness from a historical URL.
4. Validate read-only routes first. Compare anonymous, low-privilege, and owner-authorized controlled accounts only where permitted. Use synthetic objects and avoid real-user enumeration or bulk collection.
5. Test security-property parity between versions: authentication, object/function/property authorization, tenant isolation, sensitive-field exposure, and abuse controls only where specifically allowed.
6. Compare the same logical operation across versions and transports. Verify whether differences are intentional and documented before assigning impact.
7. Maintain an inventory delta: new routes, removed routes, policy differences, changed schemas, and endpoints discovered in old bundles but not observed in runtime traffic.

## Practical inventory format
```text
method | normalized route | version | source | auth context | role | result | policy difference | impact | evidence | confidence
GET    | /api/v2/profile/{id} | v2 | JS bundle | token | user | observed | pending | none yet | request-ref-12 | lead
```

## Finding gate and chains
A finding needs demonstrated impact, such as unauthorized object access, a privileged function exposed to a lower role, sensitive fields returned without need, or a tenant boundary failure. Chain to endpoint enumeration for discovery, to API-no-auth hunting for missing authentication, to IDOR/BOLA for object-boundary signals, and to schema review for field-level exposure. Continue investigating meaningful version/control differences without a predetermined attempt ceiling; stop when the hypothesis is resolved, no relevant branch remains, or program/safety rules require stopping.

## False positives
- The route is a SPA fallback or returns 404/410.
- The endpoint is intentionally public and has no protected data or action.
- A separate signed client or documented API gateway policy is required.
- The route is stale, dead code, test-only, or inaccessible in the current deployment.
- The older version applies equivalent server-side controls.

## Output
Return a route delta, source provenance, liveness and authentication state, version differences, observed security-control failures, redacted evidence, confidence, and next specialist skill.
