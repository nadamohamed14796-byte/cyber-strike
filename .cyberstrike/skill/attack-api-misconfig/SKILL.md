---
name: attack-api-misconfig
description: "Assess API security configuration, mass assignment, method handling, and unsafe object merging"
category: "web-application"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [api, misconfiguration, mass-assignment, prototype-pollution, http-methods]
tech_stack: [http, rest, json, javascript]
prerequisites:
  - "Explicitly authorized API and documented scope"
  - "Controlled test account, baseline request, and bounded request rate"
chains_with: [attack-graphql, attack-idor-automation, attack-jwt, attack-cors, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-api-misconfig/SKILL.md"
  - "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"
---

# API Security Misconfiguration

## When to use

Use when an API accepts structured objects, exposes multiple HTTP methods, behaves differently across content types, returns unexpected fields, or appears to trust client-supplied properties. Keep cryptographic JWT attacks in `attack-jwt` and CORS-specific testing in `attack-cors`.

## Prerequisites and safety

- Confirm the exact API host, endpoints, methods, rate limits, and permitted test class.
- Use a dedicated account and a reversible, low-impact field where possible.
- Never set real users' roles, ownership, billing state, email verification, or security settings.
- Do not treat a successful status code or reflected input as proof of impact.

## Procedure

1. **Capture a baseline.** Save the normal request and response, authenticated principal, content type, and relevant object state.
2. **Inventory writable properties.** Compare documented fields, UI-sent fields, API response fields, and server-side object identifiers. Mark fields that should be server-controlled.
3. **Test property authorization.** In a disposable object, add one harmless unknown property or an inert marker field. Compare the response and subsequent read-back with baseline.
4. **Check mass assignment safely.** Do not submit privilege-bearing fields to a live account. If the program permits a test, use a program-provided test tenant or an explicitly reversible low-impact field. Verify persistence and authorization boundary, not merely response reflection.
5. **Check HTTP method consistency.** Compare only documented or permitted methods against the same harmless resource. Look for inconsistent authorization across GET/POST/PATCH/PUT/DELETE and supported method-override headers. Do not perform destructive verbs on real data.
6. **Check content-type parsing.** Where supported, compare JSON and form encoding using the same inert marker. Record parser differences; do not fuzz uncontrolled payload volumes.
7. **Check unsafe object merging only when a signal exists.** If nested object updates are accepted, use a harmless marker property and check a separate read-only endpoint for changed behavior. Do not attempt command execution or secret extraction on production systems.
8. **Validate server-side enforcement.** Confirm the property or method caused a meaningful unauthorized state or data change, and that it persists beyond the immediate response.
9. **Stop on instability.** Unexpected errors, shared-tenant effects, real data exposure, or rate-limit responses require stopping and documenting the boundary.

## Pitfalls

- An API echoing a submitted field is not proof that the server stored or trusted it.
- A 200/204 response is not proof of authorization failure.
- A client-side hidden field is not itself a vulnerability.
- CORS, JWT signature validation, and object-level authorization have separate canonical skills.
- Do not infer exploitability from a framework name or version.

## Verification

A finding needs a baseline, exact request diff, controlled principal, expected policy, observed semantic effect, and a safe reproducible check. If the effect cannot be confirmed without privileged changes or accessing another person's data, mark it unconfirmed and stop.

## Evidence and output

Record: endpoint, method, content type, test account, field tested, baseline result, changed result, persistence check, scope reference, timestamp, and redaction. Remove cookies, bearer tokens, personal data, and secrets before saving evidence.

## Related skills

- `attack-idor-automation` — object-level authorization.
- `attack-graphql` — GraphQL-specific API surface.
- `attack-jwt` — token validation and claims.
- `attack-cors` — cross-origin policy.
- `attack-triage-validation` — impact and false-positive review.
