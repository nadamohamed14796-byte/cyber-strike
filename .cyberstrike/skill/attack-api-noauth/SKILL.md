---
name: attack-api-noauth
description: "Check API routes for unintended unauthenticated access and inconsistent access controls"
category: "api"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [api, authentication, authorization, no-auth, rest]
tech_stack: [http, rest, json, graphql]
prerequisites:
  - "Explicit authorization for the API host and documented endpoint scope"
  - "A baseline request and a test account for comparison"
chains_with: [attack-idor-automation, attack-graphql, attack-api-misconfig, attack-triage-validation]
sources:
  - "https://github.com/uphiago/recon-skills/tree/main/redteam"
  - "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
---

# API Unauthenticated Access Assessment

## When to use

Use when routes, API versions, mobile endpoints, GraphQL operations, or alternate content types may be accessible without the authentication the application expects.

## Preconditions and safety

Stay within explicit scope. Begin with read-only endpoints and harmless metadata. Never access real users' private data or invoke account, payment, delete, export, or administrative actions. Keep request volume bounded.

## Procedure

1. **Build a route inventory.** Use in-scope application traffic, API documentation, client-side bundles, and permitted crawling. Record route, method, version, expected role, and data sensitivity.
2. **Capture an authenticated baseline.** For a controlled account, save a successful request and response with secrets redacted.
3. **Repeat without credentials.** Remove cookies and authorization headers, preserving the rest of the request. Compare semantic response content, not just status.
4. **Check alternate paths.** Where discovered in scope, compare versioned routes, trailing-slash variants, alternate HTTP methods, and documented content types. Do not generate large route dictionaries without permission.
5. **Check object-level boundaries separately.** A route that requires login may still have IDOR; use `attack-idor-automation` for that hypothesis.
6. **Validate returned data.** Confirm whether sensitive fields or operations are truly available to an unauthenticated caller. A public configuration or intentionally public catalog may be expected.
7. **Check caching and identity.** If a response may be cached, compare controlled anonymous and authenticated requests without attempting to poison shared caches.
8. **Stop and minimize exposure.** If private information appears, capture only the minimum proof, redact it, and stop further enumeration.

## Pitfalls

- A 200 response with an empty body is not proof.
- Login pages, public health endpoints, public content, and intentionally public metadata may be unauthenticated by design.
- A missing token on one route does not prove other routes share the same behavior.
- Authentication bypass and object authorization are separate controls.

## Verification

Provide route and method, expected authentication policy, redacted anonymous request, meaningful response difference, sensitivity/impact, and reproducibility. Never collect a dataset of exposed records to prove impact.
