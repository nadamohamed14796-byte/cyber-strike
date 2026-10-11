---
name: attack-nextjs
description: "Assess authorized Next.js applications for routing, server/client boundaries, and cache isolation"
category: "platform-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [nextjs, react, ssr, server-actions, cache]
tech_stack: [nextjs, react, nodejs, http]
prerequisites:
  - "Authorized application and test accounts for relevant roles"
  - "Permission for low-impact route and cache behavior checks"
chains_with: [attack-web-recon, attack-api-noauth, attack-idor-automation, attack-cache-poison]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-nextjs/SKILL.md"
---

# Next.js Application Assessment

## When to use

Use when reviewing a Next.js application with server-side rendering, route handlers, server actions, middleware, client/server data boundaries, or caching.

## Safety gate

Use controlled accounts and non-sensitive test records. Do not poison shared production caches, trigger destructive server actions, or access other users' private pages as proof.

## Procedure

1. Confirm Next.js evidence and map app routes, API handlers, middleware, server actions, and static/dynamic rendering behavior.
2. Compare anonymous and authenticated responses for a controlled test record; inspect whether user-specific data is cached or shared.
3. Review authorization at server actions and route handlers rather than relying on hidden client components or middleware alone.
4. Check redirects and middleware normalization with a few documented route variants.
5. Inspect build artifacts and source maps only where in scope; public build output does not itself prove a vulnerability.
6. Validate cache isolation using two controlled accounts and harmless synthetic content; avoid shared-cache poisoning payloads.
7. Review framework version and advisories against exact deployment configuration.
8. Capture minimal evidence, including cache headers, route, role, and state, with secrets redacted.

## Pitfalls

- A hidden button or client-side route guard is not the server authorization boundary.
- A cache header alone does not prove cross-user data leakage.
- Server actions can be intentionally public but must enforce their own policy.

## Verification

Demonstrate a repeatable route, authorization, or cache-isolation failure with controlled accounts and synthetic data. State whether the result is confirmed or only a configuration concern.
