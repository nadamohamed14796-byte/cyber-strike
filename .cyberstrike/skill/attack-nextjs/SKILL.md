---
name: attack-nextjs
description: "Assess Next.js route handlers, middleware, server actions, rendering boundaries, and deployment configuration for authorization and data exposure defects."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - nextjs
  - react
  - rsc
  - server-actions
  - middleware
  - web
tech_stack:
  - nextjs
  - react
  - nodejs
  - typescript
  - app-router
  - pages-router
cwe_ids:
  - CWE-285
  - CWE-200
  - CWE-79
  - CWE-918
chains_with:
  - attack-bfla
  - attack-idor-automation
  - attack-xss
  - attack-ssrf
prerequisites: []
severity_boost:
  attack-bfla: "A missing guard on a server action or route is a function-level flaw only when a lower-role test identity performs the restricted operation."
---

# Next.js Application Security Assessment

## Objective

Identify trust-boundary issues in Next.js apps spanning Server Components, Server Actions, Route Handlers, middleware, API routes, and static assets. Use owned accounts and test records; treat framework-specific behavior as a hypothesis until the server-side boundary is demonstrated.

## Testing Methodology

### Phase 1: Identify app architecture and version

Use package metadata supplied by the program, source manifests, build output, and response headers to determine App Router versus Pages Router, runtime, middleware, and deployment platform. Avoid inferring an exact version from a banner alone.

### Phase 2: Map handlers and authorization gates

Inventory Route Handlers, API routes, Server Actions, middleware matchers, and server-only modules. Check whether each sensitive action performs server-side authentication and object/role authorization; a protected page or hidden button is not a control on the underlying handler.

### Phase 3: Check server/client data boundaries

Review Server Component props, RSC payloads, serialized action state, public environment variables, and client bundles for private data or secrets. Record names and truncated indicators only; never print full tokens/API keys. Confirm that data is intended to be client-visible.

### Phase 4: Validate cache and rendering context

Inspect static/dynamic rendering, revalidation, user-specific responses, cache headers, and CDN behavior with synthetic accounts. Confirm one test user's private response cannot be replayed to another test user. Do not poison shared production caches.

### Phase 5: Review middleware and route normalization

Check middleware matchers and exclusions, redirects/rewrites, basePath/locales, and alternate HTTP methods. A route outside a matcher is a lead; confirm the handler's own authorization with a minimal test request rather than trying large bypass lists.

### Phase 6: Check URL fetch, image, and upload features

Review remote image allowlists, redirects, metadata previews, document rendering, and upload serving origins. Use harmless controlled hosts/test files; never probe internal cloud metadata or submit active payloads to production.

### Phase 7: Confirm with test identities and source trace

Compare anonymous, owner, and lower-role behavior for a synthetic record. For write actions, use disposable data and explicit permission. Trace the vulnerable path to framework code/config and remove test artifacts afterward.

## What Constitutes a Finding

- **Candidate / lead:** sensitive code appears in a client bundle, route is outside middleware matching, Server Action is discoverable, or user-specific response looks cacheable.
- **Confirmed finding:** a server-side route/action exposes private test data or performs a restricted action for an unauthorized test identity, or a verified response cache crosses test-account boundaries.
- **Not a finding:** public environment identifiers, action/route names, RSC internals, missing middleware match, or a 200 response without a security-boundary failure.

## Evidence Requirements

- App Router/Pages Router context, deployed version evidence, route/action, timestamp, and role.
- Matched requests for two tester-controlled accounts and a synthetic object; include before/after state for authorized mutations.
- Sanitized RSC/JSON response shape and relevant cache headers; redact secrets and personal data.
- Source/config trace showing authorization, cache, or server/client boundary.

## Tools

- **Browser DevTools / Burp:** capture RSC, action, and route-handler exchanges.
- **Source search:** locate server actions, route handlers, matcher config, server/client imports, and public env usage.
- **Next.js official documentation/security advisories:** verify version/runtime behavior.
- **Synthetic test accounts:** validate authorization and cache separation.

## Next.js Trust-Boundary Matrix

| Surface | Review | Confirmation |
|---|---|---|
| Server Actions | Per-action authentication/authorization and input validation | Unauthorized test account cannot invoke sensitive action |
| Route Handlers/API routes | Every method and path has server-side guards | Controlled restricted operation actually succeeds without permission |
| Middleware matcher | Exclusions, rewrites, locale/basePath variants | Handler itself lacks protection; matcher gap alone is not enough |
| RSC/Server Components | Private props, serialized payloads, server-only modules | Non-public test data reaches unauthorized client |
| Cache/revalidation | User-specific API/page cached across identities | Second test account receives first account's synthetic response |
| Environment values | NEXT_PUBLIC client exposure vs server-only secrets | Private secret value is truly bundled/exposed; capture only type/name |
| Image/proxy/upload | Remote origin allowlist, redirects, serving headers | Controlled safe object crosses intended origin/permission boundary |

**Mitigation:** authorize every server action/handler, validate inputs server-side, keep secrets in server-only modules, mark user-specific responses non-shared-cacheable, and apply safe allowlists to URL-fetch/upload features.

## Verification and False Positives

- Server Action identifiers are not authorization secrets; the invoked function must enforce permissions itself.
- RSC payloads may contain UI serialization that is expected to be visible; confirm whether the field is private.
- Middleware is defense-in-depth and can intentionally exclude static/public routes; evaluate the actual handler.
- CDN/cache headers may be transformed by deployment layers; compare real responses under test accounts.
- Stop before active cache poisoning, production SSRF to internal services, or writes outside disposable test records.


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Treat the attempt budget as a ceiling for independent, evidence-producing hypotheses, not a payload quota. If the signal remains plausible, follow the next relevant branch up to 20 distinct hypotheses; stop earlier when impact is decisive, the branch is irrelevant, or scope/safety limits apply. Cosmetic variations of one request are not independent attempts.

Track each attempt as: hypothesis, one changed variable, baseline/control, observed signal, interpretation, confidence, and next branch. Use controlled identities or synthetic resources, preserve only minimal evidence, and redact secrets.

### Skill-specific hypothesis order

1. Identify the deployed router/runtime mode (App Router or Pages Router, server/client component boundaries, API routes, and middleware) from reliable evidence; version strings alone are insufficient.
2. Compare server-side route authorization with client-side navigation protections, including API handlers, server actions, middleware, and data-fetching endpoints relevant to the same resource.
3. Check for accidentally exposed source maps, build artifacts, debug data, and environment values using random-file controls; redact secrets immediately.
4. Use controlled roles and test-owned records to verify that data fetched on the server is authorized before serialization to the client; do not assume hidden components are protected APIs.
5. Capture the exact route/runtime and proof of data/action exposure, then recommend server-side authorization, safe environment-variable exposure, and build-time regression checks.


### Verdict gates

- **Confirmed:** repeatable security impact is shown against an in-scope resource using a tester-controlled identity or fixture, with a meaningful control.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause is not yet established.
- **Unconfirmed:** observations are ambiguous, cached, generic, or not tied to a security boundary.
- **Refuted / false positive:** a relevant negative control or valid policy/implementation explanation accounts for the observation; document the attempts instead of claiming all imaginable variants were exhausted.
- Do not treat status codes, error text, response length, decoded tokens, static findings, or UI state alone as proof.

### Stop, cleanup, and handoff

Stop at scope uncertainty, unrelated sensitive data, unexpected production changes, service degradation, secret exposure, or prohibited actions. Restore disposable state and revoke test tokens/sessions where possible. Return the scope proof, baseline, hypothesis, attempt count, impact, controls, confidence/verdict, sanitized evidence pointers, relevant handoff signal and cleanup status. Chain into another skill only when its trigger is present.

## References

- [uphiago — hunt-nextjs](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-nextjs)
- [Claude-BugHunter — hunt-nextjs](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-nextjs)
- [Next.js Security Documentation](https://nextjs.org/docs/app/building-your-application/configuring/content-security-policy)
- [Next.js Server Actions](https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations)
