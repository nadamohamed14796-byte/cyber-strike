---
name: attack-js-secrets-extraction
description: "Analyze in-scope JavaScript bundles and source maps for routes, configuration, and accidentally exposed secrets"
category: "recon"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [javascript, source-maps, secrets, api, recon]
tech_stack: [javascript, http, spa, api]
prerequisites:
  - "A validated in-scope web application"
  - "Permission to download and inspect publicly served application assets"
chains_with: [attack-web-recon, attack-web-enumeration, attack-triage-validation, attack-evidence-hygiene]
sources:
  - "https://github.com/uphiago/recon-skills/blob/main/recon/js-secrets-extraction/SKILL.md"
---

# JavaScript Bundle and Source-Map Analysis

## When to use

Use for an in-scope SPA or web application when public JavaScript bundles may reveal routes, API base URLs, feature flags, source maps, or configuration that helps focus authorized testing.

## Prerequisites

Confirm asset scope and permitted download volume. Use a local workspace with restricted access. Verify installed tools and avoid uploading proprietary bundles to public analysis services unless explicitly approved.

## Procedure

1. **Collect the bundle URLs.** Start from script references in the authorized application and follow only same-scope or explicitly allowed asset hosts.
2. **Download selectively.** Use timeouts and a small request rate. Deduplicate by URL and content hash; avoid repeated downloads of identical bundles.
3. **Extract route and API hints.** Search for route definitions, API base URLs, GraphQL endpoints, feature flags, sourceMappingURL directives, and public configuration variables.
4. **Inspect source maps safely.** Check whether a referenced map is available, then inspect source paths and embedded source content locally. Treat source maps as source disclosure leads, not automatic vulnerabilities.
5. **Classify possible secrets.** Separate intentionally public client identifiers from credentials capable of privileged access. A string matching a key pattern is only a candidate until its intended exposure and impact are understood.
6. **Do not use discovered credentials.** Never validate a key by accessing a service, reading data, or changing state unless the program explicitly authorizes that exact test. Prefer provider documentation and minimal redacted evidence; report suspected exposure according to policy.
7. **Map routes to hypotheses.** Link each endpoint to its source bundle and code context. Route object identifiers to IDOR/BOLA, URL-fetch functionality to SSRF, auth flows to the appropriate auth skill, and dangerous client sinks to XSS review.
8. **Redact and retain minimally.** Keep only the snippets needed to prove a claim. Do not commit bundles, secrets, tokens, personal data, or target-specific findings.

## Output contract

Record asset URL, hash, bundle/map relationship, discovered routes, API hosts, candidate configuration values, classification, confidence, evidence pointer, and next authorized check. Store sensitive material only in approved local evidence storage.

## Verification

- Confirm a candidate string is present in the served target asset.
- Determine whether the value is designed to be public or is a secret.
- Verify the associated privilege/impact from documentation or approved evidence.
- Exclude placeholders, test fixtures, stale bundles, and false-positive regex matches.
- Keep credential functionality unverified if validating it would exceed scope.

## Pitfalls

- Treating every API key or client ID as secret.
- Using exposed credentials to enumerate or extract data.
- Assuming a source map is sensitive without inspecting its content.
- Publishing raw bundles or secrets in logs, reports, or Git history.
- Combining routes from unrelated third-party scripts with the target's own API surface.

## CyberStrike integration contract

Verify the actual asset fetcher, URL scope filter, bundle parser, secret redactor, evidence store, and skill router before runtime integration. The skill should produce hypotheses and evidence references; it must not automatically exercise discovered credentials.

## Attribution

Adapted from the recon-skills JavaScript secrets-extraction methodology: https://github.com/uphiago/recon-skills/blob/main/recon/js-secrets-extraction/SKILL.md
