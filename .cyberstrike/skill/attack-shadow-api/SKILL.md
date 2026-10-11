---
name: attack-shadow-api
description: "Discover and validate undocumented API surfaces within an authorized application boundary"
category: "api"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [shadow-api, api-inventory, endpoints, versioning]
tech_stack: [http, rest, graphql, javascript]
prerequisites:
  - "Explicitly authorized domains/apps and permitted discovery intensity"
  - "Client assets, application traffic, or documentation for endpoint provenance"
chains_with: [attack-web-recon, attack-web-enumeration, attack-js-secrets-extraction, attack-api-noauth, attack-idor-automation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-shadow-api/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/recon/api-noauth-hunt/SKILL.md"
---

# Shadow API Discovery

## When to use

Use when client bundles, mobile apps, older API versions, documentation, or observed traffic reveal API endpoints that are not represented in the current official inventory.

## Safety gate

Only enumerate routes on in-scope hosts. Prefer passive extraction from first-party client assets and documented traffic. Do not brute-force broad path dictionaries or access private data to establish endpoint existence.

## Procedure

1. Collect endpoint candidates from in-scope JavaScript, source maps, mobile artifacts, API docs, and controlled application traffic.
2. Normalize scheme, host, path, method, API version, and parameter names; preserve source provenance and timestamps.
3. Deduplicate candidates and classify confidence: referenced by client, observed in traffic, documented, or guessed.
4. Validate a small number of high-confidence candidates with read-only requests and strict timeouts.
5. Compare anonymous and authenticated behavior only where policy allows; use `attack-api-noauth` for authentication hypotheses.
6. Check whether obsolete routes expose different data or authorization behavior using controlled test accounts.
7. Do not infer vulnerability from an undocumented route alone; identify meaningful data or policy failure.
8. Update the inventory with scope decision, evidence, and next-step skill routing.

## Pitfalls

- A string in a bundle may be dead code or a third-party endpoint.
- An old route can be intentionally retained for compatibility.
- A 404/200 difference does not prove sensitive access.
- Do not test guessed endpoints outside scope.

## Verification

Each candidate should include origin/source, scope decision, method, result, auth context, confidence, and whether it needs focused security validation.
