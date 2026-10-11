---
name: attack-web-enumeration
description: "Enumerate web routes and exposed files with scope checks and response validation"
category: "recon"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [web, enumeration, routes, sensitive-files, api-docs]
tech_stack: [http, web, api]
prerequisites:
  - "An HTTP host already validated as in scope"
  - "Program permission for content discovery and a low request-rate budget"
chains_with: [attack-web-recon, attack-js-secrets-extraction, attack-triage-validation]
sources:
  - "https://github.com/uphiago/recon-skills/blob/main/recon/web-enumeration/SKILL.md"
---

# Web Route and Content Enumeration

## When to use

Use after scope and live-host validation to map publicly reachable routes, API documentation, source maps, configuration artifacts, and administrative entry points. Start with normal navigation, robots.txt, sitemap.xml, and public documentation before fuzzing paths.

## Prerequisites

Confirm the allowed host, rate limits, excluded paths, and whether content discovery is permitted. Use bounded wordlists and request timeouts. Keep target-specific response bodies out of the repository.

## Procedure

1. **Capture a baseline.** Request the home page and a deliberately nonexistent path. Record response status, redirect behavior, content type, and body fingerprint so that soft-404s and SPA catch-all responses can be recognized.
2. **Collect known routes.** Review robots.txt, sitemap.xml, public API specifications, links, and application navigation.
3. **Run bounded discovery.** If permitted, use a small wordlist at low concurrency and rate. Stop or reduce activity when rate limiting, instability, or an explicit restriction appears.
4. **Check candidate artifacts.** Paths such as API docs, source maps, repository metadata, debug pages, and environment/configuration files are leads. Do not assume a response is sensitive based on its path or status.
5. **Validate response content.** Compare body length and fingerprints to the baseline. Confirm a genuine file or route exists and inspect only the minimum content needed to establish sensitivity.
6. **Handle sensitive data safely.** If a response contains credentials, personal data, or private source code, do not test the credential, dump more data, or expand access. Preserve minimal redacted evidence and follow program disclosure rules.
7. **Route to a focused skill.** Source maps or JavaScript bundles go to attack-js-secrets-extraction; API specs go to API mapping; a confirmed security boundary failure goes to attack-triage-validation.

## Output contract

Record route, method, status, content type, redirect chain, baseline comparison, confidence, scope decision, and next action. For sensitive responses, store a redacted excerpt only.

## Verification

- Compare against the nonexistent-path baseline.
- Confirm that the body is not a login page, generic SPA shell, or soft-404.
- Verify that the exposed content is actually sensitive and belongs to the target.
- Avoid following redirects outside scope.
- Keep an access-denied response separate from proof that a resource is exploitable.

## Pitfalls

- Treating HTTP 200 as proof of exposure.
- Assuming every source map or config file contains a secret.
- Printing entire responses into terminal logs or reports.
- Using large path lists at high concurrency.
- Attempting to authenticate with discovered credentials without separate permission.
- Confusing a public API specification with an authorization vulnerability.

## CyberStrike integration contract

Verify the real HTTP request tool, scope gate, response-diff logic, rate limiter, and artifact store before runtime integration. If the tool cannot redact sensitive response data, do not persist the raw body automatically.

## Attribution

Adapted from the recon-skills web-enumeration methodology: https://github.com/uphiago/recon-skills/blob/main/recon/web-enumeration/SKILL.md
