---
name: attack-nodejs
description: "Assess authorized Node.js applications for unsafe input handling and security configuration"
category: "platform-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [nodejs, javascript, npm, web, api]
tech_stack: [nodejs, express, npm, http]
prerequisites:
  - "Authorized application and test account"
  - "Framework evidence and bounded input-testing plan"
chains_with: [attack-api-misconfig, attack-prototype-pollution, attack-nosqli, attack-ssti]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-nodejs/SKILL.md"
---

# Node.js Application Assessment

## When to use

Use when a target is identified as Node.js or uses a JavaScript server framework and input parsing, object merging, template rendering, dependency exposure, or error handling is in scope.

## Safety gate

Do not execute arbitrary commands, invoke process-spawning sinks, or access environment secrets on production. Prefer source review, static checks, test fixtures, and harmless markers.

## Procedure

1. Confirm Node.js/framework evidence and identify routes and input formats.
2. Review dependency manifests and lockfiles where authorized; match vulnerable packages to exact affected versions and reachable code paths.
3. Inspect object merge, prototype-sensitive operations, dynamic evaluation, file path handling, template rendering, and child-process boundaries in source when available.
4. Test request parsing and validation with small harmless inputs; compare JSON, form, and query behavior only when supported.
5. Check authorization at API and object boundaries with controlled accounts.
6. Review error responses for stack traces, filesystem paths, and environment details without attempting to read secrets.
7. Validate suspected sink behavior in a local/staging environment. Never test command execution or secret access on production without explicit approval.
8. Recommend strict schemas, safe APIs, patched dependencies, least privilege, and redacted error handling.

## Pitfalls

- A Node.js banner does not identify the exact framework or version.
- A dangerous API call is not automatically reachable from user input.
- Prototype pollution requires a source-to-sink path and meaningful effect.

## Verification

Document input source, server-side sink or control, exact dependency/configuration evidence, reproduction boundary, and impact. Clearly label source-review hypotheses that were not runtime-confirmed.
