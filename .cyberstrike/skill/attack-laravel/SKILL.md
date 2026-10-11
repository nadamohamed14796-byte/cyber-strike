---
name: attack-laravel
description: "Review authorized Laravel applications for route, middleware, configuration, and authorization weaknesses"
category: "platform-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [laravel, php, framework, web, configuration]
tech_stack: [laravel, php, composer, http]
prerequisites:
  - "Authorized Laravel application and permitted test account"
  - "Version evidence or access to sanitized configuration"
chains_with: [attack-idor-automation, attack-api-misconfig, attack-source-leak, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-laravel/SKILL.md"
---

# Laravel Application Assessment

## When to use

Use when an authorized target appears to use Laravel and routing, middleware, debug behavior, storage, serialization, or API resource authorization may be relevant.

## Safety gate

Use low-impact checks and test accounts. Do not retrieve `.env` files, application keys, database credentials, or production logs. Do not run framework exploit code against a live target without explicit approval.

## Procedure

1. Confirm Laravel evidence and collect version information only from reliable sources.
2. Review route definitions and middleware in authorized source/configuration when available; identify routes that should require authentication or a specific role.
3. Check debug/error behavior with harmless malformed requests and confirm whether meaningful secrets or internal paths are exposed.
4. Review file storage and public disk configuration; test only synthetic files and do not download private uploads.
5. Check object-level authorization on API resources using controlled accounts and dedicated test records.
6. Review mass assignment and validation boundaries in update flows using harmless fields; never change privileged fields on production accounts.
7. Match component versions to advisories and validate exact preconditions in a lab where possible.
8. Capture redacted evidence and recommend middleware, policy, validation, and secret-management fixes.

## Pitfalls

- A Laravel fingerprint does not prove a vulnerable version.
- A public storage directory can be intentional.
- Debug output is not a finding unless sensitive information is exposed.

## Verification

State the evidence for framework identification, route and principal context, expected behavior, actual result, impact, and confidence. Avoid claims based on generic error pages.
