---
name: attack-aspnet
description: "Assess authorized ASP.NET applications for framework-specific configuration and authorization flaws"
category: "platform-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [aspnet, dotnet, web, authentication, configuration]
tech_stack: [aspnet, dotnet, iis, http]
prerequisites:
  - "In-scope application and permission for low-impact validation"
  - "Test account and framework/version evidence"
chains_with: [attack-api-misconfig, attack-idor-automation, attack-auth-bypass, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-aspnet/SKILL.md"
---

# ASP.NET Application Assessment

## When to use

Use when an in-scope application is identified as ASP.NET/.NET or IIS-hosted and framework-specific behavior may affect routing, authentication, serialization, or error handling.

## Safety gate

Do not exploit production framework CVEs without explicit approval. Prefer configuration review, safe version evidence, and test accounts. Never expose machine keys, connection strings, stack traces, or session tokens in reports.

## Procedure

1. Confirm framework evidence from response behavior, static assets, headers, or authorized source/configuration review.
2. Identify authentication and authorization middleware, route constraints, API serialization, and error-handling boundaries where source/configuration is available.
3. Review security-relevant settings such as debug mode, custom errors, cookie flags, request validation, trust boundaries, and secret storage.
4. Match exact version and configuration evidence to vendor advisories; do not infer vulnerability from a server banner alone.
5. Check route and object authorization using controlled accounts; route object-specific cases to `attack-idor-automation`.
6. Test malformed input with small, schema-aware cases to determine whether errors expose sensitive internals or bypass validation.
7. Validate in a lab or staging build when a CVE requires exploit-level proof.
8. Report exact preconditions, impact, remediation, and uncertainty.

## Pitfalls

- IIS hosting does not prove ASP.NET version.
- Verbose errors are information disclosure only when they reveal meaningful sensitive details.
- Framework defaults may be overridden by application or infrastructure configuration.

## Verification

Provide framework evidence, affected route/configuration, expected control, minimal redacted proof, and applicable advisory. Separate configuration concerns from demonstrated exploitability.
