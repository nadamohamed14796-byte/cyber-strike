---
name: attack-springboot
description: "Review authorized Spring Boot applications for actuator exposure and security boundary failures"
category: "platform-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [spring-boot, java, actuator, api, configuration]
tech_stack: [java, spring-boot, http, maven, gradle]
prerequisites:
  - "In-scope application and explicit permission for endpoint checks"
  - "Read-only test account and version/configuration evidence"
chains_with: [attack-api-noauth, attack-api-misconfig, attack-ssrf, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-springboot/SKILL.md"
---

# Spring Boot Application Assessment

## When to use

Use when a target appears to use Spring Boot and management endpoints, application configuration, serialization, or API authorization may be exposed.

## Safety gate

Begin with passive fingerprinting and read-only endpoints. Do not invoke shutdown, heap dump, environment, log-file, or state-changing management operations on production. Treat secrets in management responses as sensitive and stop after minimal proof.

## Procedure

1. Confirm Spring Boot evidence and map publicly reachable application and management routes.
2. Review management endpoint exposure and access control using safe endpoints such as health/info only when permitted.
3. Do not request sensitive actuator endpoints unless explicitly approved; use configuration review or a lab reproduction instead.
4. Check authentication and role enforcement across normal routes and management routes with controlled identities.
5. Review error responses and configuration exposure without collecting credentials or environment variables.
6. Match version evidence to vendor advisories and verify affected conditions.
7. Check API object-level authorization separately from framework fingerprinting.
8. Document endpoint, expected access policy, sanitized response, impact, and remediation.

## Pitfalls

- A health endpoint is often intentionally public.
- Actuator presence does not imply sensitive endpoints are enabled.
- Version strings and generic error pages are not proof of exploitability.

## Verification

Confirm meaningful unauthorized access or a configuration weakness with an impact statement. Redact all environment values, tokens, and internal paths.
