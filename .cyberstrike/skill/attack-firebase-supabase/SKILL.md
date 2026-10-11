---
name: attack-firebase-supabase
description: "Assess Firebase and Supabase data access rules and client-exposed configuration safely"
category: "cloud-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [firebase, supabase, database, authorization, cloud]
tech_stack: [firebase, firestore, realtime-database, supabase, postgres]
prerequisites:
  - "Explicit authorization for the project and its data services"
  - "Test project or controlled test records; read-only access preferred"
chains_with: [attack-cloud-misconfig, attack-api-noauth, attack-idor-automation, attack-triage-validation]
sources:
  - "https://github.com/uphiago/recon-skills/blob/main/recon/firebase-supabase-attack/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/redteam/hunt-firebase/SKILL.md"
---

# Firebase and Supabase Authorization Assessment

## When to use

Use when an authorized web/mobile app uses Firebase, Firestore, Realtime Database, Supabase, or related client SDKs and database APIs.

## Safety gate

Confirm project ownership and exact scope. Use a dedicated test project or synthetic records whenever possible. Never enumerate real users, download whole tables, or change production rules as a test.

## Procedure

1. Identify the platform from client SDK usage, public configuration, API hosts, and application behavior. Public project identifiers or anon keys are not automatically secrets.
2. Locate the relevant data services and document expected read/write access for anonymous, authenticated, and privileged users.
3. Review rules/policies when source or console access is authorized; record version and effective policy.
4. Use harmless test records to compare anonymous and authenticated reads, writes, and deletes only where explicitly allowed.
5. For Supabase, review row-level security and grants; verify that API exposure does not bypass intended tenant filters.
6. For Firebase, review security rules at the actual database/document path and consider inherited or overlapping match rules.
7. Test object/tenant boundaries using controlled identities and synthetic records. Route object-level cases to `attack-idor-automation`.
8. Verify whether data is actually exposed or modified; do not rely on a client configuration value, status code, or SDK name alone.
9. Restore synthetic records and redact project identifiers where required.

## Pitfalls

- Client-visible configuration is often designed to be public.
- A rule snippet may not reflect effective deployed policy.
- Anonymous read access can be intentional for public content.
- Do not test against real personal records or alter production policy.

## Verification

Provide platform, resource path, test identity, expected policy, minimal redacted request/response, demonstrated access boundary, and cleanup result.
