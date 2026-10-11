# External Skill Library Migration

## Goal

Build a cohesive CyberStrike-native skill library from:
- https://github.com/elementalsouls/Claude-BugHunter
- https://github.com/uphiago/recon-skills

This is a staged migration, not a claim that every upstream file has already been imported. Each skill must be reviewed, adapted, checked for duplicates, and validated against the real runtime before it is marked integrated.

## Source inventory

### Claude-BugHunter

The upstream catalog documents 83 skills across web vulnerability classes, enterprise/platform assessment, recon/OSINT, methodology, and reporting/validation. Its repository states that skill content is licensed separately from code. Review NOTICE, LICENSE-CONTENT, and credits before redistributing source-derived material.

### Recon Skills

The upstream library covers authentication/SSO, attack chains, infrastructure, engagement methodology, reconnaissance, vulnerability validation, and reporting. It provides a skill quality baseline and an MIT license. Preserve applicable copyright and license notices for substantial reused portions.

## Migration rules

1. **Inventory first:** record path, name, category, description, revision, source URL, license, and support files.
2. **Compare against CyberStrike:** inspect existing skills and aliases before creating a new name.
3. **Merge duplicates:** consolidate overlapping techniques into canonical skills while preserving meaningful differences.
4. **Adapt, do not blindly copy:** align frontmatter and terminology; remove unverified commands, stale tool references, runtime assumptions, and engagement-specific data.
5. **Safety and scope:** document authorization, boundaries, rate limits, stop conditions, and safe evidence handling.
6. **Runtime truthfulness:** label proposed integrations as contracts until the loader, registry, schemas, and tests confirm them.
7. **Attribution:** retain upstream URLs and applicable license notices.
8. **Validation:** check frontmatter, duplicate names, references, tool/script existence, required sections, and tests before claiming completion.
9. **Batch changes:** group work by methodology/recon, web/API vulnerability classes, auth/identity, infrastructure/cloud, chains, and reporting. Use reviewable pull requests rather than one unreviewable bulk import.

## First migration batches

This branch currently adds 18 CyberStrike-native skill drafts:

**Methodology and reporting**
- attack-bb-methodology
- attack-triage-validation
- attack-evidence-hygiene
- attack-report-writing

**Recon**
- attack-web-recon
- attack-subdomain-enumeration
- attack-port-service-discovery
- attack-web-enumeration
- attack-js-secrets-extraction

**Web vulnerability classes**
- attack-xss
- attack-sqli
- attack-csrf
- attack-file-upload

**Authentication and recovery**
- attack-auth-bypass
- attack-oauth
- attack-saml
- attack-mfa-bypass
- attack-password-reset

These are adapted, attribution-linked drafts. They do not yet prove runtime auto-loading or tool integration. The expanded IDOR skill is tracked in the same feature branch separately.

## Completion criteria

A skill is complete only when its triggers, prerequisites, procedure, verification, pitfalls, and output contract are clear; referenced tools are checked against the repository; cross-references resolve; duplicate functionality is consolidated; attribution is present; a validator/test covers its structure; and loader/routing integration is verified where applicable.

## Sources

- https://github.com/elementalsouls/Claude-BugHunter
- https://github.com/uphiago/recon-skills
- https://github.com/uphiago/recon-skills/blob/main/STYLE.md


## Second migration batch

The following 12 focused drafts were added after the first batch:

- `attack-api-misconfig`
- `attack-ato`
- `attack-business-logic`
- `attack-clickjacking`
- `attack-grpc`
- `attack-cloud-iam`
- `attack-deserialization`
- `attack-api-noauth`
- `attack-wordpress`
- `attack-apk-redteam-pipeline`
- `attack-bugcrowd-reporting`
- `attack-cicd-security`

Their entries have also been added to `.cyberstrike/skill/index.json`, along with the first batch and the expanded IDOR skill, so the index can discover those names. The registry marks these entries `unverified`; this is deliberate. Loader behavior, runtime trigger selection, actual tool availability, and end-to-end tests remain to be verified before these skills can be called fully integrated.


## Third migration batch

Nine more adapted drafts were added and registered in `.cyberstrike/skill/index.json`:

- `attack-captcha-bypass`
- `attack-cloud-misconfig`
- `attack-mcp-security`
- `attack-llm-security`
- `attack-email-security`
- `attack-401-403-bypass`
- `attack-source-leak`
- `attack-firebase-supabase`
- `attack-supply-chain-recon`

These remain `unverified` registry entries until loader behavior, referenced tools, and end-to-end routing have been checked.


## Fourth migration batch

Ten additional adapted drafts were added and registered in `.cyberstrike/skill/index.json`:

- `attack-ldap`
- `attack-k8s`
- `attack-vcenter`
- `attack-m365-entra`
- `attack-okta`
- `attack-brute-force`
- `attack-ntlm`
- `attack-lfi`
- `attack-nosqli`
- `attack-session-management`

These remain `unverified` registry entries until the real runtime loader, tool availability, and end-to-end routing have been checked.
