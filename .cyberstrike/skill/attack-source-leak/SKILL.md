---
name: attack-source-leak
description: "Validate suspected source-code, build-artifact, backup, and configuration leaks with minimal evidence"
category: "recon"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [source-leak, artifacts, backups, configuration, recon]
tech_stack: [http, javascript, git, web]
prerequisites:
  - "In-scope host and explicit permission for content-discovery checks"
  - "Rate limits and a safe output directory"
chains_with: [attack-web-enumeration, attack-js-secrets-extraction, attack-evidence-hygiene, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-source-leak/SKILL.md"
  - "https://github.com/uphiago/recon-skills/blob/main/recon/source-leak-hunt/SKILL.md"
---

# Source and Artifact Leak Assessment

## When to use

Use when source maps, repository metadata, backup files, debug artifacts, environment files, or build outputs appear exposed on an authorized web asset.

## Safety gate

Use bounded requests and do not bulk-download archives, repositories, backups, or configuration files. If sensitive content appears, capture only a minimal redacted excerpt and stop.

## Procedure

1. Confirm the host and path are in scope; check whether the response is a real artifact or a generic application fallback.
2. Inspect publicly referenced source maps, build manifests, repository metadata, and known deployment artifacts using low-rate requests.
3. Validate content type and body. A 200 response is not proof; require meaningful source, repository metadata, internal configuration, or secret-like material.
4. For source maps, determine whether they expose original source or only generated mappings. Do not assume a public client-side API key is secret.
5. For backups/configuration, do not retrieve full files when a short redacted sample establishes exposure.
6. Classify the exposed content: source disclosure, internal path disclosure, credential exposure, personal data, or harmless artifact.
7. If credentials are encountered, do not test or use them. Redact, stop, and report the exposure through the authorized channel.
8. Record URL, response metadata, minimal proof, timestamp, and whether the content was cached or generated dynamically.

## Pitfalls

- Empty files, generic 404 pages, and SPA fallbacks are false positives.
- Public source code does not automatically expose a vulnerability.
- Public identifiers are not automatically credentials.
- Never place discovered secrets in commits, logs, or screenshots.

## Verification

Confirm meaningful content and explain the security impact. Preserve only a minimal redacted excerpt and do not access any data behind discovered credentials.
