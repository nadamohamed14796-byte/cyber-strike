---
name: attack-wordpress
description: "Assess authorized WordPress surfaces, plugins, themes, and configuration with version-aware validation"
category: "platform-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [wordpress, cms, plugins, themes, configuration]
tech_stack: [wordpress, php, http, mysql]
prerequisites:
  - "In-scope WordPress host and approved scan intensity"
  - "Rate limits, target exclusions, and output directory confirmed"
chains_with: [attack-web-recon, attack-web-enumeration, attack-api-misconfig, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-wordpress/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
---

# WordPress Security Assessment

## When to use

Use when reconnaissance confirms WordPress or suggests a WordPress-powered site, plugin/theme surface, REST API, XML-RPC, or exposed backup/configuration files.

## Safety gate

Confirm the host is in scope before active checks. Begin with passive fingerprinting and low-rate requests. Do not attempt password spraying, destructive plugin exploits, file writes, database changes, or denial-of-service tests against production.

## Procedure

1. **Confirm platform evidence.** Check page assets, response headers, common WordPress paths, generator metadata, and REST API behavior. Record confidence and alternate explanations.
2. **Map the exposed surface.** Where permitted, inspect public plugin/theme assets, REST API routes, login surface, XML-RPC behavior, uploads, and public documentation. Avoid broad enumeration when policy forbids it.
3. **Identify components.** Record plugin/theme names and versions only when supported by evidence. Do not infer a vulnerable version from a stale asset or cache.
4. **Review known advisories.** Match component and affected version range to a reputable advisory. Verify the exact preconditions and affected functionality.
5. **Validate safely.** Prefer non-invasive checks or a local reproduction. On a live target, use a harmless read-only proof that confirms the vulnerable behavior without accessing private data or changing site state.
6. **Check access boundaries.** For REST API objects, media, exports, and user-specific endpoints, distinguish public-by-design data from authorization failures; route object tests to `attack-idor-automation`.
7. **Check exposed files carefully.** A path response is not a finding unless its body contains meaningful sensitive content. Do not download large backups or secrets; capture minimal redacted proof.
8. **Report and stop.** Include exact component evidence, advisory link, affected route, preconditions, impact, and whether exploitability was confirmed.

## Pitfalls

- A WordPress fingerprint alone is not a vulnerability.
- Plugin names in JavaScript may be stale or unused.
- A 200 response for a path may be a generic fallback page.
- Public author pages and REST fields can be intentional.
- Do not use exploit code solely because a CVE matches the major version.

## Verification

Confirm platform, component/version evidence, advisory applicability, and meaningful impact. If only fingerprinting or version suspicion exists, label it as an unverified lead rather than a confirmed finding.
