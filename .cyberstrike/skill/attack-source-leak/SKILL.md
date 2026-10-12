---
name: attack-source-leak
description: "Assess exposed source repositories, source maps, backups, archives, configuration artifacts, and build outputs without collecting or using leaked secrets."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - source-code
  - source-map
  - backup
  - git-exposure
  - secrets
  - information-disclosure
tech_stack:
  - web
  - javascript
  - git
  - php
  - nodejs
  - cloud-storage
cwe_ids:
  - CWE-200
  - CWE-538
  - CWE-540
chains_with:
  - attack-information-disclosure
  - attack-wordpress
  - recon-methodology
prerequisites: []
severity_boost:
  attack-information-disclosure: "Source leakage is confirmed disclosure when non-public source or operational configuration is readable outside its intended audience."
---

# Source Code and Artifact Exposure Assessment

## Objective

Confirm whether an in-scope host unintentionally exposes source, source maps, VCS metadata, backups, build artifacts, or configuration. Preserve only minimum proof; do not clone/download entire private repositories or test discovered credentials.

## Testing Methodology

### Phase 1: Scope and justify candidate paths

Confirm the hostname is explicitly in scope and derive candidate paths from observed technology, public build references, or owner-provided artifacts. Use a small fixed list; do not recursively fuzz arbitrary paths or probe third-party CDNs without scope.

### Phase 2: Establish content validity

Compare each candidate with a random nonexistent path. For source maps, inspect map headers/JSON structure and sourcesContent presence; for archives, validate file signatures; for Git metadata, check a minimal metadata marker. Avoid retrieving full databases, backup archives, or private repositories.

### Phase 3: Classify source and configuration sensitivity

Determine whether the artifact is public, intended for client delivery, or exposes server-side implementation, private comments, hidden routes, internal names, or configuration. Source maps for delivered client JavaScript may be intentional; server source and secret-bearing config need separate policy checks.

### Phase 4: Handle secrets safely

If a token/password/key is visible, stop reading surrounding content once the leak is established. Record the source location, key name/type, exposure context, and a fully redacted value. Do not test the credential, call its API, or reuse it.

### Phase 5: Check reachability and access control

Compare anonymous and test-account behavior only where appropriate. Verify whether CDN/object policy exposes the artifact or whether authentication is enforced. Do not enumerate sibling bucket objects, repository commits, or directory contents.

### Phase 6: Confirm root cause and cleanup

Identify deployment rules, static-root mapping, archive retention, source-map publication settings, or VCS directory serving. Keep a sanitized PoC and recommend removing the exposed artifact, rotating any secret through the owner's process, and adding deployment checks.

## What Constitutes a Finding

- **Candidate / lead:** .map, .git, backup, archive, source/config path returns a response.
- **Confirmed finding:** genuine non-public source/config/backup content is accessible to an unauthorized in-scope requester.
- **Secret exposure:** report the existence/type and location with value fully redacted; do not prove further access by using the secret.
- **Not a finding alone:** a client-side bundle intentionally served to browsers, a public source repo, a soft-404 response, or a path returning 200 without genuine artifact content.

## Evidence Requirements

- Exact scoped URL, timestamp, request method, anonymous/test role, and negative control.
- File/content signature or minimal excerpt proving the artifact type.
- Source location and exposure mechanism, with secret values/PII redacted.
- Never attach complete private repositories, backup archives, databases, private keys, or usable credentials.

## Tools

- **curl / browser DevTools:** inspect bounded responses and delivered assets.
- **file / unzip -l / JSON parser:** validate artifact signatures/structure without extracting everything.
- **Git metadata checks:** confirm only the minimal marker and stop; do not reconstruct the repository unless specifically authorized.
- **Secret scanning tools:** run locally on already authorized source; suppress full values in output.

## Source and Artifact Exposure Matrix

| Artifact | Validation | Exposure risk |
|---|---|---|
| JavaScript source map | Valid map structure, source list, embedded content | May reveal original client code; secrets are not assumed |
| Server-side source | Genuine language/source marker and non-public route | Internal business logic or unsafe configuration disclosure |
| .git/VCS metadata | Valid minimal metadata signature | Potential source/history exposure; don't clone by default |
| Backup/archive | Valid file signature and small listing if already authorized | May contain private data; do not bulk extract |
| Environment/config file | Genuine assignments and sensitive key names | Potential secrets; values must remain redacted |
| Build/debug artifacts | Deployment-generated debug data | Path, symbol, source, or internal config disclosure |
| Public client bundle | Intended to be shipped to browsers | Public identifiers are not secrets by themselves |

**Mitigation:** exclude VCS and backup paths from web roots, restrict object access, avoid deploying server source/config, gate source-map publication based on risk, rotate exposed secrets, and add artifact scanning to CI/CD.

## Verification and False Positives

- A valid client source map is not automatically a vulnerability; evaluate whether any sensitive information was meant to remain server-side.
- Generic HTML/JSON from an SPA can make nonexistent files appear accessible; use negative controls and file signatures.
- Do not use discovered credentials or keys to confirm impact.
- Stop before downloading full private repositories, archives, databases, mail, or logs with customer data.

## References

- [elementalsouls/Claude-BugHunter — hunt-source-leak](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-source-leak/SKILL.md) — merged source.
- [uphiago/recon-skills — JavaScript secrets extraction](https://github.com/uphiago/recon-skills/blob/main/recon/js-secrets-extraction/SKILL.md) — merged for bundle/source-map review.
- [uphiago/recon-skills — GitHub secret hunting](https://github.com/uphiago/recon-skills/blob/main/recon/github-secret-hunting/SKILL.md) — merged for public repository and history review; secret validation is limited to safe owner-side confirmation.
- [elementalsouls/Claude-BugHunter — public source-leak hunting](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-source-leak) — merged source.

- [uphiago/recon-skills — source leak hunt](https://github.com/uphiago/recon-skills/tree/main/recon/source-leak-hunt)
- [OWASP — Source Code Disclosure](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE-538 — Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)
