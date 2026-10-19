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

- **curl or Python httpx:** inspect bounded responses and delivered assets for an observed in-scope URL.
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


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue with materially distinct, authorized checks while evidence can change the conclusion; deduplicate equivalent paths and retries. Stop when direct evidence resolves the hypothesis, meaningful branches are exhausted, a prerequisite is unavailable, or scope/safety requires stopping. Never use or test a discovered secret.

Keep an attempt ledger: hypothesis, one variable changed, baseline/control, signal, interpretation, confidence and next branch. Use controlled identities/fixtures, independent corroboration, low-impact requests and minimum sanitized evidence.

### Skill-specific hypothesis order

1. Use a random-path control while checking candidate artifacts such as source maps, repository metadata, backup files, build manifests, debug bundles, or public package registries.
2. Confirm the artifact belongs to the in-scope application and whether it contains source code, internal route names, secrets, or personal data; distinguish a public source map from an actual credential leak.
3. Collect only minimal sanitized snippets/metadata needed to demonstrate exposure. Never reuse a discovered credential, clone unrelated private repositories, or download full data stores.
4. If a credential appears exposed, record provider/type, repository/file/commit, and key name without copying the value. Do not test or use it; notify the owner/program so they can validate and rotate it through their approved process.
5. Report reproducible exposure path, real sensitivity, applicable access boundary, and removal/rotation/cache-invalidation remediation; validate the fix with the same control request.


### Verdict gates

- **Confirmed:** repeatable impact at an explicit in-scope boundary is demonstrated with a controlled fixture/identity and relevant control.
- **Likely / needs corroboration:** multiple independent signals support the candidate but the effect or cause remains uncertain.
- **Unconfirmed:** signal is generic, timing/cache-dependent, or not tied to a security property.
- **Refuted / false positive:** a relevant control or valid product/security behavior explains the observation; preserve the test ledger rather than claiming all theoretical vectors were attempted.
- A status code, banner, parser error, timing fluctuation, version string, or scanner alert alone is not proof.

### Safety, cleanup, and handoff

Stop on scope ambiguity, unexpected state changes, sensitive data, service degradation, secret exposure or prohibited actions. Restore synthetic state and revoke temporary credentials/sessions where possible. Report scope proof, baseline, hypothesis, attempt count, impact, controls, verdict/confidence, sanitized evidence and cleanup status. Chain into another skill only after observing its required signal.

## References

- [elementalsouls/Claude-BugHunter — hunt-source-leak](https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-source-leak/SKILL.md) — merged source.
- [uphiago/recon-skills — JavaScript secrets extraction](https://github.com/uphiago/recon-skills/blob/main/recon/js-secrets-extraction/SKILL.md) — merged for bundle/source-map review.
- [uphiago/recon-skills — GitHub secret hunting](https://github.com/uphiago/recon-skills/blob/main/recon/github-secret-hunting/SKILL.md) — merged for public repository and history review; secret validation is limited to safe owner-side confirmation.
- [elementalsouls/Claude-BugHunter — public source-leak hunting](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-source-leak) — merged source.

- [uphiago/recon-skills — source leak hunt](https://github.com/uphiago/recon-skills/tree/main/recon/source-leak-hunt)
- [OWASP — Source Code Disclosure](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE-538 — Insertion of Sensitive Information into Externally-Accessible File or Directory](https://cwe.mitre.org/data/definitions/538.html)


## Targeted quality-loop enrichment (2026-10-19)

### Secret-like artifact handling
Inventory the artifact type, repository/build path, exposure context, commit/deploy provenance, and exact file/line fingerprint without copying the secret value. Distinguish public identifiers, example keys, revoked credentials, and live secret candidates; never test a candidate against a service or expand access unless the program explicitly permits a dedicated credential validation method. Prefer provider metadata or source-level configuration evidence that shows what the credential is intended to access. A private source map or .git path alone is not automatically critical. Route credential-like exposures to triage with a redacted fingerprint, source maps to JS analysis, and CI artifacts to CI/CD assessment; keep exploitability claims separate from exposed-material facts.


## Artifact validation helpers

Use these only against an explicitly in-scope URL or a local artifact already obtained with authorization. Compare candidate URLs with a random nonexistent path to detect SPA soft-404s. Do not crawl directory listings or download large archives to establish a leak.

```bash
# Capture headers only; fetch a body only after the path is justified and safe.
curl -sS -D artifact.headers -o /dev/null "$IN_SCOPE_CANDIDATE_URL"
grep -iE '^(HTTP/|content-type:|content-length:|content-disposition:|cache-control:|last-modified:)' artifact.headers
```

For a locally available source map, inspect only metadata first:

```python
import json
from pathlib import Path

data = json.loads(Path("app.js.map").read_text())
print("version:", data.get("version"))
print("sources_count:", len(data.get("sources", [])))
print("has_sources_content:", bool(data.get("sourcesContent")))
print("source_names_sample:", data.get("sources", [])[:10])
```

Do not print sourcesContent wholesale; it may contain private implementation details or secret-like values. If sensitive material is suspected, record the file and location, redact the value, and stop reading further than needed.

### Exposure triage fields

Record artifact_kind, canonical_url, response_signature, negative_control, scope_basis, intended_visibility, source_provenance, secret_type_only, secret_value_redacted, minimal_proof_ref, owner_notification_path, and cleanup_or_cache_purge_status. Do not store credentials in the knowledge base, reports, commits, or logs.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Use ripgrep for exact local string searches, Gitleaks for secret-pattern triage over authorized local source/assets, and Burp/browser DevTools to verify whether a suspected exposed artifact is publicly retrievable. Secret scanners are noisy and their output must be treated as sensitive.

### Installation and setup
- [Gitleaks official releases/install](https://github.com/gitleaks/gitleaks) — use release binaries or documented package instructions.
- [TruffleHog documentation](https://docs.trufflesecurity.com/) — optional secret-scanning alternative; prefer local scanning and review how the selected mode handles data.
- Kali/Debian: `sudo apt update && sudo apt install ripgrep`.
Do not paste discovered key values into tickets, chat, or global research. Never validate a token by using it against a service; report the fingerprint/location to the authorized owner and rotate exposed credentials through approved processes.

### Primary resources
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) — handling and remediation.
- [Gitleaks](https://github.com/gitleaks/gitleaks) — local scanning behavior.
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) — disclosure validation.

### Reusable helper
`python3 .cyberstrike/skill/scripts/js_endpoint_inventory.py ./javascript` extracts route candidates from local assets and avoids printing source lines; it is not a secret verifier.

### Result handling
Store file/hash/location and a redacted fingerprint, not the value. Distinguish a placeholder, public identifier, expired credential, and credible secret without attempting unauthorized use.

## Agent-executable CLI tooling, resources, and helper scripts

Use agent-executable CLI tools and local scripts; browser interfaces, extensions, and interactive intercepting proxies are not dependencies. Check tool presence/version and official documentation before running it; only process data the operator is authorized to inspect.

### Recommended tools
- gitleaks — local secret scanning
- noseyparker — secret detection across local text and history
- git — inspect exposed repository metadata in authorized scope
- jsluice — local JS route/secret-pattern candidates

### Resources
- https://github.com/gitleaks/gitleaks
- https://github.com/praetorian-inc/noseyparker
- https://github.com/BishopFox/jsluice
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids; verify project maintenance, license, and supported behavior from official sources.

### Helper-script contract
Store finding type, file/path, line/offset, commit, detector, and redacted fingerprint only. Never print, use, or submit discovered credential values; prioritize reporting/rotation guidance.

Keep raw artifacts separate from normalized output. Preserve provenance, timestamp, tool/version, detector/rule, error state, confidence, redaction, and evidence path. Use JSON/JSONL when useful and test redaction on local fixtures.

### Handoff
Return actual commands and versions, inputs/outputs, records processed, redaction status, errors, confidence, limitations, and next skill. Never include live secrets in notes or reports.
