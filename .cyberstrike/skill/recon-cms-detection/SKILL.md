---
name: recon-cms-detection
description: "Fingerprint CMS platforms, versions, themes, plugins, and exposed administrative surfaces using corroborated passive and low-impact signals."
category: "recon"
version: "1.0.0"
author: "cyberstrike-official"
tags: [recon, CMS, WordPress, Drupal, Joomla, fingerprinting]
tech_stack: [HTTP, HTML, JavaScript, DNS]
chains_with: [recon-methodology, attack-wordpress, attack-source-leak, attack-information-disclosure]
prerequisites: []
severity_boost: {}
---

# CMS and Component Fingerprinting

## Objective

Identify the content-management platform and relevant extensions accurately enough to prioritize version-specific security review, while distinguishing fingerprints from confirmed vulnerabilities.

## Scope

- Requires a confirmed, organization-owned web application (output of `recon-methodology` or a program-provided target list). Do not fingerprint third-party widgets, embedded SaaS login providers, or CDN infrastructure that only happens to be reachable from the target.
- Passive and low-impact active checks only: normal page loads, published readme/changelog files, and documented API endpoints. No credential guessing against login or admin routes — that belongs to a dedicated authentication-testing skill.
- Component-inventory brute forcing (large wordlists against plugin/theme directories) is a last resort; prefer passive evidence first and keep any active enumeration low-rate and clearly logged.

## Methodology

### 1. Collect baseline signals

Inspect HTML generator metadata, static asset paths, common CMS directories, login routes, response headers, cookies, JavaScript globals, and robots/sitemap entries. Capture a normal page and a random-path control to account for custom error pages and single-page application fallbacks.

### 2. Corroborate platform identity

Use at least two independent indicators such as asset paths plus a CMS-specific API response. Consider reverse proxies, custom themes, removed generator tags, and headless CMS architectures. Record confidence instead of forcing a single platform label.

### 3. Fingerprint versions cautiously

Use static asset versions, readme/changelog files where publicly served, API metadata, source maps, and known release-specific behavior. A version string can be stale or intentionally altered; confirm with a second signal before associating an application with a vulnerable release.

### 4. Inventory extensions and integrations

Review public plugin/theme asset paths, frontend bundles, REST routes, GraphQL schemas, and references in source code. Prioritize components that are reachable and materially affect authentication, file handling, template rendering, or data access. Avoid brute forcing large extension lists when passive evidence is sufficient.

### 5. Verify the security condition

Map a confirmed component/version to a credible advisory, then verify the vulnerable precondition and affected code path with a minimal non-destructive test. A component being outdated is not automatically a reportable exploitable issue without impact and applicable policy.

## What This Produces

- CMS and framework fingerprint with confidence notes.
- A component inventory tied to observed evidence.
- Candidate advisories requiring applicability verification.
- A prioritized list of safe follow-up tests.

## Evidence Requirements

- Response excerpts or asset paths that establish the fingerprint.
- Version evidence and a corroborating signal.
- Advisory identifier and exact affected-version range for any vulnerability claim.
- A minimal proof of the security condition, with secrets and user data redacted.

## Tools

- Browser DevTools, curl, Burp Suite, and HTML/JavaScript inspection.
- CMS-specific passive fingerprinting tools.
- Public vendor advisories, changelogs, and vulnerability databases.
- Local scripts to normalize asset URLs and compare response fingerprints.

## Fingerprint Confidence Matrix

| Signal | Confidence | Caveat |
|---|---|---|
| Generator metadata | Low to medium | May be removed or spoofed |
| CMS-specific asset directory | Medium | Custom sites can reuse paths |
| CMS API response with platform schema | High | May be intentionally public |
| Multiple independent component assets | Medium to high | Assets may be cached or copied |
| Version query parameter | Low | Often stale and not authoritative |
| Public readme/changelog | Medium | May not match deployed code |
| Confirmed behavior unique to release | High | Requires careful, non-destructive verification |

## Verification and False Positives

- Compare candidate paths with a random nonexistent path to detect catch-all responses.
- Distinguish a headless frontend from the CMS origin.
- Treat plugin names and version strings as leads until confirmed.
- Check the advisory's prerequisites and reachable code path.
- Do not claim RCE or data exposure solely from an outdated version banner.

## Stop Conditions

- Stop active probing of a specific path if it triggers account lockouts, CAPTCHA, or visible rate-limiting; that behavior itself is evidence enough and further requests risk denial-of-service.
- Stop and confirm attribution before continuing if a discovered CMS instance appears to be a third party's staging environment, a reseller/demo install, or otherwise not clearly owned by the target organization.
- Do not proceed from "outdated version identified" to exploitation without first confirming the advisory's vulnerable code path is actually reachable; version-matching alone is not authorization to run an exploit.

## Defensive Notes

- Removing or genericizing generator metadata, version strings, and default admin paths raises the cost of fingerprinting but does not replace patching; attackers can still corroborate version from behavior.
- Keeping CMS core, themes, and plugins current, and restricting admin/login routes by network or MFA, reduces both the fingerprinting surface and the exploitability of anything found.


## Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. there is no fixed hypothesis-count ceiling; continue distinct, decision-relevant hypotheses while authorized, and stop when evidence or a real safety/policy boundary resolves the branch. Prefer passive sources first, deduplicate candidates, and use active checks only when the asset and activity are explicitly in scope.

### Evidence record and confidence

For each candidate, preserve normalized asset, source/provenance, observation time, scope proof, resolver/HTTP/tool and relevant version, raw-evidence location, corroborating source, negative control, attribution confidence, next action, and related-skill trigger. Separate **asset confidence** (is it related to the organization?) from **security confidence** (is a vulnerability demonstrated?).

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. C1/C2 are not confirmed vulnerabilities.

### Skill-specific next steps

1. Use passive fingerprints and low-impact read-only requests to identify likely CMS, theme/plugin families, version clues, and entry points; preserve each signal and confidence separately.
2. Confirm each fingerprint with at least one independent marker (such as distinctive assets, headers, generator metadata, route behavior, or source evidence) and use a random-path control to detect generic pages.
3. Account for reverse proxies, caching, custom themes, removed generator tags, and patched backports before assigning a version or risk label.
4. Consult official vendor/plugin advisories for the exact component and version; prioritize exposed login/admin, API, upload, and legacy interfaces only when in scope.
5. Return a deduplicated component inventory with evidence, confidence, timestamp, and suggested read-only checks. A CMS fingerprint or old version clue is a lead, not a confirmed finding.


### Deduplication and stop rules

Normalize case, trailing dots, scheme/port, redirects, canonical names and resolved addresses before deduplication. Detect wildcard DNS, shared hosting, CDN/edge responses, soft-404s and stale records before ranking counts. Stop on exclusions, ownership ambiguity, unexpected sensitive data, throttling, instability or boundaries requiring further permission. Never claim ownership or register dangling resources.

### Handoff format

Return candidates with scope/provenance, confidence level, evidence path, deduplication key, negative control, priority rationale, safe next step and trigger for any linked attack skill. Promote a candidate to active testing only after scope and attribution are confirmed; promote it to a finding only after the relevant attack skill verifies the security boundary.

## References

- Source merged: [uphiago/recon-skills — recon/cms-detection/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/cms-detection/SKILL.md)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST National Vulnerability Database](https://nvd.nist.gov/)


## Targeted quality-loop enrichment (2026-10-19)

### Fingerprint-to-vulnerability gate
Maintain independent confidence for CMS identity, component identity/version, deployment ownership, and vulnerability applicability. Corroborate a fingerprint with multiple signals and account for reverse-proxy caches, custom themes, backported fixes, and misleading banners. Before invoking a version-specific skill, verify the affected component is reachable and that the preconditions are plausible; do not map a scanner's version label directly to a confirmed CVE. Use passive/GET-only probes where possible, preserve response hashes and the exact fingerprint source, and stop when no meaningful permitted observation remains. Chain to the CMS-specific skill only after identity evidence, then require that skill's independent proof gate.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Use passive fingerprint sources and browser response evidence first. WhatWeb or ProjectDiscovery httpx technology detection can help identify likely CMS/framework versions; Wappalyzer is a useful browser add-on for a second opinion.

### Installation and setup
- [WhatWeb project](https://github.com/urbanadventurer/WhatWeb) — official source and install instructions.
- [ProjectDiscovery documentation](https://docs.projectdiscovery.io/) — official httpx installation/usage.
- [Wappalyzer](https://www.wappalyzer.com/) — browser extension and technology lookup.
Use only in-scope hosts and policy-permitted request rates. Fingerprints are probabilistic; don't run CMS exploit modules solely because a scanner guessed a version.

### Primary resources
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) — fingerprinting and verification.
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb) — signatures and options.
- [Wappalyzer](https://www.wappalyzer.com/) — independent fingerprinting context.

### Reusable helper
Run python3 .cyberstrike/skill/scripts/normalize_urls.py urls.txt to deduplicate URLs collected through browser, passive sources, and scanners.

### Result handling
Keep each fingerprint's source/time/confidence and confirm version clues with headers, assets, or a normal route. Don't collapse uncertainty into an exact version without corroboration.
