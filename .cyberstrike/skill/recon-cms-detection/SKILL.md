---
name: recon-cms-detection
description: "Fingerprint CMS platforms, versions, themes, plugins, and exposed administrative surfaces using corroborated passive and low-impact signals."
category: "recon"
version: "1.0.0"
author: "cyberstrike-official"
tags: [recon, CMS, WordPress, Drupal, Joomla, fingerprinting]
tech_stack: [HTTP, HTML, JavaScript, DNS]
chains_with: [recon-methodology, attack-wordpress, attack-source-leak, attack-information-disclosure]
prerequisites:
  - "A confirmed organization-owned web application"
severity_boost: {}
---

# CMS and Component Fingerprinting

## Objective

Identify the content-management platform and relevant extensions accurately enough to prioritize version-specific security review, while distinguishing fingerprints from confirmed vulnerabilities.

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

## References

- Source merged: [uphiago/recon-skills — recon/cms-detection/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/cms-detection/SKILL.md)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST National Vulnerability Database](https://nvd.nist.gov/)
