---
name: recon-visual-recon
description: "Use screenshots, page titles, visual clustering, and browser-observed behavior to prioritize web assets and identify distinct applications."
category: "recon"
version: "1.0.0"
author: "cyberstrike-official"
tags: [recon, screenshots, visual-triage, web-enumeration]
tech_stack: [HTTP, browser, TLS]
chains_with: [recon-methodology, recon-vhost-enumeration, recon-staging-subdomain-hunt]
prerequisites:
  - "A list of attributable web URLs"
severity_boost: {}
---

# Visual Reconnaissance and Application Clustering

## Objective

Reduce a large host inventory into distinct applications and high-value testing candidates using reproducible visual evidence. Screenshots and titles are triage signals, not vulnerability proof.

## Methodology

### 1. Normalize and validate the URL set

Deduplicate URLs by canonical hostname and path, remove malformed entries, and confirm attribution before browser visits. Separate redirects, CDN errors, parked domains, and third-party login providers from actual application pages.

### 2. Capture consistent snapshots

Use a headless browser or screenshot tool with a consistent viewport, wait condition, and timeout. Record URL, final URL, title, status, screenshot path, timestamp, and any TLS/certificate errors. Avoid submitting forms or triggering state changes during automated capture.

### 3. Cluster applications

Group pages using normalized titles, visual similarity, favicon hashes, shared asset paths, login-provider identity, and DOM landmarks. Dynamic timestamps, personalized banners, A/B tests, and cookie notices can skew visual hashes; retain multiple signals rather than trusting one metric.

### 4. Prioritize for manual review

Prioritize unique login portals, tenant selection screens, admin consoles, file management, billing, API documentation, legacy interfaces, and non-production-looking pages. Verify ownership and security relevance before deeper testing.

### 5. Convert visual leads into testable hypotheses

For each cluster, record observed roles, major workflows, visible API routes, framework clues, and potential trust boundaries. Reproduce the observation in a browser or proxy before assigning a vulnerability label.

## What This Produces

- A visual catalog of confirmed web applications.
- Clusters that reduce duplicate manual review.
- A prioritized queue of unique workflows and authentication surfaces.
- Reproducible screenshot metadata linked to each URL.

## Evidence Requirements

- URL and final redirect destination.
- Timestamped screenshot plus status/title metadata.
- Cluster rationale and confidence.
- Separate technical evidence for any claimed vulnerability.

## Tools

- Playwright or Chromium headless capture.
- gowitness or EyeWitness where available.
- Browser DevTools and Burp Suite for manual follow-up.
- Python scripts for URL normalization, screenshot indexing, and metadata export.

## Visual Triage Matrix

| Signal | Triage value | Follow-up |
|---|---|---|
| Distinct login portal | Potential separate identity boundary | Map SSO, tenant, and role flows |
| Admin-like interface | High-value functionality candidate | Verify access control using test roles |
| API documentation page | Endpoint inventory | Compare declared and observed auth controls |
| Similar screenshots across hosts | Possible shared application deployment | Check hostname-specific configuration |
| Unique upload/billing/tenant workflow | Business logic surface | Build a workflow map and test invariants |
| Browser error or parked page | Usually low value | Confirm DNS and attribution before discarding |
| Different title only | Weak fingerprint | Corroborate with DOM/assets and repeat capture |

## Verification and False Positives

- Exclude random-host catch-all pages and generic CDN error screens.
- Keep cookies and authentication state consistent when comparing pages.
- Do not infer ownership from branding alone.
- Treat screenshots as navigation evidence, not proof of server-side access.
- Re-capture dynamic pages before concluding that two deployments differ.

## References

- Source merged: [uphiago/recon-skills — recon/visual-recon/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/visual-recon/SKILL.md)
- [Playwright documentation](https://playwright.dev/docs/intro)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
