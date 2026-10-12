---
name: recon-visual-recon
description: "Use screenshots, page titles, visual clustering, and browser-observed behavior to prioritize web assets and identify distinct applications."
category: "recon"
version: "1.0.0"
author: "cyberstrike-official"
tags: [recon, screenshots, visual-triage, web-enumeration]
tech_stack: [HTTP, browser, TLS]
chains_with: [recon-methodology, recon-vhost-enumeration, recon-subdomain-enumeration]
prerequisites: [recon-subdomain-enumeration]
severity_boost: {}
---

# Visual Reconnaissance and Application Clustering

## Objective

Reduce a large host inventory into distinct applications and high-value testing candidates using reproducible visual evidence. Screenshots and titles are triage signals, not vulnerability proof.

## Scope

- Only capture URLs already confirmed as in-scope and attributable to the target organization (e.g., output of `recon-subdomain-enumeration` or a program-provided asset list). Do not expand capture to third-party SaaS, CDN, or parked infrastructure discovered incidentally.
- Automated capture is passive (GET/navigation only). Do not submit forms, accept cookie/consent prompts beyond what is needed to render the page, or interact with authentication flows during the bulk pass.
- If a captured page requires credentials the tester does not hold, or displays content suggesting it belongs to an unrelated customer/tenant, exclude it from the dataset and flag it for scope confirmation rather than clustering it.

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

## Stop Conditions

- Stop capturing a host and flag it for review if a page prompts for real payment details, displays what appears to be another customer's live data, or returns content inconsistent with program scope.
- Stop and throttle if the target shows rate-limiting, CAPTCHA challenges, or WAF block pages across multiple hosts; bulk headless capture should not be mistaken for a denial-of-service attempt.
- Stop before any authenticated or state-changing interaction; visual recon hands off to the relevant attack-* or auth skill once a testable hypothesis is formed, it does not perform the test itself.

## Defensive Notes

- Organizations can reduce the value of this technique by consolidating default/placeholder pages, disabling framework and admin-panel banners on production hosts, and keeping staging/legacy interfaces off public DNS or behind authentication.
- Consistent, informative error pages (rather than framework-default error pages) reduce fingerprinting value from screenshots and titles alone.


## Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. The validation budget is at most 20 distinct hypotheses per candidate asset; it is not permission for 20 scans or repeated probes. Prefer passive evidence first and perform active checks only when explicitly in scope.

### Evidence record and confidence

For each candidate, preserve normalized asset, provenance, capture time, scope proof, browser/tool and version, evidence location, corroborating signal, negative control, attribution confidence, next action and related-skill trigger. Separate asset confidence from security confidence.

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** a specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. Visual similarity or a distinctive screenshot alone cannot exceed C1/C2.

### Visual signal follow-through

Normalize URLs and capture conditions; compare viewport, title, DOM landmarks, favicon, branding, application routes and login state. Separate apparent clones caused by shared templates, CDN error pages, branding reuse or default hosting pages. For each high-priority visual cluster, write a falsifiable hypothesis about a distinct application or trust boundary, then route it to the relevant framework, access-control, API or technology-fingerprinting skill.

### Deduplication and stop rules

Deduplicate by canonical host/URL, redirect destination, title/DOM fingerprint and application identity while retaining alternate routes that can cross a different trust boundary. Stop on scope ambiguity, unexpected sensitive information, service instability, or if capture requires unapproved credentials or active behavior.

### Handoff format

Return normalized asset, scope/provenance, capture conditions, confidence, duplicate cluster, negative control, prioritization rationale, candidate hypothesis, safe next step and trigger for any linked attack skill. A screenshot is evidence of what rendered, not proof of a vulnerability.

## References

- Source merged: [uphiago/recon-skills — recon/visual-recon/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/visual-recon/SKILL.md)
- [Playwright documentation](https://playwright.dev/docs/intro)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
