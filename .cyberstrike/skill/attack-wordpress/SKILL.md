---
name: attack-wordpress
description: "Assess WordPress core, theme, plugin, REST API, CORS, XML-RPC, and adjacent deployment risks using bounded, authorized checks and independently verified impact."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - wordpress
  - plugins
  - rest-api
  - xmlrpc
  - cors
  - cve
  - cms
tech_stack:
  - wordpress
  - php
  - rest-api
  - xmlrpc
  - mysql
cwe_ids:
  - CWE-284
  - CWE-862
  - CWE-942
  - CWE-1104
chains_with:
  - attack-cors
  - attack-file-upload
  - attack-idor-automation
  - attack-sqli
  - attack-xss
  - attack-rce
  - attack-source-leak
prerequisites: []
severity_boost:
  attack-cors: "Credentialed CORS can expose non-public WordPress data only when a controlled browser can read it under an authorized session."
  attack-file-upload: "Plugin upload weaknesses increase impact only when authorization, storage, and execution behavior are independently verified."
---

# WordPress Attack Surface Assessment

## Objective

Build a defensible picture of an in-scope WordPress installation, validate candidate component and API weaknesses, and confirm only the minimum security impact. WordPress presence, a public route, user metadata, XML-RPC support, or a version match is not a finding by itself.

## Testing Methodology

### Phase 1: Establish scope and confirm WordPress

Confirm the exact in-scope host/path and request budget. Start with a low-rate read-only check of the homepage, /wp-json/, /wp-login.php, /xmlrpc.php, and /wp-content/. Use bounded timeouts and pauses; do not run multi-host or high-concurrency sweeps unless the engagement explicitly allows them.

Confirm WordPress using at least two independent signals where practical: HTML/assets, REST namespace data, cookies, readme/changelog content, or route behavior. Compare candidate paths with one random nonexistent path to detect single-page-app catch-all responses.

### Phase 2: Inventory core, themes, plugins, and versions

Collect plugin/theme asset paths and the REST API namespace list from public responses. For each candidate component, record the signal, confidence, and whether the plugin is actually active/reachable. Prefer corroborating signals such as plugin header, readme/changelog, versioned assets, namespace, or known route; a stale asset or accessible readme alone may misstate the deployed version.

For CVE triage, consult current vendor advisories, WPScan/Patchstack, NVD, and the official patch/changelog. Compare semantic versions correctly and capture affected range, fixed version, configuration prerequisites, authentication level, and reachability. Do not present a CVE match as a confirmed vulnerability until the affected code path is shown to be reachable.

### Phase 3: Review REST routes and authorization

Fetch the REST index and inspect relevant namespaces and documented routes. Prefer read-only GET requests and small page sizes. Classify returned information before assigning impact: published posts/pages are generally public; usernames or slugs may be reconnaissance; private drafts, email addresses, role data, settings, orders, customer details, logs, and form entries require separate authorization review.

Use two test-owned accounts with different roles and a synthetic object to compare anonymous, owner, and non-owner behavior. For write methods (POST/PUT/PATCH/DELETE), perform no mutation unless the specific operation is authorized and a disposable record exists. Do not blanket-replay arbitrary write methods with empty or crafted bodies against production.

### Phase 4: Evaluate plugin route protections

Review permission callbacks, authentication requirements, writable fields, and method-level policies for relevant plugin routes. A route returning 200, a missing-parameter error, or a public schema does not establish an authorization bypass. Confirm that the response represents an actual operation and check persisted state only using a disposable test object.

If a source review is available, trace user-controlled inputs through the route registration and permission callback. Note whether the route is read-only, state-changing, or privileged and whether a nonce alone is incorrectly treated as authorization. Avoid publishing content, changing settings, creating admin users, changing roles, or touching real customer records as proof.

### Phase 5: Validate CORS in a browser

First send a single request with a controlled Origin value and save the response headers/body. Header reflection is a candidate, not proof. Credentialed CORS requires a browser-origin context, a response that permits the tester-controlled origin, credential behavior consistent with the browser's cookie policy, and access to data that is not public to anonymous visitors.

Use an approved test login and a harmless, non-public test record. Compare a credentialed browser request with an anonymous control. Do not collect cookies, export private account data, send results to an external exfiltration endpoint, or involve a real user. Wildcard origin without credentials and public data readable by anyone are usually not sensitive CORS findings.

### Phase 6: Classify XML-RPC safely

Use a protocol-valid POST response, such as a benign method-list request, to distinguish XML-RPC from a generic status code. Capture redirects separately and do not follow them while classifying the original protocol response. Method availability is not proof the caller is authorized to perform that method.

Do not use XML-RPC multicall for credential guessing, password spraying, amplified requests, internal port scans, metadata probing, or shell uploads. If an engagement explicitly includes a specific XML-RPC operation, use a test identity, one controlled request, strict timeouts, a synthetic resource, and the operation's stop/cleanup conditions. A pingback callback alone establishes an outbound request to a controlled endpoint, not access to an internal service or cloud credentials.

### Phase 7: Check exposed files, debug output, and staging variants

Only probe file paths justified by observed stack evidence and program rules. Verify content rather than HTTP 200: Git markers in exposed Git metadata, configuration assignments in environment files, real application entries in debug logs, meaningful archive signatures, or directory index content. Avoid bulk downloading backups, logs, or database dumps; capture only a small sanitized sample sufficient to establish exposure.

Compare in-scope staging/subdirectory installations with production for version, authentication, REST/API, logging, and storage configuration. A weaker staging control matters only if the asset is in scope and a trust relationship or meaningful impact is demonstrated.

### Phase 8: Confirm component CVEs and build chains only from verified prerequisites

For every candidate CVE: establish exact version from multiple signals when possible, verify the affected range in a current advisory, check whether the plugin is active and route reachable, note authentication and feature prerequisites, then validate with a harmless lab reproduction or approved test fixture. Do not use exploit code that creates web shells, executes commands, writes files, or mutates production settings as a default proof.

Treat each proposed chain as a sequence of individually verified edges: component/version -> reachable vulnerable route -> required test identity/capability -> controlled state change -> separate impact proof. Registration normally yields a low-privilege role; a REST namespace does not imply upload rights; accepted upload does not imply executable storage; and XML-RPC, CORS, or open registration do not automatically compose into RCE.

## What Constitutes a Finding

- **Candidate / lead:** WordPress is detected, a plugin namespace exists, a version may be affected, XML-RPC responds, CORS headers are unusual, or a file path returns 200.
- **Confirmed finding:** the in-scope code path and required conditions are demonstrated, and the relevant security boundary fails with a controlled test identity or synthetic record.
- **CVE confirmed on target:** installed version and vulnerable feature are corroborated and the vulnerable route/configuration is reachable; public version metadata alone is insufficient.
- **CORS confirmed:** an approved browser can read non-public test data across origins under the intended credential conditions.
- **Authorization confirmed:** a non-owner/low-privileged test account accesses or changes a protected test object and authoritative state confirms the result.
- **Not a finding by itself:** WordPress presence, public author metadata, an open XML-RPC endpoint, public readme.txt, a 200 response, a CVE version match without reachability, or an upload route that rejects unauthorized requests.

## Evidence Requirements

- Exact scoped base URL, checked paths, timestamp, and low-rate request context.
- Two corroborating component/version signals or an explicit note explaining why only one was available.
- Sanitized request/response and the relevant security header, REST route, XML-RPC method response, or file-content marker.
- For authorization/CORS, test account roles, synthetic object ownership, anonymous negative control, browser evidence where required, and before/after state.
- For a CVE, advisory URL, affected/fixed version range, prerequisite, reachable route, and controlled validation result.
- Redact cookies, authorization headers, tokens, user data, order details, secrets, and configuration values. Store only the minimum content needed to reproduce.

## Tools

- **curl:** bounded single-path checks, header capture, and protocol-valid requests with timeouts.
- **jq / Python JSON parsing:** inspect REST namespaces/routes and compare response shapes without dumping records.
- **WPScan:** identify candidate components and known advisories when the program permits scanning; do not equate a scanner result with proof.
- **NVD, vendor advisories, WPScan, and Patchstack:** corroborate affected versions, prerequisites, and patch history.
- **Burp Suite and browser DevTools:** validate auth boundaries and credentialed CORS in a real controlled browser context.
- **Source review / diff:** inspect REST permission callbacks, plugin route registration, upload handlers, and patched code.

## WordPress Coverage and Impact Matrix

| Surface | Candidate signal | Required confirmation |
|---|---|---|
| Core / theme / plugin | Asset, namespace, readme, or version string | Two signals when practical; exact version and reachable affected feature |
| REST read endpoint | User, post, settings, or plugin data returned | Sensitivity and access policy; public data is not automatically disclosure |
| REST mutation | POST/PUT/PATCH/DELETE route or missing-param error | Controlled test account plus persisted synthetic state change |
| Plugin CVE | Installed component falls in reported range | Current advisory, fixed range, feature/config prerequisites, reachable route |
| CORS | Origin reflection / allow-credentials header | Browser actually reads non-public test data; public/anonymous negative control |
| XML-RPC | Protocol-valid method response | Specific method, auth requirements, and permitted action established separately |
| File/debug exposure | 200 on a backup/config/log candidate | Content signature and minimal sensitive marker; exclude SPA/catch-all response |
| Upload chain | Inert file accepted | Storage origin, retrieval controls, and executable handling are separate checks |
| Staging asset | Older version or weaker setting | In-scope status and meaningful shared-trust or deployment impact |

**False-positive controls:** WordPress and SPA catch-all routes can both return 200; compare content and a random path. Use semantic version comparison rather than shell string order. Verify the exact plugin is active; a deactivated plugin generally cannot be reached through its normal web handler. Test CORS in a browser, not with curl alone. XML-RPC method listing is not proof of authorization. Public REST data and open registration do not automatically expose private content or create a privileged account.

**Mitigation / regression:** keep core/themes/plugins patched, remove unused extensions, restrict REST routes with explicit permission callbacks, enforce object/property authorization, configure CORS with exact origin allowlists, disable unused XML-RPC functionality, isolate uploads from executable origins, protect logs/backups, and regression-test the exact route and role matrix.

## Verification and False Positives

- A route may be a cache/WAF/SPA response rather than WordPress; confirm from content and independent signals.
- Version metadata can be stale, backported, hidden, or belong to an inactive plugin; check changelog/patch diff and route reachability.
- Open registration usually creates a subscriber or another low-privilege role, not an administrator.
- A REST namespace can be public while each operation remains protected.
- CORS header reflection is not sensitive data theft; browser cookie rules, exposed data, and a working cross-origin read must be validated.
- XML-RPC response status alone is insufficient; require valid protocol structure. An outbound pingback does not prove internal data access.
- Stop before high-volume scans, credential testing, service stress, file writes, shell uploads, internal-network access, real-data collection, or any action outside written authorization.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Use the verification ledger to track distinct evidence-producing hypotheses, not as a quota for payload mutations. Follow relevant signal-led branches only while the candidate remains plausible; stop early on decisive evidence, scope/safety limits, or when no meaningful branch remains. Cosmetic variants are not separate hypotheses.

Track each attempt as hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired requests and controlled test identities/fixtures; save only minimal sanitized evidence.

### Skill-specific hypothesis order

1. Use passive/read-only evidence to identify WordPress core, active plugins/themes, REST routes, XML-RPC state, and public user disclosure; retain confidence levels because caching/CDNs can obscure versions.
2. Map only in-scope routes and compare anonymous with controlled test-role behavior; distinguish intentional public pages/API fields from private content or administrative functions.
3. Check plugin/theme exposures against official advisories for the exact affected version and enabled configuration; do not treat outdated version banners as a confirmed exploitable flaw.
4. Use only test-owned content for upload, role, REST, and authentication tests. Do not brute-force passwords, enumerate private users beyond program rules, install plugins, or modify production settings.
5. Report the verified boundary, exact component/version evidence, minimally sufficient proof, and version/configuration-specific remediation with a safe retest.


### Verdict gates

- **Confirmed:** repeatable impact at an explicit in-scope boundary is demonstrated using a controlled identity/fixture and a meaningful control.
- **Likely / needs corroboration:** independent indicators support the candidate, but the consequence or root cause remains uncertain.
- **Unconfirmed:** evidence is generic, ambiguous, cached, or not tied to a security property.
- **Refuted / false positive:** a relevant negative control or valid implementation/policy explanation accounts for the observation. Document tested branches; do not claim all imaginable variants were exhausted.
- Scanner alerts, version strings, banner text, status codes, and response length alone are not proof.

### Stop, cleanup, and handoff

Stop on scope ambiguity, unexpected user data, state changes, service degradation, secret exposure or prohibited behavior. Clean disposable test state and revoke temporary sessions/tokens where possible. Return scope proof, baseline, hypothesis, attempts used, impact, negative controls, verdict/confidence, sanitized evidence and cleanup status. Start a chained skill only when its trigger has been independently observed.

## References

- [uphiago/recon-skills — WordPress REST authentication bypass](https://github.com/uphiago/recon-skills/blob/main/recon/wp-plugin-rest-auth-bypass/SKILL.md) — merged plugin/API access-control source.
- [uphiago/recon-skills — XML-RPC testing](https://github.com/uphiago/recon-skills/blob/main/recon/xmlrpc-exploitation/SKILL.md) — merged WordPress protocol source.

- [uphiago/recon-skills — wordpress-plugin-hunt](https://github.com/uphiago/recon-skills/tree/main/recon/wordpress-plugin-hunt)
- [uphiago/recon-skills — wp-mass-recon](https://github.com/uphiago/recon-skills/tree/main/recon/wp-mass-recon)
- [uphiago/recon-skills — wp-plugin-automation](https://github.com/uphiago/recon-skills/tree/main/redteam/wp-plugin-automation)
- [uphiago/recon-skills — wp-plugin-cve-hunt](https://github.com/uphiago/recon-skills/tree/main/redteam/wp-plugin-cve-hunt)
- [uphiago/recon-skills — wp-plugin-rest-auth-bypass](https://github.com/uphiago/recon-skills/tree/main/recon/wp-plugin-rest-auth-bypass)
- [uphiago/recon-skills — wordpress-full-compromise](https://github.com/uphiago/recon-skills/tree/main/chains/wordpress-full-compromise)
- [uphiago/recon-skills — wordpress-cors-xmlrpc-rce-chain](https://github.com/uphiago/recon-skills/tree/main/redteam/wordpress-cors-xmlrpc-rce-chain)
- [uphiago/recon-skills — cors-credential-wordpress](https://github.com/uphiago/recon-skills/tree/main/recon/cors-credential-wordpress)
- [uphiago/recon-skills — xmlrpc-exploitation](https://github.com/uphiago/recon-skills/tree/main/recon/xmlrpc-exploitation)
- [uphiago/recon-skills — hunt-wordpress](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-wordpress)
- [WordPress REST API Handbook](https://developer.wordpress.org/rest-api/)
- [WPScan Vulnerability Database](https://wpscan.com/)
- [NIST National Vulnerability Database](https://nvd.nist.gov/)


## Targeted quality-loop enrichment (2026-10-19)

### Plugin/core route differential
Inventory core, theme, plugin, REST/AJAX routes, capabilities, nonce checks, version evidence, and the exact code path where possible. Compare anonymous and two controlled WordPress roles against a synthetic post/media/user fixture, checking read, update, delete, upload, and custom plugin methods independently. A visible plugin version or XML-RPC exposure is not a vulnerability without a specific reachable behavior. Validate CVE applicability against exact version/build and any backport; do not mass-enumerate users or test destructive plugin actions on production. Route custom REST permission callbacks to BFLA/property authorization, upload processing to file-upload, and origin/header issues to CORS/CSRF only when their effects are separately proven.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and purpose
Use Burp/browser DevTools for observed behavior; WPScan for permitted WordPress version/plugin/theme exposure checks; WP-CLI and static source review only where source or admin access is authorized.

### Installation and setup
- [WPScan documentation](https://wpscan.com/) — official CLI usage and supported installation methods.
- [WP-CLI installation](https://wp-cli.org/) — official tool for owned instances.
- [Burp Suite](https://portswigger.net/burp) — request verification.
Use an in-scope hostname and the program rules for enumeration. If API access or a token is needed, manage it privately and never paste it into notes. Do not exploit or modify plugins/themes in production just because a scanner reports a vulnerable version.

### Primary resources
- [WordPress security documentation](https://developer.wordpress.org/apis/security/) — nonce/capability and secure API patterns.
- [WPScan](https://wpscan.com/) — version and component detection.
- [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) — confirmation and impact.

### Reusable helper
Run python3 .cyberstrike/skill/scripts/normalize_urls.py urls.txt to deduplicate collected WordPress-related URLs locally and strip query values.

### Result handling
Distinguish fingerprinted version exposure from an exploitable vulnerability; verify the affected component/version, reachable vulnerable feature, and safe proof. Use a disposable site for write tests.

## Agent-executable CLI tooling, resources, and helper scripts

Use agent-executable CLI tools and local test harnesses; browser UI, browser extensions, and interactive intercepting proxies are not dependencies. Verify official installation docs, tool version, license, dependency provenance, and target impact before use.

### Recommended tools
- WPScan — WordPress-specific checks with authorized API/configuration
- WhatWeb — technology fingerprinting
- Trivy/Semgrep — local plugin/theme source or container checks when available
- jq/Python — normalize plugin/version/advisory inventory

### Resources
- https://wpscan.com/
- https://github.com/urbanadventurer/WhatWeb
- https://developer.wordpress.org/advanced-administration/security/
- https://github.com/vavkamil/awesome-bugbounty-tools

Treat community lists as discovery aids; official docs and advisories are the source of truth for tool behavior and affected versions.

### Helper-script contract
Record core/plugin/theme version evidence and vendor advisory references. Do not run brute-force or destructive checks; a guessed plugin version is not confirmation that a vulnerable code path is present.

Preserve native evidence and write normalized results separately. Retain tool/version, timestamps, source, rule/advisory IDs, error state, confidence, and redaction. Use deterministic fixtures and structured output.

### Handoff
Return actual commands, versions, inputs/outputs, checks passed/failed, limitations, and next skill. Static or version-based signals are not confirmed vulnerabilities without evidence of an affected path.
