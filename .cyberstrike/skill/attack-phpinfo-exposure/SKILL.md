---
name: attack-phpinfo-exposure
description: "Validate exposed PHP configuration pages for sensitive information disclosure and assess execution prerequisites without attempting webshell deployment or command execution."
category: "web-application"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - phpinfo
  - php
  - configuration
  - information-disclosure
  - rce-prerequisites
tech_stack:
  - php
  - wordpress
  - web
  - linux
cwe_ids:
  - CWE-200
  - CWE-497
chains_with:
  - attack-information-disclosure
  - attack-file-upload
  - attack-rce
prerequisites: []
severity_boost:
  attack-rce: "PHP configuration disclosure may inform exposure context but never proves RCE without a separate authorized execution primitive."
---

# PHPInfo and PHP Configuration Exposure

## Objective

Determine whether a public phpinfo() page exposes non-public configuration details, paths, modules, or environment metadata and document risk without using the information to deploy executable content.

## Testing Methodology

### Phase 1: Confirm real phpinfo output

Request only justified paths such as a discovered info.php/phpinfo.php and compare with a random nonexistent path. Confirm output contains real PHP configuration tables rather than a SPA catch-all. Keep the request count low.

### Phase 2: Capture minimal sensitive configuration

Record only specific non-public fields necessary to show impact, such as internal filesystem paths, private hostname, module list, non-public environment names, or proxy topology. Do not archive the entire page because it may contain cookie values, environment variables, or request metadata.

### Phase 3: Review effective configuration carefully

Differentiate Local Value and Master Value for directives. Inspect PHP version, display_errors, open_basedir, allow_url_include/fopen, upload limits, and disabled functions only as configuration context. A directive being enabled/disabled is not proof that a separate vulnerability exists.

### Phase 4: Check exposure scope and caching

Verify whether the page is publicly accessible without intended authentication, whether a CDN caches it, and whether the same content is available from a documented public diagnostics page. Use a sanitized response and avoid cache poisoning tests unless separately authorized.

### Phase 5: Review adjacent execution prerequisites as code review only

If an unrelated upload or code execution path is suspected, evaluate it separately using source/configuration review or a lab. Never upload a webshell, invoke disabled-function bypasses, test command execution, read host files, or chain PHPInfo into RCE on production.

### Phase 6: Validate remediation

Confirm the diagnostics page is removed or access-controlled and that the response no longer contains sensitive configuration. Preserve a regression check that scans for the distinctive phpinfo page title and configuration table markers.

## What Constitutes a Finding

- **Candidate / lead:** a path named phpinfo.php or info.php returns 200.
- **Confirmed disclosure:** the response is genuine phpinfo output and exposes non-public configuration that materially aids targeting or reveals sensitive environment data.
- **Not a finding alone:** public PHP version banner, non-sensitive generic module list, or 200 HTML from a catch-all route.
- **RCE must remain separate:** available process functions, open_basedir values, or an upload form do not prove code execution.

## Evidence Requirements

- Sanitized request/response, exact path, timestamp, and whether authentication was required.
- Minimal redacted fields supporting the claim; omit the full dump, cookies, environment secrets, and request headers containing tokens.
- PHP version and directive context where relevant, including local/master distinction.
- Before/after evidence after remediation.

## Tools

- **curl:** retrieve bounded output and save only minimal sanitized evidence.
- **HTML parser / grep:** detect phpinfo markers and compare with catch-all controls.
- **PHP manual:** verify directive semantics from authoritative documentation.
- **Source/configuration review:** identify why diagnostics are exposed and confirm remediation.

## PHPInfo Exposure and RCE Distinction Matrix

| Observed detail | Security interpretation | Required follow-up |
|---|---|---|
| PHP version/build | Fingerprint; may support version triage | Match exact vendor support/advisory information |
| DOCUMENT_ROOT / filesystem paths | May disclose internal layout | Confirm the paths are non-public and meaningfully sensitive |
| Environment/config values | Potential secret disclosure | Capture key name/type and truncated fragment only, not full value |
| display_errors enabled | Error leakage risk | Verify a normal error reveals sensitive detail without forcing destructive errors |
| open_basedir / disable_functions | Runtime hardening context | Not proof of RCE or a bypass |
| Upload/code execution candidate | Separate attack surface | Require independent authorized lab proof; never chain from PHPInfo by default |

**Mitigation:** remove public phpinfo endpoints, restrict diagnostics to authenticated admin/network paths, avoid dumping environment secrets, disable production display_errors, and include a regression test.

## Verification and False Positives

- Single-page apps and reverse proxies may return the same HTML for nonexistent paths; use a negative control.
- PHPInfo often reflects request headers/cookies; full-page capture can accidentally store secrets.
- Configuration settings can differ by pool or request context; avoid claiming global behavior from one page.
- Enabled functions do not imply a remotely reachable input sink.
- Stop before webshells, command execution, filesystem reads, disable_functions bypasses, or any file-write operation.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue with materially distinct, authorized checks while evidence can change the conclusion; deduplicate equivalent path checks and retries. Stop when direct evidence resolves the hypothesis, meaningful branches are exhausted, a prerequisite is unavailable, or scope/safety requires stopping. Minimize captured diagnostic content and never use exposed secrets.

Record each attempt: hypothesis, single changed variable, control/baseline, observed signal, interpretation, confidence and next branch. Prefer paired requests, controlled identities, synthetic records and independent corroboration; retain minimal sanitized evidence.

### Skill-specific hypothesis order

1. Request the suspected phpinfo endpoint and a random nonexistent path under the same host/session; compare normalized output to rule out soft-404 or generic debug pages.
2. Confirm that the response is actual phpinfo output using stable PHP/build markers, then identify only the configuration values needed to characterize exposure.
3. Redact environment variables, filesystem paths, request headers, session data, and any credentials immediately; do not use exposed values to access other services.
4. Check whether the page is reachable anonymously, only by authenticated roles, or only from an intended administrative network; record those conditions separately.
5. Recommend removing the diagnostic page from production or restricting it behind operational controls, then verify the endpoint no longer returns configuration data.


### Verdict gates

- **Confirmed:** repeatable security impact against an explicitly in-scope resource is shown using a tester-controlled identity/fixture and a meaningful negative control.
- **Likely / needs corroboration:** independent observations support the hypothesis but impact/root cause remains uncertain.
- **Unconfirmed:** output is generic, cached, ambiguous, or detached from a security boundary.
- **Refuted / false positive:** a relevant negative control or valid product/security-policy explanation accounts for the signal. Document attempted branches rather than claiming to exhaust every theoretical variant.
- Status codes, banners, timing changes, error messages, or scanner alerts alone are not proof.

### Stop, cleanup, and handoff

Stop at scope ambiguity, real-user data, unexpected state changes, service degradation, secret exposure or a prohibited action. Clean disposable state, revoke temporary sessions/tokens where possible, and log cleanup status. Handoff scope proof, baseline, hypothesis, attempts used, impact, controls, verdict/confidence, sanitized evidence and any proven related-skill trigger; do not chain from a speculative association.

## References

- [uphiago/recon-skills — phpinfo-to-rce](https://github.com/uphiago/recon-skills/blob/main/recon/phpinfo-to-rce/SKILL.md) — merged discovery and exposure-validation source.

- [uphiago/recon-skills — phpinfo-to-rce](https://github.com/uphiago/recon-skills/tree/main/recon/phpinfo-to-rce)
- [PHP Manual — phpinfo](https://www.php.net/manual/en/function.phpinfo.php)
- [PHP Manual — Core INI directives](https://www.php.net/manual/en/ini.core.php)


## Targeted quality-loop enrichment (2026-10-19)

### Sensitive-value minimization and adjacent-risk test
Verify the response is genuine PHP configuration output and preserve only a redacted section demonstrating the configuration boundary. Do not scrape or publish environment values, filesystem paths, request headers, or secrets from the page. Distinguish internal path disclosure, loaded-module/version hints, and actual credential exposure, and corroborate version findings with vendor advisories and deployment context. A phpinfo page alone does not prove RCE; review adjacent execution prerequisites offline or in a lab and label any untested link as a hypothesis. Chain to source/config exposure only when a distinct reachable artifact is confirmed, and use the evidence-hygiene skill before report submission.


## Minimal capture and remediation verification

Prefer response headers and an existence check first. If genuine phpinfo output is returned, stop broad collection and preserve only a redacted excerpt of the exact sensitive property needed for the report.

```bash
curl -sS --max-time 6 -D candidate.headers -o /dev/null "$IN_SCOPE_CANDIDATE_URL"
grep -iE '^(HTTP/|content-type:|cache-control:|content-length:)' candidate.headers
```

A 200 or HTML content type is not proof of phpinfo. If content inspection is needed, use a private local response artifact and remove it after producing a minimal redacted excerpt. Do not save a full phpinfo page to shared notes or attach it to a report.

Record endpoint, anonymous_or_role_access, phpinfo_signature_observed, minimal_sensitive_field_category, exact_value_redacted, random_path_control, cache_context, owner_remediation, and retest_result. Treat adjacent RCE or credential exposure as a separate hypothesis requiring independent proof.
