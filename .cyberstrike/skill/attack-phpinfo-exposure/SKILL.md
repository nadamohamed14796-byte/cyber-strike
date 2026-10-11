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

## References

- [uphiago/recon-skills — phpinfo-to-rce](https://github.com/uphiago/recon-skills/tree/main/recon/phpinfo-to-rce)
- [PHP Manual — phpinfo](https://www.php.net/manual/en/function.phpinfo.php)
- [PHP Manual — Core INI directives](https://www.php.net/manual/en/ini.core.php)
