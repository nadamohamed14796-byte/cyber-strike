# CyberStrike Skill Tooling Catalog

This is a discovery and selection guide for agent-executable CLI tools, local libraries, datasets, references, and helper scripts. Browser UI, browser extensions, and interactive intercepting proxies are not agent dependencies.

## Tool selection by task

| Task | Primary candidates | Complementary checks | Preserve |
|---|---|---|---|
| Passive subdomain discovery | subfinder, amass | certificate transparency, passive DNS | candidate, source, timestamp, attribution confidence |
| DNS validation | dnsx, dig | puredns/shuffledns only when active discovery is allowed | record type, answer, TTL, wildcard controls, resolver errors |
| Ports and services | naabu, nmap, tlsx, fingerprintx | httpx for HTTP metadata | host, port, protocol, timestamp, service confidence |
| URL/history collection | gau, waymore, waybackurls | katana for authorized crawling | normalized URL, source, first-seen, parameters |
| Content discovery | feroxbuster, ffuf, dirsearch | context-appropriate wordlists | status, length, content fingerprint, errors |
| JavaScript inventory | jsluice, xnLinkFinder, LinkFinder | retire.js, local source-map review | bundle hash, route, method/parameters, line/offset, confidence |
| Parameter discovery | Arjun, x8, ParamSpider | local parameter inventory | endpoint template, method, parameter, source |
| Template checks | nuclei with reviewed templates | class-specific CLI and evidence review | template ID/version, request impact, evidence pointer |
| Local secret scanning | gitleaks, noseyparker, trufflehog | redaction and context review | detector, file/commit, redacted fingerprint; never raw live secret |
| Source/config checks | Semgrep, Trivy, Checkov where applicable | vendor advisories | rule/advisory, path/resource, version, remediation |
| HTTP response comparison | curl, Python requests/httpx | http_response_diff.py | baseline/control, changed variable, status and response fingerprint |
| Evidence/report validation | Python stdlib, jq | validate_evidence_manifest.py | evidence path, redaction status, finding disposition |

## Readiness requirements

1. Check availability with `command -v <tool>` and record the version before relying on it.
2. Prefer official installation/release documentation. Review license, release provenance, dependencies, platform support, and update activity.
3. Do not install or execute a tool only because it appears in a community list. Establish a concrete skill need first.
4. Never send secrets or production customer data to third-party scanners or public services.
5. Use safe defaults and explicit per-target configuration. No unbounded high-rate scans, destructive operations, credential guessing, or real-user data extraction.
6. Preserve native output as evidence and normalize a separate copy.
7. Tool output is a lead, not a verdict. Confirm impact with a minimal controlled test before marking a finding verified.

## Existing CyberStrike helpers

- `normalize_urls.py`: URL normalization and deduplication.
- `js_endpoint_inventory.py`: local JavaScript endpoint candidate inventory.
- `http_response_diff.py`: baseline/controlled-variant comparison.
- `validate_evidence_manifest.py`: evidence manifest validation.
- `audit_skill_enrichment.py`: audit direct skills for executable tooling guidance.
- `tool_preflight.py`: check local CLI availability and version output without installing tools or contacting targets.
- `validate_skill_catalog.py`: structural catalog checks.

Inspect each helper's actual CLI and tests before assuming flags or behavior.

## Upstream resources

- https://github.com/vavkamil/awesome-bugbounty-tools — community discovery index; not a dependency manifest.
- https://owasp.org/www-project-web-security-testing-guide/
- https://owasp.org/API-Security/
- https://portswigger.net/web-security

Each tool candidate must be individually reviewed before installation. Use official docs for supported flags, installation, output formats, and limitations.
