# CyberStrike Skill Tooling Catalog

This is a discovery and selection guide for agent-executable CLI tools, local libraries, datasets, references, and helper scripts. Browser UI, browser extensions, and interactive intercepting proxies are not agent dependencies.

## Tool selection by task

| Task | Primary candidates | Complementary checks | Preserve |
|---|---|---|---|
| Passive subdomain discovery | subfinder, amass | certificate transparency, passive DNS | candidate, source, timestamp, attribution confidence |
| DNS validation | dnsx, dig | puredns/shuffledns only when active discovery is allowed; `host_inventory.py` for provenance-preserving normalization | record type, answer, TTL, wildcard controls, resolver errors |
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
| IDOR/BOLA and tenant authorization | Python requests, jq, pytest | `authorization_matrix.py` for explicit test-fixture plans; `http_response_diff.py` for controlled comparisons | principal/object/action, expected permission, control result, redacted evidence |

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
- `host_inventory.py`: normalize hostname observations from JSONL while retaining every source record; no network traffic.
- `authorization_matrix.py`: validate explicit test-owned principal/object/action cases and generate a planned JSONL matrix; no network traffic.
- `validate_skill_catalog.py`: structural catalog checks.

Inspect each helper's actual CLI and tests before assuming flags or behavior.

## Upstream resources

- https://github.com/vavkamil/awesome-bugbounty-tools — community discovery index; not a dependency manifest.
- https://owasp.org/www-project-web-security-testing-guide/
- https://owasp.org/API-Security/
- https://portswigger.net/web-security

Each tool candidate must be individually reviewed before installation. Use official docs for supported flags, installation, output formats, and limitations.

## Additional vulnerability-specific tool families

These are optional candidates; choose them only when the skill's hypotheses and test constraints justify them.

| Skill family | CLI tools / libraries | Authoritative references | Evidence to retain |
|---|---|---|---|
| XSS and client-side injection | dalfox; retire.js for known vulnerable JS dependencies; Semgrep for source-level patterns | [OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), [PortSwigger XSS](https://portswigger.net/web-security/cross-site-scripting) | source/sink or reflection context, payload context, browser-independent evidence when possible |
| SQL injection | sqlmap or ghauri for explicitly authorized validation | [OWASP SQLi Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), [PortSwigger SQLi](https://portswigger.net/web-security/sql-injection) | baseline/control responses, minimal proof, no database dump by default |
| SSRF and out-of-band behavior | interactsh-client for unique, controlled callback correlation; Python stdlib for evidence parsing | [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), [PortSwigger SSRF](https://portswigger.net/web-security/ssrf) | unique token, timestamped callback, no internal/cloud metadata access without explicit authorization |
| XXE | controlled XML test fixtures; interactsh-client where an out-of-band callback is needed | [OWASP XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) | parser behavior, minimal harmless proof, no local-file or internal-network extraction |
| GraphQL | graphql-cop; clairvoyance only where schema discovery is permitted | [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html) | operation/field inventory, per-resolver authorization, query cost and error behavior |
| JWT and sessions | jwt_tool; Python for redacted claim comparison | [OWASP Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) | redacted claims, signature/validation behavior, session boundary matrix; never persist live tokens |
| IDOR/BOLA and tenant isolation | Python requests, jq, pytest against controlled accounts/fixtures | [OWASP API1: BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/), [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/) | principal/object/action matrix, owner-vs-caller comparison, controlled-object impact |
| CORS, redirects, and header issues | curl and Python requests for repeatable request/response comparisons | [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/), [PortSwigger Open Redirect](https://portswigger.net/web-security/ssrf/open-redirect) | origin/credential matrix, redirect chain, raw headers with secrets redacted |
| Race conditions | requests-racer and pytest for controlled concurrent tests | [PortSwigger Race Conditions](https://portswigger.net/web-security/race-conditions) | initial state, timing/order, final controlled state; avoid repeated real-world mutations |
| Subdomain takeover candidates | subzy plus the provider-specific checks documented by can-i-take-over-xyz | [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) | dangling DNS, provider fingerprint, independent claimability evidence; do not attempt claiming a real target |
| CVE and template-driven checks | nuclei with reviewed templates; cvemap for vulnerability metadata | [Nuclei documentation](https://docs.projectdiscovery.io/tools/nuclei/overview) | template ID/version, matched request/response, manual validation status |
| Race-safe and repeatable API checks | Python requests, pytest, jq | [OWASP API Security](https://owasp.org/www-project-api-security/) | deterministic input fixtures, baseline/control, output schema and exit status |

## Helper-script policy

- Prefer the shared helpers listed above for URL normalization, JS endpoint inventory, response diffs, evidence manifests, and tool preflight.
- Before adding a helper, search the existing script directory and extend an existing helper if the responsibility is already covered.
- Every helper should have a documented CLI, deterministic input/output format, useful exit codes, safe handling of secrets, and a smoke/self-test path.
- Keep raw output and normalized output separate. Include source, timestamp, tool/version, and errors in structured records.
- Never claim a tool is installed, a check ran, or a finding is confirmed unless actual command output or evidence supports that claim.

