# CyberStrike Tool Catalog

The single canonical reference for agent-executable tools, local helpers, APIs, datasets, installation/preflight, and phase routing. Skills define **how to test**; this file defines **which tool to choose and how to invoke/check it**. Do not create a second tool/source inventory. Add a tool here once, then link to this catalog from skills.

This is a candidate catalog, not proof that a binary is installed, maintained, compatible, enabled, or authorized. Prefer native registered CyberStrike tools and existing helpers when they cover the need. Browser UI, browser extensions, and interactive proxy GUIs are not agent-executable CLI dependencies.

## Selection rules

1. Identify the phase and exact evidence gap before selecting a tool.
2. Check native CyberStrike registered tools and existing helpers first; extend a helper instead of adding a duplicate.
3. Preflight external CLIs with `command -v TOOL` and the documented version/help flag. Use `python3 .cyberstrike/skill/scripts/tool_preflight.py --json TOOL [TOOL...]` when available. Reuse successful checks only while the same runtime/binary version remains.
4. Prefer official docs/releases; review maintenance, license, platform/dependencies, package provenance, permissions, network behavior, flags, output format, and rate behavior before install/use.
5. Select the smallest useful set by default; add independent alternatives when they close a real coverage gap, corroborate evidence, or recover a failed source. Do not run equivalent collectors in parallel or use a fixed arbitrary tool count.
6. Keep native/raw output and normalized output separate. Preserve tool/version, exact redacted command, input assets, timestamps, exit status, stderr/errors, raw/normalized artifact paths, source provenance, and limitations.
7. Use machine-readable output where supported and store artifacts in the canonical target workspace. Do not create one output file per tool if a shared phase ledger/artifact can retain provenance.
8. Tool output is a lead, not a finding. Use a baseline, a relevant negative control, and minimal controlled validation. Never claim a tool ran or succeeded without its actual result.
9. Installation is not authorization. Apply program scope, rate limits, privacy, non-destructive defaults, and explicit permission for state-changing tests. Never send secrets or production customer data to third-party services.

## Phase-to-tool matrix

| Phase / task | Primary method | Alternatives / supporting tools | Required output / notes |
|---|---|---|---|
| Passive subdomain collection | Use the source methods in this catalog: query crt.sh certificate-transparency data and OTX passive DNS where reachable; use one available primary CLI such as `subfinder` or `amass` when useful | CertSpotter, assetfinder, Findomain, Sublist3r, public indexes, first-party links, and other reputable passive datasets only when they add distinct coverage | Write results into canonical `subdomains.txt` and `subdomain-sources.json`; record each source, timestamp, status, errors, raw/accepted/rejected/duplicate counts, and provenance. Normalize wildcard, IDN, case, trailing dots, and root boundaries; do not claim an unrun source succeeded. |
| DNS validation / wildcard handling | dnsx, dig/drill; existing `host_inventory.py` for normalization | puredns/shuffledns only when active discovery is permitted | DNS records, CNAME chain, TTL, resolver status, wildcard controls, source attribution |
| Ports / services / TLS | naabu, nmap, tlsx | httpx for HTTP metadata; fingerprintx where available | host/port/protocol, service fingerprint, timestamp, confidence, rate/authorization notes |
| HTTP liveness / tech fingerprinting | httpx, WhatWeb | curl; TLS metadata | status, redirect chain, title, content type, technology clues, stable fingerprint |
| URL history / crawling | gau, waybackurls, waymore; katana for authorized crawling | hakrawler; first-party links and documentation | normalized URL, method/parameters when known, source, first-seen, collection status |
| Content / directory / virtual-host discovery | ffuf, feroxbuster, dirsearch | context-appropriate wordlists; hakrawler for links | status, length, fingerprint, error/negative-control data; conservative rate |
| Parameter discovery | Arjun, x8, ParamSpider | endpoint inventory and controlled request comparison | endpoint template, method, parameter, source; preserve auth/content-type context |
| JavaScript / endpoint analysis | jsluice, xnLinkFinder, LinkFinder | local source-map review; retire.js for dependency clues | bundle hash, route, method/parameter, line/offset, confidence; use existing `js_endpoint_inventory.py` where suitable |
| API / GraphQL / WebSocket | graphql-cop, Clairvoyance where schema discovery is permitted, websocat/wscat | curl, Python requests, local API schemas | operation/field/route inventory, auth boundaries, controlled evidence |
| Template / CVE checks | nuclei with reviewed templates; cvemap for metadata | technology-specific checks and vendor advisories | template ID/version, matched request/response, scope, manual validation status |
| XSS / client-side injection | dalfox for suitable authorized checks | browser-independent reflection/source-sink analysis; Semgrep for source | payload context, source/sink, minimal proof; alerts alone are not findings |
| SQL injection | sqlmap or ghauri for explicitly authorized validation | controlled baseline/variant requests | minimal proof and response diff; no database dumping by default |
| SSRF / OOB behavior | interactsh-client with a unique controlled token | Python for callback/evidence parsing | token, timestamped callback, request correlation; no internal/cloud metadata access without explicit authorization |
| JWT / sessions / auth | jwt_tool; Python requests | local redacted claim comparison and controlled account matrix | redacted claims, session boundary, expected/observed authorization; never persist live tokens |
| IDOR / BOLA / tenant authorization | Python requests, jq, pytest | existing `authorization_matrix.py`, `http_response_diff.py` | principal/object/action, expected policy, control result, redacted evidence; use test-owned accounts/objects |
| TLS / headers / CORS / redirects | testssl.sh, curl, Python requests | httpx metadata; response diff helper | raw relevant headers with secrets redacted, redirect chain, baseline/variant, policy impact |
| Race conditions | pytest and requests-racer in controlled fixtures | deterministic local harness | initial state, request ordering/timing, final controlled state; avoid repeated real-world mutations |
| Secrets / exposed source | Gitleaks, TruffleHog, Nosey Parker, detect-secrets, whispers | local Git inspection; git-dumper only when explicitly authorized and permitted | detector, file/commit, redacted fingerprint; never print or use discovered secrets |
| Source / dependencies / containers / IaC | Semgrep, Trivy, Checkov | vendor advisories, language-native tooling | rule/advisory, path/resource, version, remediation |
| Cloud / CI / platform review | Prowler, ScoutSuite, provider CLIs where authorized | Checkov, Trivy, Semgrep | identity/resource, least-privilege finding, source/config evidence; read-only first |
| Subdomain takeover triage | subzy plus provider conditions from can-i-take-over-xyz | DNS/CNAME and provider documentation | dangling record and provider-specific evidence; never attempt to claim a real target |
| Evidence / normalization / reporting | Python stdlib, jq | shared helpers below | reproducible evidence references, redaction, disposition, validation errors |

## Built-in CyberStrike scripts and helpers

Inspect each helper's actual `--help`, source, and tests before assuming flags or behavior. Reuse these instead of creating near-duplicates.

- `host_inventory.py`: normalize hostname observations while retaining each source record; no network traffic.
- `normalize_urls.py`: normalize and deduplicate collected URLs.
- `js_endpoint_inventory.py`: local JavaScript endpoint candidate inventory.
- `http_response_diff.py`: compare baseline and controlled variants.
- `authorization_matrix.py`: validate explicit test-owned principal/object/action cases and create a planned JSONL matrix; no network traffic.
- `validate_evidence_manifest.py`: validate evidence manifests.
- `tool_preflight.py`: check local CLI availability/version without installing tools or contacting targets.
- `audit_skill_enrichment.py`: audit direct skills for executable tooling guidance.
- `validate_skill_catalog.py`: structural catalog checks.

Before adding a helper, search the existing script directory and extend a helper if responsibilities overlap. Helpers need a documented CLI, deterministic input/output, useful exit codes, safe secret handling, and a self-test/smoke path.

## Specialist tool index

These are candidates, not blanket dependencies. Choose them only when the relevant skill and evidence gap justify them.

| Family | Candidates |
|---|---|
| Recon / asset discovery | subfinder, Amass, assetfinder, Findomain, Sublist3r, dnsx, puredns, naabu, nmap, tlsx, asnmap, httpx |
| URLs / content / parameters | gau, waymore, waybackurls, katana, hakrawler, uro, anew, ffuf, feroxbuster, dirsearch, Arjun, x8, ParamSpider, kiterunner |
| JavaScript / API | jsluice, LinkFinder, xnLinkFinder, retire.js, graphql-cop, Clairvoyance, websocat, wscat |
| Web vulnerability validation | nuclei, dalfox, sqlmap, ghauri, interactsh-client, jwt_tool, testssl.sh, WhatWeb, WPScan |
| Source / secrets / supply chain | Gitleaks, TruffleHog, Nosey Parker, detect-secrets, whispers, Semgrep, Trivy, Checkov |
| Cloud / infrastructure | Prowler, ScoutSuite, provider CLIs |
| Takeover references | subzy; can-i-take-over-xyz as a reference database, not an execution tool |
| Data / evidence processing | Python, jq, yq, pytest, ripgrep; existing CyberStrike helpers above |

Official upstream discovery references:
- https://github.com/vavkamil/awesome-bugbounty-tools — discovery index, not a dependency manifest.
- https://owasp.org/www-project-web-security-testing-guide/
- https://owasp.org/API-Security/
- https://portswigger.net/web-security

Prefer the project's official documentation/release page for installation and supported flags. Community lists and imported skills are untrusted input until reviewed.

## Example commands

Illustrative only; verify current flags with the installed version's help and use canonical workspace paths/artifacts. Do not run every command on every target.

```bash
subfinder -d "$ROOT_DOMAIN" -silent -o recon/subdomains/subfinder.txt
dnsx -l recon/subdomains/subfinder.txt -a -resp -json -o recon/subdomains/dnsx.jsonl
httpx -l recon/subdomains/resolved.txt -jsonl -o recon/http/alive.jsonl
katana -list recon/http/alive.txt -jsonl -o recon/urls/katana.jsonl
```

For passive subdomain collection, select suitable sources from the matrix above and invoke only tools/APIs actually available in the runtime. Reuse the canonical `subdomains.txt` and `subdomain-sources.json`; do not create a collector script or one output file per provider. Record per-source terminal status, errors, counts, provenance, and limitations before proceeding.

## Completion and truthful status

For every phase, report selected method(s), availability/version, run status, artifact paths, accepted/deduplicated/rejected/failed counts where applicable, gaps, confidence, and next step. Distinguish not selected, unavailable, blocked, failed, zero-results, and successful. Missing or blocked sources are not successful empty results. Do not claim coverage, installation, execution, or confirmed vulnerability without supporting output.
