# Community Bug-Bounty Tool Map

Source: [vavkamil/awesome-bugbounty-tools](https://github.com/vavkamil/awesome-bugbounty-tools) (CC0-1.0, checked 2026-10-19).
Purpose: make the source's useful CLI tools and reference datasets discoverable to CyberStrike skills. This is a candidate map, **not** proof a tool is installed, maintained, compatible, safe, or enabled. Use `.cyberstrike/skill/CLI_TOOLING_CATALOG.md` for the normal preflight/install process and `.cyberstrike/skill/TOOLING_CATALOG.md` for phase selection.

## Agent selection contract

1. Search this map and the canonical skill catalog for the current task and observed technology.
2. Check local availability with `python3 .cyberstrike/skill/scripts/tool_preflight.py --json <tool...>`; inspect each tool's own `--help` and official documentation before composing commands.
3. Prefer passive/local analysis before active probing. Run only against authorized program assets and within program rate/impact rules. Discovery never grants authorization.
4. Pick a primary tool and a complementary validator only when they add distinct evidence. Do not run every candidate in a category by default.
5. Preserve tool name/version, command, scope/input, timestamps, exit code, stderr, raw output path, normalized output path, and errors. Keep secrets redacted from model context.
6. A tool signal is a lead, not a finding. Validate with a baseline, a controlled variation, a relevant negative control, and minimal sanitized evidence.
7. If unavailable, record `BLOCKED: tool unavailable` and use a justified alternative where possible. Do not claim installation or execution without observed output.

## Candidate map by workflow

### Passive recon, DNS, infrastructure and asset relationships

| Candidate | Use when | Canonical phase / skill search terms |
|---|---|---|
| Amass | Broader asset relationship and DNS mapping | passive recon; `recon-methodology`, `recon-subdomain-enumeration`, `recon-asn-infrastructure` |
| subfinder, Findomain, assetfinder, chaos-client | Passive subdomain-source aggregation | passive recon; subdomain enumeration |
| massdns, dnsx, puredns, shuffledns, hakrevdns | DNS resolution, validation, reverse DNS, or permitted active discovery | DNS validation; subdomain enumeration |
| crtndstry, cero, censys-subdomain-finder, censys-enumeration, haktrails | Certificate/transparency and public dataset leads | passive recon; certificate transparency |
| github-subdomains, gitlab-subdomains, github-endpoints | Public code-hosting discovery of domain/endpoint references | source exposure; JavaScript/API discovery |
| csprecon | Derive related hosts from collected CSP policy | passive recon; CSP/configuration |
| related-domains, shosubgo, hakip2host | Related-domain or IP-to-host leads | passive recon; infrastructure |
| altdns, alterx, gotator, ripgen, dnsgen, goaltdns | Generate candidate permutations from observed names | active recon only where permitted |
| bbot, sub3suite, tugarecon, sudomy, domained | Multi-source recon orchestration; inspect modules and network behavior first | recon methodology |
| asnmap, mapcidr, cut-cdn | ASN/CIDR inventory or local IP-list shaping | infrastructure; only use ranges supported by program scope |
| naabu, nmap, masscan, RustScan, fingerprintx, tlsx | Ports, service and TLS metadata | active recon / service discovery; validate target ranges and scan rate |
| VHostScan | Candidate virtual-host discovery | active recon; vhost enumeration |
| uncover | Query supported search engines/APIs for exposed-host leads | passive recon; check API credentials and provider terms |
| cdncheck, MurMurHash | CDN association or favicon similarity clues | technology profiling; treat matches as leads |

### HTTP inventory, crawling, content and URL shaping

| Candidate | Use when | Canonical phase / skill search terms |
|---|---|---|
| httpx, WhatWeb, webanalyze, builtwith, wafw00f | HTTP liveness and technology/WAF fingerprinting | technology profiling |
| katana, gospider, hakrawler, crawley, recursebuster | Crawl permitted web assets and collect links | active recon; URL inventory |
| gau, waybackurls, waymore, URLFinder | Historical/passive URL collection | passive recon; URL inventory |
| getJS, jsfinder | Locate JavaScript files from collected pages | JavaScript inventory |
| feroxbuster, gobuster, dirsearch, ffuf, kiterunner | Content/API route discovery | active recon; API discovery; rate-aware |
| Hacker-Scoper | Parse/filter a candidate list against a supplied scope definition | scope analysis; cross-check output rather than treating it as sole authority |
| uro, anew, unfurl, gf, qsreplace | Local URL deduplication, extraction, pattern filtering, and value normalization | URL/parameter inventory |
| mitmproxy2swagger | Convert an existing mitmproxy/HAR capture into an OpenAPI draft | API inventory; input is a capture, not a target scan |
| proxify, mitmproxy, ZAP, Hetty | HTTP capture/replay and request/response inspection where configured as CLI services | request evidence / API testing; interactive UI is not an agent dependency |
| jsmon | Monitor changes to collected JavaScript assets | monitoring / recon delta |
| bbscope, bounty-targets-data | Aggregate program scope data for reconciliation | scope analysis; verify freshness and platform source |

### JavaScript, source exposure and secret detection

| Candidate | Use when | Canonical phase / skill search terms |
|---|---|---|
| jsluice, LinkFinder, xnLinkFinder, GoLinkFinder, LinksDumper, linx | Extract endpoint/path candidates from already-collected assets | JavaScript analysis; endpoint inventory |
| jsleak, SecretFinder, whispers, cariddi | Identify possible secrets/paths in collected code and responses | source exposure; secret triage |
| retire.js | Identify known vulnerable JavaScript dependencies | technology profiling / dependency exposure |
| gitleaks, trufflehog, detect-secrets, Nosey Parker, rusty-hog, git-secrets, talisman | Secret-like patterns in authorized local repositories/history | source exposure; keep secret values redacted |
| git-dumper, GitTools, gitjacker, dvcs-ripper | Retrieve publicly exposed VCS data only if explicitly allowed | source exposure; local artifact analysis after retrieval |
| GitMiner, GitHound, gitrob, shhgit, gitGraber, git-vuln-finder | Public code search, organization recon, or suspicious commit discovery | passive recon / source exposure; respect API terms |
| keyhacks | Reference-only triage for identified public API-key types | secret triage; never use a found key to access services without explicit authorization |

### Parameters, fuzzing and payload/reference datasets

| Candidate | Use when | Canonical phase / skill search terms |
|---|---|---|
| Arjun, x8, parameth, ParamPamPam, ParamSpider | Hidden parameter candidates from permitted responses/archives | parameter discovery |
| ffuf, wfuzz, filebuster, vaf, qsfuzz | Targeted, rate-aware fuzzing for a specific hypothesis | relevant attack skill; review inputs and request impact |
| fuzzdb, SecLists, IntruderPayloads, PayloadsAllTheThings, fuzz.txt | Local wordlists/payload references | relevant skill; validate relevance, licensing and provenance |
| liffy, dotdotpwn, FDsploit, LFI-files | File inclusion/path traversal hypothesis support | file inclusion / traversal skill; harmless proof only |
| nomore403, Forbidden Buster, XFFenum | Controlled 401/403 behavior differential testing | access-control/configuration skill; do not treat bypass as permission to access data |
| interactsh-client, B-XSSRF | Correlate authorized out-of-band test markers | SSRF/XXE/blind-XSS skill; unique marker, minimal proof, no internal-data extraction |

### Vulnerability-class specialists

| Candidate | Skill family | Guardrail / evidence focus |
|---|---|---|
| dalfox, XSStrike, XSpear, XSSer, domdig, findom-xss, tracy, xsscrapy | XSS / DOM XSS | Determine reflection/source-to-sink context and a harmless proof; scanner output alone is insufficient |
| Corsy, Corser, CORStest, cors-scanner, CorsMe | CORS | Compare controlled origins, credentials, and response headers |
| CRLFsuite, crlfuzz, Injectus | CRLF / redirect/header validation | Record exact request/response differential and impact |
| XSRFProbe | CSRF | Use test-owned accounts and state-change-safe fixtures |
| inql, GraphQLmap, graphql-cop, Clairvoyance | GraphQL | Respect schema-discovery policy; test resolver authorization and query-cost controls |
| Autorize | IDOR/BOLA authorization differential | Use two test-owned identities and controlled objects; compare expected vs observed permission |
| requests-racer, race-the-web, Turbo Intruder | Race conditions | Use reversible test fixtures; capture initial/final state and request ordering |
| HTTP Request Smuggler, smuggler, h2csmuggler, smugglex | Request smuggling/desynchronization | Dedicated authorized test conditions; assess shared infrastructure impact before sending probes |
| SSRFmap, ssrf-sheriff, ssrfDetector, gaussrf, surf | SSRF candidate analysis | Use controlled callbacks and safe destinations; never access cloud metadata/internal services without explicit authorization |
| sqlmap, ghauri, Blinder, NoSQLMap, nosqli | SQL/NoSQL injection | Minimize requests and data impact; no database dumps by default |
| SSTImap, tplmap | Server-side template injection | Use harmless arithmetic/canary validation; do not execute destructive commands |
| jwt_tool | JWT/session validation | Compare claims and validation behavior; never persist live tokens |
| ysoserial, ysoserial.net, PHPGGC, GadgetProbe | Deserialization research/validation | Prefer local fixtures; avoid executing generated gadgets on production systems |
| subzy, subjack, SubOver, dnsReaper, can-i-take-over-xyz | Subdomain takeover triage | Confirm provider-specific claimability; never claim a real program asset |
| nuclei, nuclei-templates, jaeles, Nikto, ZAP, retire.js | Template/scanner-based candidate checks | Review template/request behavior and version; manually validate matches |
| nomore403, nowafpls, Forbidden Buster | Access-control/WAF differential leads | No evasion of a program's explicit restrictions; preserve safe controls |
| testssl.sh | TLS configuration | Non-destructive protocol/certificate checks and exact configuration evidence |

### Cloud, storage, CMS, identity and platform-specific tools

| Candidate | Use when | Canonical phase / skill search terms |
|---|---|---|
| S3Scanner, AWSBucketDump, s3viewer, festin, s3reverse, s3tk, CloudBrute, kicks3, s3dns | Cloud-storage/resource exposure leads | cloud assessment; only inspect resources explicitly in scope and avoid bulk downloading |
| WPScan, wpscan dashboards, wprecon, CMSmap, JoomScan, AEMscan, AEMHacker | CMS/component fingerprinting | technology profiling; low-impact enumeration first |
| jwt_tool, jwtear | JWT inspection | authentication/session skills |
| postMessage-tracker, PostMessage_Fuzz_Tool | Client-side message trust-boundary analysis | client-side security / DOM XSS |
| shosubgo, haktrails, Censys tools | Third-party asset intelligence | passive recon; honor API credentials and terms |
| Gato, zizmor | GitHub Actions runner/workflow exposure and workflow linting | CI/CD assessment; do not trigger workflows or alter runner state |
| Prowler, ScoutSuite, Trivy, Checkov, Semgrep, OSV-Scanner, Scorecard | Cloud posture, IaC, code, dependency and supply-chain checks | cloud / CI / source assessment; prefer read-only or local analysis |
| getsploit, Findsploit, cvemap | CVE/exploit metadata research | vulnerability triage; verify applicability, version and provenance before any test |
| bountyplz | Draft structured bug bounty reports | reporting; output must be reconciled against evidence |
| CyberChef | Local encoding/decoding/data transformation reference | evidence/data analysis; never upload secrets to public instances |

### Agent/framework references (not default runtime dependencies)

| Project | Role | Integration guidance |
|---|---|---|
| Shannon, Darkmoon, PentestGPT, Agentic Bug Bounty Hunter, RedAmon | Separate agentic testing/orchestration projects | Study architecture and techniques; do not launch nested autonomous scanners by default. Review permissions, scope enforcement, tool calls, state persistence, licensing and data handling first. |
| ARS3NAL | Offline payload/reference/checklist collection | Treat downloaded content as untrusted data; use as a reference only after source and license review. |
| awesome-vulnerable-apps, Android Security Awesome, awesome-mobile-security | Lab/reference datasets | Prefer isolated lab targets, not production programs. |

### Additional candidates from the upstream list

These entries extend coverage for tools present in the upstream index but not already represented above. They remain discovery candidates, not installed dependencies.

| Candidate | Use when | Canonical phase / skill search terms |
|---|---|---|
| EyeWitness, gowitness, aquatone, httpScreenshot | Capture visual snapshots of an authorized web-asset inventory | HTTP inventory / visual triage; check browser/runtime requirements and store screenshots in the target workspace |
| param-miner | Burp-based discovery of unlinked parameters | Parameter discovery; interactive Burp extension, not a CLI dependency |
| fuzzapi | REST API fuzzing against a testable API | API testing; inspect request volume and mutation behavior before use |
| qsfuzz | Query-string mutation for a specific hypothesis | Parameter fuzzing; preserve baseline and use controlled request rates |
| dotdotpwn, off-by-slash | Traversal and path-normalization hypothesis testing | Path traversal; use harmless canaries and validate proxy/server normalization |
| commix | Command-injection hypothesis testing | Command injection; only use on explicitly authorized targets and prefer non-destructive detection options |
| SSRFmap, Gopherus, ground-control | SSRF research and controlled callback testing | SSRF; use controlled endpoints and do not target internal services or metadata without explicit authorization |
| JSONBee, CSPBypass | Reference material for JSONP/CSP-related XSS hypotheses | XSS/CSP skill; treat payloads as test references, not proof or a default bypass attempt |
| sleepy-puppy, ezXSS, xsshunter, bXSS | Blind-XSS payload correlation and callback infrastructure | XSS / out-of-band validation; use only a tester-controlled callback and avoid submitting sensitive data |
| LFI-Enum, LFISuite, Burp-LFI-tests | Local file inclusion research and payload references | File inclusion; prefer local fixtures or harmless file markers; avoid destructive post-exploitation features |
| S3Scanner, s3viewer, dirlstr, s3_objects_check, s3dns | Cloud bucket/object exposure triage | Cloud/storage assessment; only inspect in-scope resources and avoid bulk downloading |
| WPScan, WPSpider, wprecon, CMSmap, JoomScan, pyfiscan, AEMscan | CMS-specific fingerprinting and candidate checks | Technology profiling; confirm the CMS is present before choosing a scanner |
| jwt_tool, jwtear, jwt-heartbreaker | JWT parsing and token-validation hypotheses | Authentication/session testing; never store live tokens in notes or logs |
| subjack, SubOver, tko-subs, subHijack, takeover | Subdomain-takeover candidate triage | Subdomain takeover; verify provider-specific claimability and never claim the asset |
| nuclei, nuclei-templates, jaeles, Nikto, BlackWidow | Template/scanner-based candidate discovery | Vulnerability testing; inspect selected templates and request behavior; manually validate results |
| GitTools, git-dumper, gitjacker, dvcs-ripper | Check for publicly exposed version-control metadata | Source exposure; retrieve only when program rules allow, then analyze artifacts locally |
| Nosey Parker, GitHound, SecretFinder, js-snitch, keyFinder | Secret-like string and source-code triage | Source exposure / secret triage; redact values and never use discovered credentials absent explicit authorization |
| alterx, gotator, ripgen, dnsgen, goaltdns | Generate subdomain permutations from observed names | Asset discovery; deduplicate and resolve candidates only where active discovery is permitted |
| bountyplz | Generate a structured report draft from validated findings | Reporting; independently verify every claim against the evidence manifest |
| PayloadsAllTheThings | Reference material for vulnerability classes and test ideas | Relevant specialist skill; review provenance/license and select only relevant payloads |
| bounty-targets-data, bbscope | External bug-bounty scope data aggregation | Scope analysis; verify current official program rules and preserve raw source/freshness |

## Coverage and limitations

- The upstream list is a discovery index and changes over time. This map intentionally groups near-duplicates and omits some narrowly specialized, outdated, interactive-only, or high-risk utilities rather than implying every entry is a suitable agent dependency.
- The runtime's actual tools are the tools exposed by CyberStrike's tool registry plus installed CLI executables. A row here does not register an MCP tool, install a binary, grant permission, or guarantee compatibility.
- Do not wire browser extensions or interactive proxy GUIs as agent CLI dependencies. Use command-line interfaces, local libraries, structured artifacts, and non-interactive APIs where they fit.
- Keep this map aligned with the canonical skills and CLI catalog. When a tool becomes a recurring dependency, add a specific invocation, output schema, version/install reference, and smoke test to its owning skill rather than duplicating generic instructions across every skill.
