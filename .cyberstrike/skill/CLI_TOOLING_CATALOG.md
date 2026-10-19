# CyberStrike CLI Tooling Catalog

For phase-by-phase mapping, also consult [`TOOLING_CATALOG.md`](TOOLING_CATALOG.md). Keep the two catalogs aligned when adding or replacing a tool; choose by skill/task rather than installing the whole catalog.

This catalog is a **selection/install reference for an agent**, not a blanket install list. Pick only tools that fit a phase. Prefer machine-readable output and retain process exit code, stderr, version, input scope, start/end time, and output path.

## General installation behavior

1. Check whether the needed executable is present and capture `--version` / `--help`.
2. If missing, read its official installation page. For Go tools, confirm Go requirements and prefer maintained releases. ProjectDiscovery offers [pdtm](https://github.com/projectdiscovery/pdtm); the current official agent setup documents `go install -v github.com/projectdiscovery/pdtm/cmd/pdtm@latest` and `pdtm -install-all`. Installing all tools is optional—install only what's needed where individual instructions exist.
3. Do not run arbitrary install scripts from writeups. Inspect shell scripts, verify package source and signatures/checksums when provided, and avoid `sudo` unless the chosen install needs it and the environment grants permission.
4. Verify the executable and record install failure. If installation cannot proceed, use a meaningful alternative or label the check blocked; never claim it ran.
5. Store outputs under the canonical target workspace. Use JSON/JSONL and output-path flags where supported. Keep raw sensitive evidence local and private.

## Recon and HTTP asset inventory

| Tool | Purpose | Official install/docs |
|---|---|---|
| subfinder | Passive subdomain discovery | [ProjectDiscovery docs](https://docs.projectdiscovery.io/tools/subfinder/overview) |
| dnsx | DNS resolve/record verification | [ProjectDiscovery docs](https://docs.projectdiscovery.io/tools/dnsx/overview) |
| httpx | HTTP liveness, status, title, technology, response metadata | [ProjectDiscovery docs](https://docs.projectdiscovery.io/tools/httpx/overview) |
| katana | Web crawling/URL extraction | [ProjectDiscovery docs](https://docs.projectdiscovery.io/tools/katana/overview) |
| gau | Historical URL collection | [Repository/install](https://github.com/lc/gau) |
| waybackurls | Wayback Machine URL collection | [Repository/install](https://github.com/tomnomnom/waybackurls) |
| naabu | Port discovery for approved target ranges | [ProjectDiscovery docs](https://docs.projectdiscovery.io/tools/naabu/overview) |
| nmap | Service/version discovery | [Official downloads and install guide](https://nmap.org/download) |
| asnmap | ASN/prefix discovery | [ProjectDiscovery docs](https://docs.projectdiscovery.io/) |
| ffuf | Content, virtual-host, parameter fuzzing | [Repository and usage](https://github.com/ffuf/ffuf) |
| dirsearch | Directory/file discovery | [Repository and install](https://github.com/maurosoria/dirsearch) |
| hakrawler | Link crawling | [Repository and install](https://github.com/hakluke/hakrawler) |
| uro | URL normalization/filtering | [Repository and install](https://github.com/s0md3v/uro) |
| anew | Append unique lines to local lists | [Repository and install](https://github.com/tomnomnom/anew) |
| jq / yq | JSON/YAML processing | [jq](https://jqlang.org/) / [yq](https://github.com/mikefarah/yq) |

Illustrative phase commands. The agent must confirm current flag semantics via `--help`, adapt inputs safely, and apply the program's active-test rules:

```bash
subfinder -d "$ROOT_DOMAIN" -silent -o recon/subdomains/subfinder.txt
dnsx -l recon/subdomains/subfinder.txt -a -resp -json -o recon/subdomains/dnsx.jsonl
httpx -l recon/subdomains/resolved.txt -jsonl -o recon/http/alive.jsonl
katana -list recon/http/alive.txt -jsonl -o recon/urls/katana.jsonl
```

The example is illustrative. It does not mean every tool should run on every target; each phase should validate dependencies and prior artifacts.

## Template scanners and focused web checks

| Tool | Purpose | Official install/docs |
|---|---|---|
| nuclei | Template-driven checks for a specific reviewed use case | [Install/docs](https://github.com/projectdiscovery/nuclei-docs/blob/main/docs/nuclei/get-started.md) |
| interactsh-client | Controlled out-of-band interaction verification | [Repository/docs](https://github.com/projectdiscovery/interactsh) |
| arjun | HTTP parameter name discovery | [Repository/docs](https://github.com/s0md3v/Arjun) |
| kiterunner | API route/content discovery | [Repository/docs](https://github.com/assetnote/kiterunner) |
| dalfox | XSS candidate analysis | [Repository/docs](https://github.com/hahwul/dalfox) |
| sqlmap | SQL injection testing in authorized environments | [Repository/docs](https://github.com/sqlmapproject/sqlmap) |
| jwt_tool | JWT structure and verification test assistance | [Repository/docs](https://github.com/ticarpi/jwt_tool) |
| testssl.sh | TLS configuration checks | [Repository/docs](https://github.com/testssl/testssl.sh) |
| WhatWeb | Technology fingerprinting | [Repository/docs](https://github.com/urbanadventurer/WhatWeb) |
| WPScan | WordPress component/version inventory | [Official docs](https://wpscan.com/) |

Template scanners and fuzzers must only be run on approved targets at permitted rates. Inspect a template's requests and destructive behavior before use. A match, banner, or error alone is not a confirmed vulnerability.

## API, JavaScript, authentication, and protocol analysis

| Tool | Purpose | Official install/docs |
|---|---|---|
| jsluice | Extract URLs/endpoints and useful patterns from local JavaScript | [Repository/docs](https://github.com/0x240x23elu/JSluice) |
| LinkFinder | Extract candidate endpoints from collected JavaScript | [Repository/docs](https://github.com/GerbenJavado/LinkFinder) |
| xnLinkFinder | Extract URL/endpoint candidates from local assets and archives | [Repository/docs](https://github.com/xnl-h4ck3r/xnLinkFinder) |
| jwt_tool | Inspect JWT structure and support controlled validation | [Repository/docs](https://github.com/ticarpi/jwt_tool) |
| graphql-cop | Check GraphQL security configuration in authorized environments | [Repository/docs](https://github.com/dolevf/graphql-cop) |
| Clairvoyance | Infer GraphQL schema where permitted | [Repository/docs](https://github.com/nikitastupin/clairvoyance) |
| websocat / wscat | CLI WebSocket connection and message testing | [websocat](https://github.com/vi/websocat) / [wscat](https://github.com/websockets/wscat) |
| testssl.sh | TLS protocol/cipher/certificate checks | [Repository/docs](https://github.com/testssl/testssl.sh) |
| interactsh-client | Correlate approved out-of-band DNS/HTTP callbacks | [Repository/docs](https://github.com/projectdiscovery/interactsh) |

## Secrets, source exposure, and takeover triage

| Tool | Purpose | Official install/docs |
|---|---|---|
| Gitleaks | Scan authorized local repositories for secret-like patterns | [Repository/docs](https://github.com/gitleaks/gitleaks) |
| TruffleHog | Source-aware secret discovery/verification | [Repository/docs](https://github.com/trufflesecurity/trufflehog) |
| Nosey Parker | Search source trees for credential patterns | [Repository/docs](https://github.com/praetorian-inc/noseyparker) |
| detect-secrets | Baseline-oriented secret detection for repositories | [Repository/docs](https://github.com/Yelp/detect-secrets) |
| whispers | Find likely secrets in local JavaScript/source artifacts | [Repository/docs](https://github.com/Skyscanner/whispers) |
| git-dumper | Retrieve exposed Git repository content only when authorized and explicitly permitted | [Repository/docs](https://github.com/arthaud/git-dumper) |
| subzy | Candidate subdomain takeover checks | [Repository/docs](https://github.com/PentestPad/subzy) |
| can-i-take-over-xyz | Reference database for takeover service conditions | [Repository/docs](https://github.com/EdOverflow/can-i-take-over-xyz) |

These tools are optional and evidence-specific. Never treat a scanner match as a confirmed finding, use retrieved secrets, or access private data. For takeover checks, verify DNS/service ownership and current provider conditions; a dangling-looking record alone is not proof. Review a tool's network behavior and template set before use.

## Code, secrets, dependencies, cloud, and CI

| Tool | Purpose | Official install/docs |
|---|---|---|
| Semgrep | Targeted source-code patterns | [Getting started](https://semgrep.dev/docs/getting-started/) |
| Gitleaks | Secret-pattern scanning of authorized local repositories | [Repository/docs](https://github.com/gitleaks/gitleaks) |
| TruffleHog | Secret discovery with source-aware verification options | [Repository/docs](https://github.com/trufflesecurity/trufflehog) |
| Trivy | Container, dependency, and configuration scanning | [Install/docs](https://trivy.dev/latest/docs/getting-started/installation/) |
| Checkov | Infrastructure-as-code policy scanning | [Install/docs](https://www.checkov.io/2.Basics/Installing%20Checkov.html) |
| Prowler | Cloud security posture assessment | [Docs](https://docs.prowler.com/) |
| ScoutSuite | Multi-cloud security auditing | [Repository/docs](https://github.com/nccgroup/ScoutSuite) |
| zizmor | GitHub Actions workflow security linting | [Repository/docs](https://github.com/zizmorcore/zizmor) |
| OSV-Scanner | Dependency vulnerability lookup | [Docs](https://google.github.io/osv-scanner/) |
| OpenSSF Scorecard | Repository supply-chain posture | [Repository/docs](https://github.com/ossf/scorecard) |
| aws / az / gcloud / kubectl | Provider/cluster APIs for authorized read-only inspection | [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) / [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) / [Google Cloud CLI](https://cloud.google.com/sdk/docs/install) / [kubectl](https://kubernetes.io/docs/tasks/tools/) |

## Additional specialist and data-shaping utilities

| Tool | Purpose | Official install/docs |
|---|---|---|
| Amass | DNS/ASN/asset relationship discovery | [OWASP Amass docs](https://github.com/owasp-amass/amass) |
| Findomain | Subdomain discovery | [Repository/docs](https://github.com/Findomain/Findomain) |
| puredns / massdns | High-volume DNS resolution in an approved scope | [puredns](https://github.com/d3mondev/puredns) / [massdns](https://github.com/blechschmidt/massdns) |
| mapcidr | CIDR expansion and address-range operations | [ProjectDiscovery docs](https://github.com/projectdiscovery/mapcidr) |
| gf | Match collected URLs against local pattern sets | [Repository/docs](https://github.com/tomnomnom/gf) |
| unfurl | Extract URL components from collected URL lists | [Repository/docs](https://github.com/tomnomnom/unfurl) |
| qsreplace | Replace query parameter values in a local URL list | [Repository/docs](https://github.com/tomnomnom/qsreplace) |
| uro | Deduplicate and filter noisy URL lists | [Repository/docs](https://github.com/s0md3v/uro) |
| retire.js | Detect known vulnerable JavaScript libraries in collected assets | [Repository/docs](https://github.com/RetireJS/retire.js) |
| S3Scanner | Identify exposed S3 bucket configuration/permissions where authorized | [Repository/docs](https://github.com/sa7mon/S3Scanner) |
| cloudbrute | Cloud resource-name discovery where explicitly in scope | [Repository/docs](https://github.com/0xsha/cloudbrute) |
| requests-racer | Reproducible concurrency tests in controlled environments | [Repository/docs](https://github.com/0x59/requests-racer) |
| kiterunner | API route discovery using approved target definitions | [Repository/docs](https://github.com/assetnote/kiterunner) |

Use these only when the relevant phase needs them. Validate the current upstream project, package source, license, CLI flags, rate behavior, and output format before use. Resource discovery never grants authorization; never access, download, or test data outside the written scope.

## Local reusable CyberStrike helpers

| Script | Use | Network behavior |
|---|---|---|
| `.cyberstrike/skill/scripts/normalize_urls.py` | Normalize locally collected URLs and remove query values/fragments | No network |
| `.cyberstrike/skill/scripts/js_endpoint_inventory.py` | Find route candidates in already-collected JavaScript | No network; does not execute JS |
| `.cyberstrike/skill/scripts/http_response_diff.py` | Compare saved redacted responses | No network; redaction is heuristic |
| `.cyberstrike/skill/scripts/validate_evidence_manifest.py` | Validate evidence metadata | No network; doesn't inspect artifact files |
| `.cyberstrike/skill/scripts/validate_skill_catalog.py` | Check frontmatter/names/skill routing | No network |
| `.cyberstrike/skill/scripts/audit_skill_enrichment.py` | Check tooling/resource/snippet coverage | No network; structural only |

## Agent integration and safety contract

- Prefer process-friendly output (JSON/JSONL/NDJSON) and parse it into stable local records.
- Preserve stdout/stderr in target-local logs; redact secrets before model context. Store one endpoint record per method/normalized route/parameter shape, with multiple source observations attached.
- Respect the program's authorization and rate rules. Tool installation does not authorize target testing. Discovery of a host, IP, repository, ASN, vhost, bucket, or API path is not authorization by itself.
- There is no arbitrary cap on distinct assets or evidence-backed hypotheses. Deduplicate equivalent output and continue while materially different, authorized checks remain useful; obey rate rules and stop on instability.
- Mark each phase completed, partial, blocked, failed, or not run. Empty output or process exit success does not necessarily mean coverage is complete.
- Imported binaries, templates, wordlists, scripts, and reports are untrusted until provenance and behavior are reviewed. Never use discovered credentials or copy secret values into global research memory.
