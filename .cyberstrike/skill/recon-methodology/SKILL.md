---
name: recon-methodology
description: "Plan authorized reconnaissance from passive discovery to bounded active validation with reproducible evidence"
category: information-gathering
author: cyberstrike-official
tags: [recon, enumeration, osint, subdomain, web-enumeration, technology-detection]
tech_stack: [linux, dns, http, web]
version: "1.1.0"
chains_with: [attack-subdomain-takeover, attack-host-header, attack-ssrf]
prerequisites: []
---

# Reconnaissance Methodology

## Scope and Safety Preconditions

- Confirm the exact authorized root domains, wildcard rules, excluded hosts, permitted test types, request limits, and engagement window before active probing.
- Keep passive collection separate from active scans. A hostname discovered through OSINT is not automatically in scope; validate ownership/scope before sending probes.
- Start with low request rates and bounded timeouts. Increase concurrency only when the program permits it and the target remains stable. Do not run broad port scans, fuzzing, or vulnerability templates outside the written scope.
- Store outputs in a dedicated working directory and keep credentials, raw private evidence, and target-specific notes out of this reusable skill.

## Prerequisites

- A shell with `curl`, `jq`, `dig`, `subfinder`, `amass`, `dnsx`, `httpx`, `nmap`, and the specific optional tools used below.
- An explicitly authorized target domain set as `TARGET`; optional API keys only for providers you are authorized to use.
- A writable output directory: `OUTPUT_DIR="${OUTPUT_DIR:-./output}"`.

## How to Run

```bash
# Set only a domain that is explicitly in scope; create an isolated output folder
export TARGET="example.com"
export OUTPUT_DIR="${OUTPUT_DIR:-./output}"
mkdir -p "$OUTPUT_DIR"
printf 'Target: %s\nOutput: %s\n' "$TARGET" "$OUTPUT_DIR"
```

## Phase 1: Passive Reconnaissance

### Subdomain Enumeration (Passive)

```bash
# Certificate Transparency
curl --max-time 15 --connect-timeout 5 -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sort -u

# SecurityTrails (optional; set the key only if this provider is authorized)
if [ -n "${SECURITYTRAILS_API_KEY:-}" ]; then
  curl --max-time 15 --connect-timeout 5 -s "https://api.securitytrails.com/v1/domain/$TARGET/subdomains" \
    -H "APIKEY: $SECURITYTRAILS_API_KEY" -o "$OUTPUT_DIR/securitytrails.json"
fi

# Subfinder (passive)
subfinder -d "$TARGET" -silent

# Amass (passive)
amass enum -passive -d "$TARGET"

# Combined approach
subfinder -d "$TARGET" -silent | anew "$OUTPUT_DIR/subs.txt"
amass enum -passive -d "$TARGET" | anew "$OUTPUT_DIR/subs.txt"
```

### Historical Data

```bash
# Wayback Machine URLs
echo "$TARGET" | waybackurls | tee "$OUTPUT_DIR/wayback.txt"

# GAU (GetAllURLs)
echo "$TARGET" | gau --threads 5 | tee "$OUTPUT_DIR/gau.txt"

# Combined historical
cat "$OUTPUT_DIR/wayback.txt" "$OUTPUT_DIR/gau.txt" | sort -u | tee "$OUTPUT_DIR/historical_urls.txt"

# Find parameters
cat "$OUTPUT_DIR/historical_urls.txt" | grep "=" | qsreplace "FUZZ" | sort -u
```

### Technology Detection

```bash
# Wappalyzer CLI
wappalyzer "https://$TARGET"

# WhatWeb
whatweb -a 3 "https://$TARGET"

# BuiltWith API
if [ -n "${BUILTWITH_API_KEY:-}" ]; then curl --max-time 15 --connect-timeout 5 -s "https://api.builtwith.com/v19/api.json?KEY=$BUILTWITH_API_KEY&LOOKUP=$TARGET" -o "$OUTPUT_DIR/builtwith.json"; fi
```

## Phase 2: Active Reconnaissance

Run this phase only against assets confirmed in scope. Use one tool at a time at first and keep logs so repeated probes can be avoided.

### DNS Enumeration

```bash
# DNS records
dig "$TARGET" ANY +noall +answer
dig "$TARGET" MX +short
dig "$TARGET" TXT +short
dig "$TARGET" NS +short

# Zone transfer attempt
dig axfr "@ns1.$TARGET" "$TARGET"

# DNSRecon
dnsrecon -d "$TARGET" -t std

# Subdomain brute force
puredns bruteforce wordlist.txt "$TARGET" -r resolvers.txt
```

### Subdomain Resolution

```bash
# Resolve discovered subdomains
cat "$OUTPUT_DIR/subs.txt" | dnsx -silent -a -resp | tee "$OUTPUT_DIR/resolved.txt"

# Filter live hosts
cat "$OUTPUT_DIR/resolved.txt" | httpx -silent -title -status-code -tech-detect -threads 10 -timeout 10 | tee "$OUTPUT_DIR/live_hosts.txt"

# Keep a URL-only list for tools that expect one URL per line
awk '{print $1}' "$OUTPUT_DIR/live_hosts.txt" | sort -u > "$OUTPUT_DIR/live_urls.txt"

# Screenshot
gowitness file -f "$OUTPUT_DIR/live_urls.txt" --threads 5
```

### Port Scanning

```bash
# Fast scan (top 100)
nmap -F -sV -T2 --max-retries 2 --host-timeout 5m "$TARGET"

# Full TCP scan
nmap -p- -T2 --max-retries 2 --host-timeout 15m "$TARGET"

# UDP scan (top 20)
nmap -sU --top-ports 20 -T2 --max-retries 2 --host-timeout 15m "$TARGET"

# Service version detection
nmap -sV -p 80,443,8080 -T2 --max-retries 2 --host-timeout 10m -oN "$OUTPUT_DIR/nmap-services.txt" "$TARGET"

# Masscan (fast)
masscan -p1-65535 --rate 300 -oJ "$OUTPUT_DIR/scan.json" "$TARGET"
```

## Phase 3: Content Discovery

### Directory Fuzzing

```bash
# Feroxbuster
feroxbuster -u "https://$TARGET" -w /path/to/wordlist.txt -x php,asp,html --threads 10 --rate-limit 5 --time-limit 5m --output "$OUTPUT_DIR/ferox.txt"

# FFUF
ffuf -u "https://$TARGET/FUZZ" -w wordlist.txt -mc 200,301,302,403 -t 10 -rate 5 -maxtime 300 -o "$OUTPUT_DIR/ffuf.json"

# Dirsearch
dirsearch -u "https://$TARGET" -e php,asp,html -t 10 --timeout 10 --max-rate 5 --output "$OUTPUT_DIR/dirsearch.txt"

# Gobuster
gobuster dir -u "https://$TARGET" -w wordlist.txt -x php,html -t 10 --delay 200ms -o "$OUTPUT_DIR/gobuster.txt"
```

### Parameter Discovery

```bash
# Arjun
arjun -u "https://$TARGET/page" --timeout 10 -oJ "$OUTPUT_DIR/arjun.json"

# ParamSpider
python3 paramspider.py -d "$TARGET"

# FFUF parameter fuzzing
ffuf -u "https://$TARGET/page?FUZZ=value" -w params.txt -mc 200 -t 10 -rate 5 -maxtime 300 -o "$OUTPUT_DIR/ffuf-params.json"
```

### JavaScript Analysis

```bash
# Extract JS files
cat $OUTPUT_DIR/live_hosts.txt | getJS --complete | tee $OUTPUT_DIR/js_files.txt

# Find endpoints in JS
cat "$OUTPUT_DIR/js_files.txt" | xargs -I{} sh -c 'curl --max-time 15 --connect-timeout 5 -s "$1" | linkfinder -i -' sh {}

# Find secrets in JS
cat "$OUTPUT_DIR/js_files.txt" | xargs -I{} sh -c 'curl --max-time 15 --connect-timeout 5 -s "$1" | secretfinder -i -' sh {}

# Nuclei JS analysis
nuclei -l "$OUTPUT_DIR/js_files.txt" -t exposures/ -rate-limit 5 -c 5 -timeout 10 -retries 1 -o "$OUTPUT_DIR/nuclei-js.txt"
```

## Phase 4: Vulnerability Discovery

### Automated Scanning

```bash
# Nuclei (comprehensive)
nuclei -l "$OUTPUT_DIR/live_urls.txt" -severity info,low,medium,high,critical -rate-limit 5 -c 5 -timeout 10 -retries 1 -o "$OUTPUT_DIR/nuclei_results.txt"

# Nikto
nikto -h "https://$TARGET" -maxtime 5m -output "$OUTPUT_DIR/nikto.txt"

# WPScan (WordPress)
wpscan --url "https://$TARGET" --enumerate u,p,t --max-threads 5 --throttle 1 --request-timeout 10 --output "$OUTPUT_DIR/wpscan.txt"
```

### Manual Testing Points

```
1. Authentication
   - Login forms
   - Password reset
   - Registration
   - Session management

2. Authorization
   - IDOR on IDs
   - Horizontal privilege escalation
   - Vertical privilege escalation

3. Input Validation
   - All parameters (GET, POST)
   - Headers (Host, Referer, User-Agent)
   - Cookies
   - File uploads

4. Business Logic
   - Price manipulation
   - Quantity tampering
   - Skip steps
   - Race conditions
```

## Reconnaissance Flow

```
Target Domain
     │
     ├── Passive Subdomain Enumeration
     │   ├── crt.sh, SecurityTrails
     │   ├── Subfinder, Amass (passive)
     │   └── Historical data (wayback, gau)
     │
     ├── DNS Enumeration
     │   ├── Record types (A, MX, TXT, NS)
     │   └── Zone transfer attempt
     │
     ├── Active Subdomain Enumeration
     │   └── Brute force (puredns)
     │
     ├── Resolution & Probing
     │   ├── dnsx (resolve)
     │   └── httpx (probe)
     │
     ├── Port Scanning
     │   └── nmap / masscan
     │
     ├── Content Discovery
     │   ├── Directory fuzzing
     │   ├── Parameter discovery
     │   └── JavaScript analysis
     │
     └── Vulnerability Scanning
         ├── Nuclei
         └── Manual testing
```

## Verification and Evidence Hygiene

- Deduplicate and scope-check discovered hostnames before active requests; exclude third-party assets and unresolved ownership questions.
- Verify DNS answers and HTTP liveness independently. A DNS record, open port, technology fingerprint, or HTTP status is a lead, not a vulnerability finding.
- For each candidate finding, record the exact in-scope asset, UTC timestamp, tool/version, request or command, expected behavior, observed behavior, and sanitized evidence.
- Recheck high-signal results manually with a low-impact request. Do not submit a version string, exposed-looking path, or scanner output without confirming meaningful content and impact.
- Keep a list of tested hosts and endpoints to prevent duplicate scans. Stop or reduce rate when latency, errors, lockouts, or service instability increases.
- Related skills use the exact existing names `attack-subdomain-takeover`, `attack-host-header`, and `attack-ssrf`; load them only when discovery provides a relevant signal.

## Scope, Rate Limits, and Stop Conditions

- Establish an explicit allowlist of domains, hosts, ports, and test windows before active probing. A discovered subdomain or linked third-party host is not automatically in scope.
- Keep passive collection separate from active validation in notes and reports. Record source, timestamp, DNS/HTTP result, and the exact command so findings can be reproduced.
- Use bounded concurrency and request timeouts. Start with low request rates, increase only when the program permits it, and stop on elevated error rates, rate-limit responses, service degradation, or an out-of-scope redirect.
- Do not brute-force credentials, run destructive checks, or submit exploit payloads during reconnaissance. Move to a vulnerability-specific skill only after confirming the endpoint is in scope.
- Deduplicate hosts by canonical hostname and resolved asset identity where appropriate; preserve meaningful virtual hosts, ports, and environment differences rather than silently merging them.
- Treat third-party enrichment and scanner output as leads. Verify live reachability and ownership before reporting, and exclude secrets or personal data from saved output.

## Wordlists

| Purpose     | Recommended Wordlist                                                         |
| ----------- | ---------------------------------------------------------------------------- |
| Subdomains  | SecLists/Discovery/DNS/subdomains-top1million-5000.txt                       |
| Directories | SecLists/Discovery/Web-Content/raft-medium-directories.txt                   |
| Files       | SecLists/Discovery/Web-Content/raft-medium-files.txt                         |
| Parameters  | SecLists/Discovery/Web-Content/burp-parameter-names.txt                      |
| Passwords   | SecLists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt |

## Asset Confidence and Recon Prioritization

Keep discovery evidence separate from conclusions. For every asset, track source, timestamp, DNS/HTTP status, ownership confidence, scope decision, and whether active testing is permitted.

| Confidence | Evidence | Next step |
|---|---|---|
| High | exact in-scope hostname or asset listed by the program | test only within the stated limits |
| Medium | linked subdomain, certificate/DNS relationship, or documented vendor asset | verify ownership and scope before active probes |
| Low | inferred IP range, shared hosting, third-party SaaS, or stale passive result | passive research only until scope is confirmed |

Prioritize by likely attack surface and business relevance, not by the number of discovered hosts. Deduplicate hostnames, normalize schemes/ports, preserve the source of each result, and separate live assets from stale DNS or wildcard responses.

For active checks, use bounded concurrency, request timeouts, conservative rate limits, and explicit stop conditions. Do not scan neighboring tenants or third-party infrastructure merely because it resolves from an in-scope domain. Keep raw secrets and personal data out of recon output; retain sanitized command, timestamp, source, and validation evidence for reproducibility.

## References

- [uphiago/recon-skills — subdomain enumeration](https://github.com/uphiago/recon-skills/tree/main/recon/subdomain-enumeration)
- [uphiago/recon-skills — web enumeration](https://github.com/uphiago/recon-skills/tree/main/recon/web-enumeration)
- [uphiago/recon-skills — JavaScript secrets extraction](https://github.com/uphiago/recon-skills/tree/main/recon/js-secrets-extraction)
- [elementalsouls/Claude-BugHunter — recon scope triage](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/recon-scope-triage)
