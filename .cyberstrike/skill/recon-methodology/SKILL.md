---
name: recon-methodology
description: "Plan authorized reconnaissance from passive discovery to bounded active validation with reproducible evidence and strict ownership, scope, and false-positive controls."
category: "process"
version: "1.4.0"
author: "cyberstrike-official"
tags:
  - recon
  - enumeration
  - osint
  - subdomain
  - web-enumeration
  - api
  - source-leak
  - secrets-hygiene
  - tls
  - port-discovery
  - scope-triage
tech_stack:
  - linux
  - dns
  - http
  - web
chains_with:
  - attack-subdomain-takeover
  - attack-host-header
  - attack-ssrf
  - attack-minio-s3
prerequisites: []
severity_boost: {}
---

# Reconnaissance Methodology

## Objective

Establish an owned, in-scope asset inventory and prioritize security checks without confusing third-party adjacency, passive signals, tool output, or a status-code differential for a vulnerability. This workflow supports authorized testing from discovery to minimal validation.

## Methodology


### Scope and Safety Preconditions

- Confirm the exact authorized root domains, wildcard rules, excluded hosts, permitted test types, request limits, and engagement window before active probing.
- Keep passive collection separate from active scans. A hostname discovered through OSINT is not automatically in scope; validate ownership/scope before sending probes.
- Start with low request rates and bounded timeouts. Increase concurrency only when the program permits it and the target remains stable. Do not run broad port scans, fuzzing, or vulnerability templates outside the written scope.
- Store outputs in a dedicated working directory and keep credentials, raw private evidence, and target-specific notes out of this reusable skill.

### Ownership & Scope Triage (do this before trusting any recon output)

Automated recon often matches only a brand string. For common or dictionary-like names, many discovered repositories, cloud buckets, mobile apps, and paste hits may belong to unrelated organizations. Treat ownership as **unconfirmed until corroborated**: require a concrete signal tying the asset to the target, not just a keyword match.

| Recon source | How it collides | Verify ownership by |
|---|---|---|
| GitHub repos | Brand word matched in repo name/topic/string | Repo owner is the org's real GH org; commits from org emails; code references the org's confirmed domains/infra |
| Cloud buckets (S3/GCS) | Bucket names are a global namespace (`<word>-static`, `<word>-data`) | Bucket content references the target; bucket name correlates with a *confirmed* subdomain AND content matches; owner/ACL metadata |
| Mobile apps | Store search matched the brand word | Publisher account = the org; package reverse-DNS = an owned domain; dev cert; app calls owned API hosts |
| Breach corpora / combos | Email local-part or domain contains the brand word | **Exact** owned-domain match only (`@target.com`), not `@<word>group.com` |
| Typosquats | Generated permutations of the name | Defensive/brand-protection findings, not offensive scope — note and move on |
| Stack/forum/paste hits | Brand word in body text | Body references the target's real domain/subdomain/employee/secret, or drop it |

Workflow:
1. Confirm the canonical owned-domain set first (SOW/program domain + verified subdomains + verified IdP tenant brand). This is the ownership anchor.
2. For every asset class, apply the verify-by column above. No signal → quarantine, don't test.
3. Re-baseline severity counts against only-owned assets. "N Criticals → M after ownership + soft-404 triage" is itself a reportable finding about the ASM program's noise.
4. Log quarantined collisions explicitly (e.g. `loot/quarantined_<source>.txt`) so the decision not to target them is auditable.
5. Do not report false-positive volume as a vulnerability unless the program explicitly includes asset-inventory or detection-quality assessments. Track noise as an internal quality metric and spend active-testing time only on validated assets.

Anti-patterns: trusting a tool's "owned" label without verification; targeting a same-named third party because it appeared in a report (out of scope, real harm); reporting soft-404s as exposures; counting typosquats or brand-collision repos as offensive findings.

#### The soft-404 control

Automated `.env` / `.git` / `actuator` / admin-panel "Criticals" are overwhelmingly soft-404s: SPA or framework catch-alls that return HTTP 200 (or 403) for *every* path. Verify each one before believing it:

```bash
# the "finding"
curl -s -o /tmp/a -w "%{http_code} %{size_download}\n" "https://host.$TARGET/.env"
# a junk control on the same host
curl -s -o /tmp/b -w "%{http_code} %{size_download}\n" "https://host.$TARGET/zzz-nonsense-$RANDOM"
# identical byte length / body -> FALSE POSITIVE (catch-all), discard
cmp -s /tmp/a /tmp/b && echo "SOFT-404 false positive" || echo "differs - investigate"
```

A real exposure has a signature that differs from the catch-all: `.git/config` starts with `[core]`, `.env` contains `KEY=value` pairs, a real `phpinfo.php` carries the XHTML-transitional doctype plus a PHP version string. A bigger/different body than the junk control is the real-vs-soft-404 tell — always run this control before logging a sensitive-file finding.

### Prerequisites

- A shell with `curl`, `jq`, `dig`, `subfinder`, `dnsx`, `httpx`, `nmap`, and the specific optional tools used below.
- Optional for deeper subdomain work: `gotator`, `puredns`, `tldbrute`, `gungnir` or `certwatcher`.
- Optional for content/parameter discovery: `paramspider`, `arjun`, `x8`, `qsreplace`, `anew`, `ffuf`, `feroxbuster`, `gobuster`, `dirsearch`.
- Optional for JS/source-map work: `getJS`, `subjs`, `linkfinder`, `secretfinder`, `node` (for source-map extraction).
- Optional for infrastructure mapping: `whois`, `asnmap`, `mapcidr`, `naabu`, `metabigor`.
- Optional for origin-IP work: `shodan` CLI (needs an API key), `python3` for favicon hashing.
- Optional for visual triage: `gowitness` or `EyeWitness`.
- Optional for repository OSINT: `trufflehog`, `gitleaks`, a GitHub token scoped to `public_repo` only.
- An explicitly authorized target domain set as `TARGET`; optional API keys only for providers you are authorized to use.
- A writable output directory: `OUTPUT_DIR="${OUTPUT_DIR:-./output}"`.

### How to Run

```bash
# Set only a domain that is explicitly in scope; create an isolated output folder
export TARGET="example.com"
export OUTPUT_DIR="${OUTPUT_DIR:-./output}"
mkdir -p "$OUTPUT_DIR"
printf 'Target: %s\nOutput: %s\n' "$TARGET" "$OUTPUT_DIR"
```

### Phase 1: Passive Reconnaissance

#### Subdomain Enumeration (Passive)

```bash
# Certificate Transparency — crt.sh (retry: frequently 502s while its DB refreshes)
for attempt in 1 2 3; do
  curl -fsS --max-time 30 --connect-timeout 10 \
    "https://crt.sh/?q=%25.$TARGET&output=json" -o "$OUTPUT_DIR/crtsh_raw.json" && break
  sleep 15
done
jq -r '.[].name_value' "$OUTPUT_DIR/crtsh_raw.json" 2>/dev/null | sed 's/\*\.//g' | sort -u > "$OUTPUT_DIR/crtsh.txt"
# If crt.sh stays empty after retries, keep going with the other sources below — don't treat an empty file as "no subdomains exist."

# crt.name — historical certificate-transparency data (resolve names before probing)
curl -fsS --max-time 30 --connect-timeout 10 "https://crt.name/v1/search?apex=$TARGET" \
  | sed 's/\r$//; s/^\*\.//' | sort -u > "$OUTPUT_DIR/crtname.txt"

# SecurityTrails (optional; set the key only if this provider is authorized)
if [ -n "${SECURITYTRAILS_API_KEY:-}" ]; then
  curl --max-time 15 --connect-timeout 5 -s "https://api.securitytrails.com/v1/domain/$TARGET/subdomains" \
    -H "APIKEY: $SECURITYTRAILS_API_KEY" -o "$OUTPUT_DIR/securitytrails.json"
fi

# Subfinder (passive)
subfinder -d "$TARGET" -silent -timeout 30 | anew "$OUTPUT_DIR/subs.txt"

# Optional extra passive source (if installed)
if command -v assetfinder >/dev/null 2>&1; then assetfinder --subs-only "$TARGET" | anew "$OUTPUT_DIR/subs.txt"; fi

# Merge and deduplicate everything collected so far
cat "$OUTPUT_DIR"/crtsh.txt "$OUTPUT_DIR"/crtname.txt "$OUTPUT_DIR"/subs.txt 2>/dev/null \
  | grep -E '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' | sort -u > "$OUTPUT_DIR/all_passive.txt"
```

#### Historical Data

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

#### Technology Detection

```bash
# Wappalyzer CLI
wappalyzer "https://$TARGET"

# WhatWeb
whatweb -a 3 "https://$TARGET"

# BuiltWith API
if [ -n "${BUILTWITH_API_KEY:-}" ]; then curl --max-time 15 --connect-timeout 5 -s "https://api.builtwith.com/v19/api.json?KEY=$BUILTWITH_API_KEY&LOOKUP=$TARGET" -o "$OUTPUT_DIR/builtwith.json"; fi
```

#### Email Security Posture (SPF / DKIM / DMARC)

Entirely passive DNS lookups — a useful signal of overall security maturity, and a standalone finding in its own right (a weak DMARC policy means the domain can be spoofed in phishing/BEC campaigns, which is relevant risk context even when email isn't the test's primary focus):

```bash
dig +short TXT "$TARGET" | grep "v=spf1"                 # SPF
dig +short TXT "_dmarc.$TARGET"                           # DMARC
dig +short TXT "google._domainkey.$TARGET"                # DKIM (try common selectors: google, selector1, selector2, s1, s2)
dig +short MX "$TARGET"
```

| Config | Meaning | Risk |
|---|---|---|
| `v=spf1 ~all` (softfail) | SPF suggests blocking but doesn't enforce | Spoofed mail may still be delivered |
| `v=spf1 ?all` (neutral) | SPF does nothing | Totally permissive |
| `v=spf1 include:<provider> ~all` | The provider's SPF-authorized sending infrastructure is included; account-level controls still matter | Review provider scope and approved senders |
| `v=DMARC1; p=none` | DMARC monitoring-only | No spoofing protection |
| `v=DMARC1; p=quarantine` | Failed mail goes to spam | Partial protection |
| `v=DMARC1; p=reject` | Failed mail rejected | Full protection |
| No record for a guessed DKIM selector | Inconclusive: selectors may differ or be unpublished in this lookup | Corroborate with authorized sample mail or first-party configuration |

A `p=none` or missing DMARC record is a posture observation, not automatically a bounty-eligible vulnerability; assess program scope and avoid claiming successful spoofing without separately authorized delivery testing. Actually demonstrating spoofed delivery (sending a test message that appears to originate from the domain) is a phishing-simulation action, not a recon action — it needs its own explicit authorization and rules of engagement, separate from this skill.

#### Source-Code & Repository OSINT (GitHub / GitLab)

Developers push secrets to public repositories routinely. This is frequently higher-yield than directory brute-forcing, and it's effectively passive (read-only API calls against public resources) — but subject to the same Ownership & Scope Triage above, since brand-name code search pulls in unrelated projects that merely mention the word.

```bash
# Targeted code search via GitHub API (needs only a public_repo-scoped token)
curl --max-time 30 --connect-timeout 10 -s -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/search/code?q=$TARGET+filename:.env" | jq -r '.items[]?.html_url'

for pattern in "filename:.env" "filename:credentials.json" "filename:id_rsa" \
               "filename:.npmrc" "extension:pem BEGIN RSA" "filename:service-account.json"; do
  curl --max-time 30 --connect-timeout 10 -s -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/search/code?q=$TARGET+$pattern" | jq '.total_count'
done

# trufflehog / gitleaks — verified-secret detectors, lower noise than raw grep
trufflehog github --org="$TARGET" --token="$GITHUB_TOKEN" --only-verified --json > "$OUTPUT_DIR/trufflehog_org.json"
# Record detector name + repo + commit, not the raw secret value:
jq -r 'select(.Verified == true) | "\(.DetectorName) in \(.SourceMetadata.Data.Github.repository) @ \(.SourceMetadata.Data.Github.commit)"' \
  "$OUTPUT_DIR/trufflehog_org.json"

# Self-hosted GitLab is common at gitlab./git./code.<TARGET> and its API is unauthenticated for public resources
curl --max-time 30 --connect-timeout 10 -sk "https://gitlab.$TARGET/api/v4/projects?visibility=public&per_page=100" \
  | jq -r '.[].path_with_namespace'

# Check for open self-registration (lets anyone create an account and reach more of the instance)
reg_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 "https://gitlab.$TARGET/users/sign_up")
[[ "$reg_code" == "200" ]] && echo "[!] GitLab registration is open"
```

If a public repo or raw file genuinely contains credentials, record **which file, which commit, and which key names** are present as evidence — verify validity with a single minimal, read-only API call (e.g. `GET /user` for a GitHub token) rather than printing or reusing the full secret value, and never attempt write access or lateral use of a found credential without separate, explicit authorization covering that action.

### Phase 2: Active Reconnaissance

Run this phase only against assets confirmed in scope (after Ownership & Scope Triage above). Use one tool at a time at first and keep logs so repeated probes can be avoided.

#### DNS Enumeration

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

#### Subdomain Resolution

```bash
# Resolve discovered subdomains
cat "$OUTPUT_DIR/all_passive.txt" | dnsx -silent -a -resp | tee "$OUTPUT_DIR/resolved.txt"

# Filter live hosts
cat "$OUTPUT_DIR/resolved.txt" | httpx -silent -title -status-code -tech-detect -threads 10 -timeout 10 | tee "$OUTPUT_DIR/live_hosts.txt"

# Keep a URL-only list for tools that expect one URL per line
awk '{print $1}' "$OUTPUT_DIR/live_hosts.txt" | sort -u > "$OUTPUT_DIR/live_urls.txt"

# Check for wildcard DNS before trusting "live" counts — if *.target.com resolves,
# every generated subdomain will look alive in httpx
dig +short "nonexistent-$RANDOM.$TARGET"

# Identify shared-hosting clusters (many subdomains -> one IP can mean a shared platform,
# not individually interesting hosts; a single-subdomain IP is comparatively higher signal)
awk '{print $3}' "$OUTPUT_DIR/resolved.txt" | sort | uniq -c | sort -rn | head -10
```

#### Visual Triage (Screenshots)

With dozens or hundreds of live hosts, screenshotting beats manually opening each one. Pair it with tech detection so a screenshot's content and its fingerprint corroborate each other:

```bash
gowitness file -f "$OUTPUT_DIR/live_urls.txt" -P "$OUTPUT_DIR/screenshots/" --no-http \
  --timeout 15 --db "$OUTPUT_DIR/gowitness.db"

# Pull out titles/pages worth prioritizing
gowitness report list --db "$OUTPUT_DIR/gowitness.db" \
  | grep -iE "login|admin|dashboard|setup|install|phpmyadmin|jenkins|grafana|dev|staging|test"
```

What a screenshot is telling you:

| Screenshot shows | What it means |
|---|---|
| CMS install wizard (e.g. "Welcome to WordPress") | Unconfigured install — potential unauthenticated site takeover |
| DB admin login (phpMyAdmin, Adminer) | Database management panel exposed |
| CI/CD login (Jenkins, GitLab) | Build system exposed — check for unauthenticated access |
| Monitoring dashboard (Grafana/Prometheus) | May expose internal metrics/data publicly |
| Stack trace / debug output | Debug mode enabled — extract paths and versions for the evidence log |
| Directory listing | Readable file tree — look for config/backup files |
| Identical screenshots across many hosts | Shared infrastructure — one vulnerable host may indicate the rest are too |

#### Port Scanning

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

**Reading the open-port list.** Severity is about what's reachable without authorization, not the port number itself:

| Port | Service | Why it matters |
|---|---|---|
| 3306 / 5432 / 1433 | MySQL / PostgreSQL / MSSQL | Database directly internet-reachable |
| 27017 | MongoDB | Historically ships with no auth by default |
| 6379 | Redis | Historically ships with no auth by default |
| 9200 | Elasticsearch | Often unauthenticated; full data exposure |
| 21 | FTP | Check for anonymous login (protocol-native anonymous mode, not credential guessing) |
| 8080/8081/8084/8443/9090/3000 | Internal APIs, Grafana, Node dev servers | Backend normally hidden behind the main app |

For a service whose protocol defines an explicit anonymous/no-credential mode, confirming that mode is in-scope recon (not brute-forcing):

```bash
# Redis: PING requires no credentials when auth isn't configured — this is a protocol-native check, not a guess
redis_test=$(timeout 5 bash -c "echo -e 'PING\r\n' | nc -w 3 '$TARGET' 6379")
echo "$redis_test" | grep -q "PONG" && echo "[CRITICAL] Redis reachable with no authentication configured"

# FTP: the "anonymous" account is a protocol-defined feature, not a guessed credential
anon_test=$(timeout 10 bash -c "echo -e 'anonymous\nanonymous\n' | nc -w 3 '$TARGET' 21")
echo "$anon_test" | grep -qi "230" && echo "[HIGH] Anonymous FTP login succeeded"
```

Do **not** extend this pattern to guessing usernames/passwords against MySQL, SSH, or any service that requires a real credential — that is brute-forcing and is explicitly out of scope for reconnaissance (see Scope, Rate Limits, and Stop Conditions below). Record the open port and move it into a vulnerability-specific skill once genuinely in scope.

#### Infrastructure Mapping — ASN, CIDR, Origin IP

Passive subdomain enumeration only finds hosts with a DNS name. Pivoting through ASN/CIDR data and origin-IP techniques finds the organization's broader IP footprint and the real server behind a CDN/WAF.

```bash
# Domain -> ASN
IP=$(dig +short "$TARGET" | head -1)
ASN=$(whois "$IP" | grep -iE "origin|OriginAS" | awk '{print $NF}' | head -1)
echo "ASN: $ASN"

# ASN -> CIDR ranges
whois -h whois.radb.net -- "-i origin $ASN" | grep -Eo "([0-9.]+){4}/[0-9]+" | sort -u > "$OUTPUT_DIR/cidr_ranges.txt"
# asnmap is a faster single-tool alternative: asnmap -a "$ASN" -silent >> "$OUTPUT_DIR/cidr_ranges.txt"

# CIDR -> flat IP list, then probe for live web services
cat "$OUTPUT_DIR/cidr_ranges.txt" | mapcidr -silent > "$OUTPUT_DIR/all_ips.txt"
cat "$OUTPUT_DIR/all_ips.txt" | httpx -ports 80,443,8080,8443,3000,8000 -status-code -title -silent -o "$OUTPUT_DIR/live_ip_services.txt"

# Reverse DNS to find hostnames hiding in those IP blocks
cat "$OUTPUT_DIR/cidr_ranges.txt" | dnsx -silent -resp-only -ptr > "$OUTPUT_DIR/ptr_domains.txt"
grep -i "$TARGET" "$OUTPUT_DIR/ptr_domains.txt"
```

**Origin IP behind a CDN/WAF.** If the target is Cloudflare/Akamai-fronted (403s or challenge pages on everything), the raw origin is often discoverable:

```bash
# Favicon hash fingerprint — many orgs reuse the same favicon across CDN and origin
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/favicon.ico" -o "$OUTPUT_DIR/favicon.ico"
HASH=$(python3 -c "
import hashlib, base64
print(base64.b64encode(hashlib.md5(open('$OUTPUT_DIR/favicon.ico','rb').read()).digest()).decode())
")
# Then search this hash on Shodan/Censys (web UI, or `shodan search "http.favicon.hash:$HASH"` if authorized to use the API)

# SSL certificate SAN fields often list the origin's real hostnames
curl --max-time 30 --connect-timeout 10 -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sort -u

# Candidate non-CDN IPs from subdomain resolution: filter out known Cloudflare ranges, then verify by Host header
grep -vE '^104\.(1[6-9]|2[0-9]|3[0-1])\.|^172\.(6[4-9]|7[0-1])\.' "$OUTPUT_DIR/all_ips.txt" > "$OUTPUT_DIR/non_cf_ips.txt"
for ip in $(cat "$OUTPUT_DIR/non_cf_ips.txt"); do
  curl --max-time 10 -sk --connect-timeout 5 "https://$ip" -H "Host: $TARGET" -o /dev/null -w "%{http_code} $ip\n"
done | grep -v "^403\|^000"
```

Confirm a candidate origin by matching content (title/favicon) between the CDN-fronted site and the direct-IP request with the target's Host header — a matching favicon hash plus matching page title is reasonable confirmation; a bare open port on an unrelated IP is not.

#### Subdomain Categorization

Group discovered hostnames by likely purpose to prioritize manual review — admin/API/staging surfaces are higher value than static/CDN assets:

```bash
grep -iE 'staging|stage|dev\.|development|test|uat|beta|sandbox|preview|qa'          "$OUTPUT_DIR/all_passive.txt"  # staging/dev
grep -iE 'admin|portal|internal|dashboard|manage|cp\.|control|panel|webmail'          "$OUTPUT_DIR/all_passive.txt"  # admin/internal
grep -iE 'api|rest|graphql|ws\.|websocket'                                            "$OUTPUT_DIR/all_passive.txt"  # API
grep -iE 'cdn|static|assets|media|img|images|files|download|origin|proxy'             "$OUTPUT_DIR/all_passive.txt"  # CDN/static
grep -iE 'mail\.|smtp|imap|pop|email|webmail|autodiscover'                            "$OUTPUT_DIR/all_passive.txt"  # email
grep -iE 'aws|azure|gcp|cloud|s3|bucket|firebase'                                     "$OUTPUT_DIR/all_passive.txt"  # cloud
grep -iE 'old|v1|v2|legacy|archive|backup|bak'                                        "$OUTPUT_DIR/all_passive.txt"  # legacy
```

**Production vs staging gap check.** Staging/dev environments routinely have weaker controls than production — that gap is itself the finding, so compare rather than testing staging in isolation:

```bash
PROD="https://$TARGET"
STAGING=$(grep -iE 'staging|stage' "$OUTPUT_DIR/all_passive.txt" | head -1)

echo "=== Production headers ==="; curl -skI --max-time 15 "$PROD"
echo "=== Staging headers ===";    curl -skI --max-time 15 "https://$STAGING"
# Compare: is there a WAF/CDN header on one but not the other? Is CORS more permissive on staging?
# Same bounded check run against both — a control present on one and absent on the other is the reportable gap,
# not the mere existence of a staging host.
```

#### Subdomain Takeover Check

```bash
# Bulk CNAME check (preferred over a dig loop)
dnsx -silent -l "$OUTPUT_DIR/all_passive.txt" -cname -resp-only -o "$OUTPUT_DIR/cnames.txt"

while read -r sub; do
  cname=$(dig +short "$sub" CNAME 2>/dev/null)
  if [[ -n "$cname" ]]; then
    cname_ip=$(dig +short "$cname" A 2>/dev/null)
    if [[ -z "$cname_ip" ]]; then
      echo "[TAKEOVER?] $sub => $cname (NOT RESOLVING)"
      case "$cname" in
        *amazonaws.com*)    echo "  Provider: AWS (S3/CloudFront) - check if bucket/domain is claimable" ;;
        *azure*)            echo "  Provider: Azure - check if resource is claimable" ;;
        *github.io*)        echo "  Provider: GitHub Pages - check if repo name is available" ;;
        *herokuapp.com*)    echo "  Provider: Heroku - check if app name is available" ;;
        *vercel-dns.com*)   echo "  Provider: Vercel - check if project is claimable" ;;
        *zendesk.com*)      echo "  Provider: Zendesk - check if help desk is claimable" ;;
      esac
    fi
  fi
  sleep 0.5
done < "$OUTPUT_DIR/all_passive.txt"
```

A takeover candidate is only confirmed once the CNAME target is manually verified as unclaimed on the provider — load `attack-subdomain-takeover` before attempting registration.

#### Permutation & Prediction

Generate mutations from already-discovered subdomains to surface services that passive sources missed:

```bash
# gotator — generates permutations (patterns: %s-dev, dev-%s, %s-staging, %s-admin, %s-api, %s-internal, etc.)
gotator -sub "$OUTPUT_DIR/all_passive.txt" -perm permutations.txt -depth 1 -numbers 3 -md | sort -u > "$OUTPUT_DIR/subs_permuted.txt"

# Resolve permutations
puredns resolve "$OUTPUT_DIR/subs_permuted.txt" -r resolvers.txt -o "$OUTPUT_DIR/subs_permuted_alive.txt"
```

#### TLD Expansion

An organization that owns `target.com` often neglects `target.io`, `target.net`, `target.xyz` — and parallel infrastructure on another TLD is a distinct ownership question, not automatically in scope. Treat any hit as a lead for the Ownership & Scope Triage step above, not a confirmed asset.

```bash
# tldbrute — discovers registered TLD variants of the root brand
tldbrute -d "$TARGET"
```

#### Live Certificate Monitoring

For longer engagements, catch newly issued certificates (and therefore new subdomains) as they appear:

```bash
# gungnir — real-time certificate transparency monitoring
gungnir -d "$TARGET"

# certwatcher — alternative CT log monitor with webhook support
certwatcher -d "$TARGET"
```

### Phase 3: Content Discovery

#### CMS & Framework Fingerprinting

Knowing the stack before probing paths avoids wasted WordPress-specific tests against a Laravel API (and vice versa):

```bash
# Fast: httpx's built-in Wappalyzer-style detection across all live hosts
cat "$OUTPUT_DIR/live_urls.txt" | httpx -silent -tech-detect -o "$OUTPUT_DIR/tech_detect.txt"

# Deeper, with version strings
whatweb -i "$OUTPUT_DIR/live_urls.txt" -a 3 -t 50 --log-brief="$OUTPUT_DIR/whatweb.txt"
```

CMS-specific version leaks (verify at least two independently before recording a version as confirmed):

```bash
# WordPress
curl -sk --max-time 15 "https://$TARGET" | grep -Eo '<meta name="generator"[^>]*content="WordPress [^"]+'
curl -sk --max-time 15 "https://$TARGET/readme.html" | grep -Eo "Version [0-9.]+"
curl -sk --max-time 15 "https://$TARGET/wp-json/" | jq -r '.namespaces[]' 2>/dev/null

# Drupal — CHANGELOG.txt is Drupal's canonical version leak
curl -sk --max-time 15 "https://$TARGET/CHANGELOG.txt" | head -5

# Joomla
curl -sk --max-time 15 "https://$TARGET/administrator/manifests/files/joomla.xml" | grep -Eo '<version>[^<]+'

# Framework fingerprints via known endpoints
# Spring Boot: /actuator/health -> {"status":"UP"}
# Next.js:     /_next/static/ chunk paths present
# Django:      /admin/ redirects to /admin/login/
```

A known CMS/framework version is a lead to check against its public CVE list (e.g. the WordPress/Drupal/Magento security advisories) — not itself a finding. Load a vulnerability-specific skill once a version/CVE pairing needs validation.

#### Directory Fuzzing

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

#### Sensitive File & Path Disclosure Scanning

High-yield on neglected infrastructure: one exposed `.env` or `.git` directory can lead to full credential access. Always run the soft-404 junk-path control (above) on the same host before trusting any hit.

Representative path categories to probe (not exhaustive — extend per stack):

```
Env/config:      /.env, /.env.local, /.env.production, /.env.backup, /config/.env
VCS:             /.git/config, /.git/HEAD, /.git/logs/HEAD, /.git/packed-refs
Framework logs:  /storage/logs/laravel.log, /storage/oauth-private.key
App error logs:  /error_log, /wp-content/debug.log, /php_errors.log, /logs/error.log
Containers:      /Dockerfile, /docker-compose.yml, /docker-compose.override.yml
Dependency mgmt: /composer.json, /package.json, /yarn.lock, /requirements.txt, /go.mod
Build maps:      /assets/index-*.js.map, /static/js/*.js.map
Debug endpoints: /phpinfo.php, /info.php, /debug, /actuator, /actuator/env, /actuator/heapdump
API docs:        /swagger-ui.html, /v2/api-docs, /v3/api-docs, /graphql, /graphiql
Admin surfaces:  /admin, /manager/html, /host-manager/html, /phpmyadmin
Server config:   /.htaccess, /nginx.conf, /.well-known/security.txt, /server-status
```

```bash
# Bounded probe pattern — one host, logged, with the soft-404 control built in
for f in "/.env" "/.git/config" "/.git/HEAD" "/actuator/env" "/swagger-ui.html"; do
  code_size=$(curl -s -o /tmp/hit -w "%{http_code} %{size_download}" --max-time 15 "https://$TARGET$f")
  ctrl_size=$(curl -s -o /tmp/ctrl -w "%{size_download}" --max-time 15 "https://$TARGET/zzz-nonsense-$RANDOM")
  echo "$f -> $code_size (control: $ctrl_size)"
done
```

If a `.env` or similar file is genuinely exposed (confirmed against the soft-404 control, body contains real key=value pairs rather than an HTML homepage), record **which keys are present** (`DB_PASSWORD`, `AWS_SECRET_ACCESS_KEY`, `STRIPE_SECRET`, etc.) and a short, truncated excerpt as evidence — do not capture, print, or store full secret values beyond what is needed to prove the exposure exists. The same applies to any `.git` dump, application log, or source map that contains credentials: evidence should prove the leak, not reproduce it.

**Exposed error logs** (PHP `error_log`, `debug.log`) deserve the same bounded-sample treatment — fetch only a small byte range to classify content, rather than pulling a multi-GB log in full:

```bash
curl -sk --max-time 15 -r 0-2000 "https://$TARGET/error_log" | grep -iE 'PHP|Warning|Stack trace'
```

If server paths, SQL fragments, or a framework's session-signing keys (e.g. WordPress `AUTH_KEY`/`NONCE_SALT` constants) appear, that's reportable on its own — don't continue pulling the file just to see more.

#### Virtual Host (vHost) Enumeration

Many servers hold hidden virtual hosts that only respond to a specific `Host` header and never show up in subdomain enumeration — reachable once you have a candidate IP (from origin-IP discovery or ASN/CIDR mapping above):

```bash
# Calibrate first: find the size of the default/unknown-host response so real hits can be filtered from noise
DEFAULT_SIZE=$(curl -s "http://TARGET_IP" -H "Host: nonexistent-$RANDOM.$TARGET" | wc -c)

# Fuzz with auto-calibration
ffuf -u "http://TARGET_IP" -w dns_wordlist.txt -H "Host: FUZZ.$TARGET" -ac -mc 200,301,302,401,403

# Pull hostnames directly out of the SSL certificate's SAN field — often lists internal vhosts
echo | openssl s_client -connect TARGET_IP:443 -servername "$TARGET" 2>/dev/null \
  | openssl x509 -noout -text | grep -Eo 'DNS:[^,[:space:]]+' | cut -d: -f2 | sort -u
```

A hit must be verified manually (curl with the exact Host header, confirm distinct content from the calibrated default) before being logged — some servers echo any Host header back with a generic page, which looks like a hit but isn't one.

#### Cache / CDN Detection

```bash
curl --max-time 30 --connect-timeout 10 -sI "https://$TARGET/" | grep -iE "age|x-cache|via|server|cf-cache-status"
# Via: 1.1 varnish       = Varnish
# X-Cache: Hit from cloudfront = AWS CloudFront
# Cf-Cache-Status: HIT   = Cloudflare
```

#### Parameter Discovery

```bash
# Arjun
arjun -u "https://$TARGET/page" --timeout 10 -oJ "$OUTPUT_DIR/arjun.json"

# ParamSpider (from Wayback data)
python3 paramspider.py -d "$TARGET"

# x8 — hidden parameter discovery via response diffing
x8 -u "https://$TARGET/endpoint" -o "$OUTPUT_DIR/x8_params.txt"

# FFUF parameter fuzzing
ffuf -u "https://$TARGET/page?FUZZ=value" -w params.txt -mc 200 -t 10 -rate 5 -maxtime 300 -o "$OUTPUT_DIR/ffuf-params.json"
```

#### URL Category Extraction

Once historical/crawled URLs are collected, split them by sensitivity to prioritize manual testing:

```bash
cat "$OUTPUT_DIR/historical_urls.txt" | grep -iE '\.js(\?|$)' | grep -iv '\.json'     > "$OUTPUT_DIR/js_urls.txt"       # JS files (secret hunting)
cat "$OUTPUT_DIR/historical_urls.txt" | grep -Ei '\.(json|xml|graphql)(\?|$)'          > "$OUTPUT_DIR/api_urls.txt"      # API endpoints
cat "$OUTPUT_DIR/historical_urls.txt" | grep -Ei "login|signin|auth|oauth|reset"       > "$OUTPUT_DIR/auth_urls.txt"     # auth flows
cat "$OUTPUT_DIR/historical_urls.txt" | grep -Ei "admin|dashboard|internal|manage"     > "$OUTPUT_DIR/admin_urls.txt"    # admin panels
cat "$OUTPUT_DIR/historical_urls.txt" | grep -Ei "upload|file|download|image|media"    > "$OUTPUT_DIR/upload_urls.txt"  # file ops
cat "$OUTPUT_DIR/historical_urls.txt" | grep -Ei "[0-9]{3,}"                           > "$OUTPUT_DIR/idor_candidates.txt" # numeric-ID candidates
cat "$OUTPUT_DIR/historical_urls.txt" | grep -Ei "redirect|callback|goto|dest=|url="   > "$OUTPUT_DIR/redirect_urls.txt" # open-redirect candidates
```

#### WAF / 403 Bypass (authorized testing only)

Use only when the target is confirmed in scope and the engagement rules permit bypass testing. These are reconnaissance probes to understand access-control configuration, not an invitation to force access to admin functionality.

```bash
# Common bypass headers
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/admin" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Forwarded-Host: 127.0.0.1" \
  -H "X-Original-URL: /admin"

# HTTP method switching (observe which methods a restricted path accepts)
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  echo -n "$method: "
  curl --max-time 30 --connect-timeout 10 -sk -X "$method" "https://$TARGET/admin" -o /dev/null -w "%{http_code}\n"
done
```

#### JavaScript Analysis

Modern bundles (Webpack/Vite/esbuild) often leak internal API URLs, environment variables (`VITE_*`, `REACT_APP_*`, `NEXT_PUBLIC_*`), and third-party service configuration (Firebase, Auth0, Supabase). This is routinely higher-yield than directory brute-forcing on SPA-heavy targets. Always check JS bundles on **every open port**, not just 443 — admin or internal apps are often served on an alternate port with a different bundle and different secrets than the public site.

```bash
# Extract JS files referenced by the page, and via historical crawl data
cat $OUTPUT_DIR/live_hosts.txt | getJS --complete | tee $OUTPUT_DIR/js_files.txt
cat "$OUTPUT_DIR/historical_urls.txt" | subjs | tee -a "$OUTPUT_DIR/js_files.txt"

# Find endpoints and secrets in JS with purpose-built extractors
cat "$OUTPUT_DIR/js_files.txt" | xargs -I{} sh -c 'curl --max-time 15 --connect-timeout 5 -s "$1" | linkfinder -i -' sh {}
cat "$OUTPUT_DIR/js_files.txt" | xargs -I{} sh -c 'curl --max-time 15 --connect-timeout 5 -s "$1" | secretfinder -i -' sh {}

# Nuclei JS/exposure templates
nuclei -l "$OUTPUT_DIR/js_files.txt" -t exposures/ -rate-limit 5 -c 5 -timeout 10 -retries 1 -o "$OUTPUT_DIR/nuclei-js.txt"
```

**Secret pattern recognition.** Know the shape of what you're looking for so a hit can be triaged quickly — but log only a short, identifying fragment (e.g. first/last 4 characters) as evidence, never the full value:

| Pattern | Looks like | Notes |
|---|---|---|
| Firebase API key | `apiKey: "AIzaSy..."` | Often intentionally client-exposed; still worth noting if paired with an open backend |
| AWS key ID | `AKIA`/`ASIA` + 16 chars | Treat as a real credential leak |
| Google API key | `AIza` + 35 chars | Validate scope before assuming high impact |
| JWT | `eyJ...` . `eyJ...` . `sig` | Decode header/payload only (no signature forgery) to check claims/roles |
| Stripe live key | `sk_live_`/`pk_live_` + 24+ chars | High-impact if `sk_live_` — report immediately, don't call payment APIs |
| Supabase anon key | JWT under `supabaseKey`/`anonKey` | Often intentionally public; the real question is whether row-level security is enforced |
| Platform backend URL | `*.fly.dev`, `*.azurewebsites.net`, `*.onrender.com`, `*.supabase.co` | Intel, not a secret — reveals real backend host behind CDN/WAF |
| Vercel deployment ID | `dpl_...` | **Not** a secret — public deploy identifier, don't flag it as one |

```bash
# Platform-specific backend URL discovery (bypasses CDN/WAF fronting)
grep -Eo 'https?://[a-zA-Z0-9.\-]+\.(fly\.dev|azurewebsites\.net|onrender\.com|vercel\.app|netlify\.app|supabase\.co)[^"'\'' ]{0,40}' "$OUTPUT_DIR"/js_cache/*.js
grep -Eo '["\x60]/api/v1/[a-zA-Z0-9_\-/]+["\x60]' "$OUTPUT_DIR"/js_cache/*.js
```

**Source map reconstruction.** If a `.js.map` is left in production, it can recover near-original source for every chunk:

```bash
curl --max-time 30 --connect-timeout 10 -sI "https://$TARGET/static/js/main.js.map" | grep -iE "200|content-type"
# If present, reconstruct with a source-map tool rather than fetching it into chat context raw —
# source maps frequently embed full original source files plus any hardcoded values they contained.
```

**Per-file review for dangerous sinks.** For each downloaded chunk, a disciplined pass for specific patterns finds more than an unstructured read-through:

```bash
for chunk in "$OUTPUT_DIR"/js_cache/*.js; do
  echo "=== $chunk ==="
  grep -Eon 'eval\s*\(|new\s+Function\s*\(' "$chunk"                                   # arbitrary code execution
  grep -Eon 'postMessage\s*\(' "$chunk"                                                # missing-origin-check candidates
  grep -Eon '__proto__|constructor\.prototype' "$chunk"                                # prototype pollution patterns
  grep -Eon '(?:isAdmin|isVip|isPremium|role)\s*[=:]\s*true' "$chunk"                  # client-trusted auth flags
done
```

Each hit from this pass is a candidate, not a finding — it still needs a manual proof-of-concept before it's reportable.

### Phase 4: Vulnerability Discovery

#### Automated Scanning

```bash
# Nuclei (comprehensive)
nuclei -l "$OUTPUT_DIR/live_urls.txt" -severity info,low,medium,high,critical -rate-limit 5 -c 5 -timeout 10 -retries 1 -o "$OUTPUT_DIR/nuclei_results.txt"

# Nikto
nikto -h "https://$TARGET" -maxtime 5m -output "$OUTPUT_DIR/nikto.txt"

# WPScan (WordPress)
wpscan --url "https://$TARGET" --enumerate u,p,t --max-threads 5 --throttle 1 --request-timeout 10 --output "$OUTPUT_DIR/wpscan.txt"
```

#### Manual Testing Points

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

### Reconnaissance Flow

```
Target Domain
     │
     ├── Ownership & Scope Triage (anchor the owned-domain set first)
     │
     ├── Passive Recon
     │   ├── Subdomains: crt.sh, crt.name, SecurityTrails, Subfinder, Amass
     │   ├── Historical data (wayback, gau)
     │   ├── Email security posture (SPF/DKIM/DMARC)
     │   └── Source-code OSINT (GitHub/GitLab public search, trufflehog/gitleaks)
     │
     ├── DNS Enumeration
     │   ├── Record types (A, MX, TXT, NS)
     │   └── Zone transfer attempt
     │
     ├── Active Subdomain Enumeration
     │   ├── Brute force (puredns)
     │   ├── Permutation (gotator) & TLD expansion (tldbrute)
     │   └── Live CT monitoring (gungnir/certwatcher) for longer engagements
     │
     ├── Resolution & Probing
     │   ├── dnsx (resolve) + wildcard-DNS check
     │   ├── httpx (probe) + visual triage (screenshots)
     │   └── Categorization (staging/admin/API/CDN/cloud/legacy) + takeover check
     │
     ├── Infrastructure Mapping
     │   ├── ASN -> CIDR -> live IP services -> reverse DNS
     │   └── Origin-IP discovery behind CDN/WAF (favicon hash, cert SAN, Host-header probe)
     │
     ├── Port Scanning
     │   └── nmap / masscan + protocol-native no-auth checks (never credential guessing)
     │
     ├── Content Discovery
     │   ├── CMS/framework fingerprinting
     │   ├── Directory fuzzing
     │   ├── Sensitive file + error-log scanning (+ soft-404 control)
     │   ├── vHost enumeration, cache/CDN detection
     │   ├── Parameter discovery + URL categorization
     │   └── JavaScript analysis (secrets, source maps, backend URLs, dangerous sinks)
     │
     └── Vulnerability Scanning
         ├── Nuclei
         └── Manual testing
```

### Verification and Evidence Hygiene

- Deduplicate and scope-check discovered hostnames before active requests; exclude third-party assets and unresolved ownership questions (see Ownership & Scope Triage).
- Verify DNS answers and HTTP liveness independently. A DNS record, open port, technology fingerprint, or HTTP status is a lead, not a vulnerability finding.
- Run the soft-404 junk-path control on every sensitive-file "hit" before logging it as an exposure.
- For each candidate finding, record the exact in-scope asset, UTC timestamp, tool/version, request or command, expected behavior, observed behavior, and sanitized evidence.
- When a finding involves live credentials (exposed `.env`, JS-embedded keys, repo secrets, log-mined tokens), capture only enough of the value to prove the exposure — never the full secret, and never test it against a live account or payment flow without explicit authorization.
- An origin-IP or vHost hit needs content/fingerprint confirmation (matching favicon hash, matching title, matching SSL SAN), not just an open port or a 200 status.
- Recheck high-signal results manually with a low-impact request. Do not submit a version string, exposed-looking path, or scanner output without confirming meaningful content and impact.
- Keep a list of tested hosts and endpoints to prevent duplicate scans. Stop or reduce rate when latency, errors, lockouts, or service instability increases.
- Related skills use the exact existing names `attack-subdomain-takeover`, `attack-host-header`, and `attack-ssrf`; load them only when discovery provides a relevant signal.

### Scope, Rate Limits, and Stop Conditions

- Establish an explicit allowlist of domains, hosts, ports, and test windows before active probing. A discovered subdomain or linked third-party host is not automatically in scope.
- Keep passive collection separate from active validation in notes and reports. Record source, timestamp, DNS/HTTP result, and the exact command so findings can be reproduced.
- Use bounded concurrency and request timeouts. Start with low request rates, increase only when the program permits it, and stop on elevated error rates, rate-limit responses, service degradation, or an out-of-scope redirect.
- Do not brute-force credentials, run destructive checks, or submit exploit payloads during reconnaissance. A protocol-native anonymous mode (FTP `anonymous`, an unauthenticated Redis `PING`) is a configuration check, not brute-forcing; guessing real usernames/passwords against any service is not. Move to a vulnerability-specific skill only after confirming the endpoint is in scope.
- Deduplicate hosts by canonical hostname and resolved asset identity where appropriate; preserve meaningful virtual hosts, ports, and environment differences rather than silently merging them.
- Treat third-party enrichment and scanner output as leads. Verify live reachability and ownership before reporting, and exclude secrets or personal data from saved output.
- CIDR ranges from ASN pivoting can be enormous (large cloud providers especially). Only scan ranges confirmed to belong to the target, never an entire hosting provider's address space.

### Wordlists

| Purpose     | Recommended Wordlist                                                         |
| ----------- | ---------------------------------------------------------------------------- |
| Subdomains  | SecLists/Discovery/DNS/subdomains-top1million-5000.txt                       |
| Directories | SecLists/Discovery/Web-Content/raft-medium-directories.txt                   |
| Files       | SecLists/Discovery/Web-Content/raft-medium-files.txt                         |
| Parameters  | SecLists/Discovery/Web-Content/burp-parameter-names.txt                      |
| Passwords   | SecLists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt |

### Asset Confidence and Recon Prioritization

Keep discovery evidence separate from conclusions. For every asset, track source, timestamp, DNS/HTTP status, ownership confidence, scope decision, and whether active testing is permitted.

| Confidence | Evidence | Next step |
|---|---|---|
| High | exact in-scope hostname or asset listed by the program | test only within the stated limits |
| Medium | linked subdomain, certificate/DNS relationship, or documented vendor asset | verify ownership and scope before active probes |
| Low | inferred IP range, shared hosting, third-party SaaS, or stale passive result | passive research only until scope is confirmed |

Prioritize by likely attack surface and business relevance, not by the number of discovered hosts. Deduplicate hostnames, normalize schemes/ports, preserve the source of each result, and separate live assets from stale DNS or wildcard responses.

For active checks, use bounded concurrency, request timeouts, conservative rate limits, and explicit stop conditions. Do not scan neighboring tenants or third-party infrastructure merely because it resolves from an in-scope domain. Keep raw secrets and personal data out of recon output; retain sanitized command, timestamp, source, and validation evidence for reproducibility.

### Pitfalls

| Issue | Solution |
|-------|----------|
| crt.sh rate limiting / 502s | Retry with backoff; fall back to crt.name/subfinder rather than treating an empty result as "no subdomains" |
| subfinder requires API keys | Some sources (VirusTotal, Shodan) need keys in `~/.config/subfinder/provider-config.yaml`; without them, results are limited |
| Wildcard DNS | `*.target.com` resolving to one IP makes everything look "live" in httpx — check with a random-label query first |
| Cloudflare / CDN proxying | Subdomains behind a CDN show CDN IPs, not origin IPs — use historical DNS sources or origin-IP techniques to find the real server |
| SPA/commerce catch-all | Returns 200 with the homepage for any path — the soft-404 control (above) is mandatory before logging a file exposure |
| Minified JS, no source map | Grep for specific high-signal patterns rather than reading raw; request a source map separately |
| False-positive secret matches | Validate by checking key shape/length and, where safe, a scope/permissions check — never a live transaction |
| Huge ASN/CIDR ranges | Confirm the range belongs to the target via at least two sources before scanning any of it |
| vHost false positives | Some servers return a generic 200 for any Host header — calibrate with a known-nonexistent hostname first |
| GitHub/GitLab search noise | Most "secret" search hits are docs, examples, or template files — filter to real config filenames (`.env`, `.npmrc`, CI config) and verify before recording |


### Phase 5: Specialized Recon Add-ons

#### 401/403 Boundary and Routing Differential Checks

Ownership/scope gate: use only a denied endpoint on a confirmed in-scope host. Capture one baseline and one benign comparison. Test a small number of documented path-normalization or method-routing variants individually; avoid long bypass wordlists, request-smuggling payloads, or attempts to access sensitive admin data. Confirmation requires the protected handler/content to be reached, not a changed status code alone. Compare body hashes, title, content type, and authentication challenge headers.

#### Unauthenticated API Surface Validation

Use JavaScript references, API documentation, and a few known routes to identify candidate APIs rather than broad path fuzzing. Compare an anonymous request against the same route with a test account and a known public/negative control. Keep read evidence to a short sanitized marker. For mutations, use a disposable synthetic record and explicit authorization; verify persisted state and clean it up. Never dump user collections or enumerate identifiers.

#### Cache Behavior and Cache-Key Analysis

Begin with Age, Via, X-Cache, and provider-specific cache status; a cache header alone is not a vulnerability. Use a unique query parameter and benign marker on an endpoint/cache key you control. Compare requests with and without one candidate header or parameter and observe MISS/HIT behavior. Never inject active script, poison shared pages, retrieve another user's cached response, or flush a production cache. Cache deception/poisoning candidates require a controlled lab or explicit test path and cleanup plan.

#### Source, Backup, and Repository Exposure

Probe only a small justified set of paths on a confirmed in-scope origin and compare each response with a random nonexistent path. A 200 or HTML page is not proof: verify a content signature, Git metadata marker, valid archive structure, or minimal config/log field. For secrets, record key name/type and a short truncated fragment at most; never print, store, test, or reuse a full secret. Do not retrieve database dumps, bulk backups, customer logs, or full repository contents from production.

#### Hardcoded Credential and Secret Indicators

Review public HTML, delivered JavaScript, source maps, and configuration endpoints for suspicious assignments, distinguishing public identifiers from private credentials. Record the file/commit/response location, variable/key name, and confidence. Never echo full token values; truncate minimally where needed and redact in reports. Do not test discovered credentials against live services. Escalate through the authorized program process for controlled validation or revocation.

#### HTTP/2 and Header-Parsing Differences

Use a local HTTP/2 test server, vendor documentation, or a test endpoint to compare protocol/header normalization. In production, keep to a few non-mutating requests and don't attempt desynchronization or conflicting framing unless specifically authorized. Browser/client fingerprints are environmental signals, not authentication. Document negotiated protocol, response differences, and whether an origin-side security boundary was crossed.

#### Automation Reproducibility and Human Interaction

Use browser automation to reproduce legitimate user workflows, not to evade account protection, CAPTCHAs, fraud prevention, or rate limits. Keep account, route, browser version, and network context constant while changing one variable. Respect challenge and lockout responses; do not automate challenge solving, create accounts at scale, rotate identities/IPs to evade controls, or disguise abusive traffic. If automated and manual behavior differs, preserve it as a lead pending controlled explanation.

#### IoT Camera and Physical-Security Discovery

Physical-security devices can affect privacy and safety. Confirm device ownership and exact scope before active testing. Prefer public product/version fingerprints and low-risk auth challenges; do not fetch snapshots, video, audio, recordings, admin configuration, or personal data. Do not try default passwords, scan large ranges, or invoke pan/tilt, door, alarm, relay, or firmware-control actions. Use an owner-provided test device and synthetic media if deeper proof is required.

#### Port and Service Discovery

Only scan explicitly authorized IPs/CIDRs and ports. Start with a small known-host list and low request rates, then confirm individual hits with a bounded service probe. Do not scan broad public ranges, shared cloud ranges, or infrastructure discovered through third-party sources unless explicitly included in scope. Stop on service instability, rate-limit/IDS notification, or ownership uncertainty. Keep excluded hosts in an explicit list and never treat an open port as proof of a vulnerability.

#### Browser Automation and Anti-Bot Boundaries

Use standard, observable browser configuration for repeatable tests and document version/extensions. Fingerprint differences between curl and browser can explain false negatives but do not authorize anti-bot evasion. Do not use proxy rotation, stealth patches, geolocation deception, CAPTCHA-solving services, or human-behavior simulation to bypass security/abuse controls. When browser-only checks are permitted, use a tester-owned account and one controlled session; stop if the service challenges or blocks the test.

#### TLS Fingerprint and ClientHello Analysis

Use passive certificate inspection and safe TLS handshakes to record protocol versions, cipher negotiation, ALPN, certificate chain, and negotiated parameters. ClientHello/JA3/JA4 mismatches may explain scanner/browser differences but are not vulnerabilities by themselves. Do not impersonate other clients to evade access controls or rate limits. If client-profile comparison is needed, reproduce it against a local test server or approved endpoint and log negotiated properties.

#### Multi-Step Unauthenticated API Workflow Review

Model the workflow as a state machine (initiate, submit, upload, review, complete, export) and identify the intended identity/ownership boundary at each step. Start with a test-owned flow and synthetic data. Verify one transition at a time, including whether workflow IDs are bound to creator and tenant. Do not complete real transactions, publish content, send notifications, upload active files, or export real data. A flow ID accepted by an API is not a finding until an unauthorized state transition or access boundary is demonstrated.

## What This Produces

- An auditable asset list with source, timestamp, ownership/scope confidence, and active-test permission.
- A prioritized endpoint/service inventory with confidence notes and low-risk evidence.
- Candidate leads clearly separated from confirmed security-boundary failures.
- Sanitized artifacts plus a record of exclusions, unresolved ownership, cleanup, and stop events.

## Evidence Requirements

- Keep the original source for each hostname, route, endpoint, version string, or repository result.
- Record timestamp/time zone, resolver, status, headers, body hash/size, and account/role for active checks.
- Use random nonexistent paths and known public paths as negative controls where appropriate.
- For secret indicators, retain key name/type and a short truncated fragment only; never expose full credentials, tokens, or customer data.
- Document rate limits, scope decisions, stop events, cleanup, and uncertainty.

## Tools

- **dig / certificate transparency / passive DNS:** gather public DNS and certificate-history leads.
- **subfinder / amass / dnsx / httpx:** enumerate and confirm only explicitly scoped hostnames at bounded rates.
- **curl / browser DevTools / Burp Suite:** inspect a few routes and compare baselines with controlled requests.
- **nmap:** confirm services on explicitly authorized hosts or small approved ranges; avoid mass-scan defaults.
- **jq / grep / Python:** deduplicate results and inspect schemas while suppressing secret values.
- **Vendor advisories and asset inventory:** verify ownership, version, and current vulnerability prerequisites.

## Recon Technique and Decision Matrix

| Stage | Positive signal | Required validation | Stop condition |
|---|---|---|---|
| Passive discovery | DNS, CT, archive, or public repo result | Tie ownership to target and confirm scope | Ambiguous owner/third-party adjacency |
| DNS/HTTP liveness | Resolving host or HTTP response | Compare CNAME/provider and negative path | Scope unclear |
| API discovery | JS route/schema/docs reference | Single bounded request and auth baseline | Bulk enumeration or real data exposure |
| Source/backup exposure | Candidate file or repo path | Content signature and minimum sanitized marker | Full secret/backup/customer data appears |
| Authentication/authorization | 401/403 or role differential | Same operation under controlled identities and compare state | Lockout risk, sensitive data, unapproved mutation |
| Cache/protocol behavior | HIT/MISS or header/TLS difference | Controlled canary with test key or local harness | Shared cache poisoning, desync, or evasion required |
| Port/service | Open port or banner | Bounded confirmation on allowlisted host | Range too broad, instability, or ownership doubt |
| Reporting handoff | Reproducible evidence | Evidence hygiene, scope proof, false-positive gate | Unverified/inferred impact |

A result is a lead until the actual security boundary and intended policy are established.

## Verification and False Positives

- A passive hostname, IP, repository, bucket, certificate, or linked SaaS domain is not automatically owned or in scope.
- A status code, banner, JavaScript route, scan-template alert, or public namespace does not establish a vulnerability alone.
- Use content checks and negative controls to detect SPA catch-all routes, soft 404s, stale assets, cache variance, and gateway errors.
- Do not run credential guessing, brute force, high-volume scanning, service stress, destructive operations, active user-facing cache poisoning, or internal SSRF by default.
- If a probe reveals credentials, personal data, a production state change, service instability, or unclear third-party ownership, stop and preserve only sanitized minimum evidence.
- Validate candidate findings against the program's accepted impact list and keep unconfirmed leads out of the final findings.


## Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. The validation budget is at most 20 distinct hypotheses per candidate asset; it is not permission for 20 scans or repeated probes. Prefer passive sources first, deduplicate candidates, and use active checks only when the asset and activity are explicitly in scope.

### Evidence record and confidence

For each candidate, preserve normalized asset, source/provenance, observation time, scope proof, resolver/HTTP/tool and relevant version, raw-evidence location, corroborating source, negative control, attribution confidence, next action, and related-skill trigger. Separate **asset confidence** (is it related to the organization?) from **security confidence** (is a vulnerability demonstrated?).

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. C1/C2 are not confirmed vulnerabilities.

### Skill-specific next steps

1. Establish the written scope and exclusions, then create a reproducible workspace with a timestamped output directory, target slug, source provenance, and no secrets embedded in commands or committed to reusable skills.
2. Collect passive names and historical URLs first. Normalize case, trailing dots, schemes, and duplicate sources; preserve each original source and observation time rather than keeping only a merged list.
3. Prove ownership/attribution for every asset class and quarantine ambiguous SaaS, CDN, shared-hosting, common-name, and third-party assets. A discovery result is a candidate, not automatic authorization.
4. Use wildcard DNS, random-host, random-path, redirect, soft-404, and public/private response controls before ranking live hosts. Promote only confirmed in-scope assets to bounded active checks.
5. Route each validated lead to the most relevant skill based on observed signals (auth boundary, API schema, source artifact, service exposure). Record confidence, evidence path, next action, and explicit stop reason; never promote reconnaissance alone to a finding.


### Deduplication and stop rules

Normalize case, trailing dots, scheme/port, redirects, canonical names and resolved addresses before deduplication. Detect wildcard DNS, shared hosting, CDN/edge responses, soft-404s and stale records before ranking counts. Stop on exclusions, ownership ambiguity, unexpected sensitive data, throttling, instability or boundaries requiring further permission. Never claim ownership or register dangling resources.

### Handoff format

Return candidates with scope/provenance, confidence level, evidence path, deduplication key, negative control, priority rationale, safe next step and trigger for any linked attack skill. Promote a candidate to active testing only after scope and attribution are confirmed; promote it to a finding only after the relevant attack skill verifies the security boundary.

## References

- [uphiago/recon-skills — subdomain enumeration](https://github.com/uphiago/recon-skills/tree/main/recon/subdomain-enumeration)
- [uphiago/recon-skills — web enumeration](https://github.com/uphiago/recon-skills/tree/main/recon/web-enumeration)
- [uphiago/recon-skills — JavaScript secrets extraction](https://github.com/uphiago/recon-skills/tree/main/recon/js-secrets-extraction)
- [uphiago/recon-skills — ASN infrastructure mapping](https://github.com/uphiago/recon-skills/tree/main/recon/asn-infrastructure-mapping)
- [uphiago/recon-skills — origin IP discovery](https://github.com/uphiago/recon-skills/tree/main/recon/origin-ip-discovery)
- [uphiago/recon-skills — CMS detection](https://github.com/uphiago/recon-skills/tree/main/recon/cms-detection)
- [uphiago/recon-skills — vHost enumeration](https://github.com/uphiago/recon-skills/tree/main/recon/vhost-enumeration)
- [uphiago/recon-skills — email security](https://github.com/uphiago/recon-skills/tree/main/recon/email-security)
- [uphiago/recon-skills — visual recon](https://github.com/uphiago/recon-skills/tree/main/recon/visual-recon)
- [uphiago/recon-skills — port & service discovery](https://github.com/uphiago/recon-skills/tree/main/recon/port-service-discovery)
- [uphiago/recon-skills — staging subdomain hunt](https://github.com/uphiago/recon-skills/tree/main/recon/staging-subdomain-hunt)
- [uphiago/recon-skills — GitHub secret hunting](https://github.com/uphiago/recon-skills/tree/main/recon/github-secret-hunting)
- [uphiago/recon-skills — GitLab public recon](https://github.com/uphiago/recon-skills/tree/main/recon/gitlab-public-recon)
- [uphiago/recon-skills — error log mining](https://github.com/uphiago/recon-skills/tree/main/recon/error-log-mining)
- [elementalsouls/Claude-BugHunter — recon scope triage](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/recon-scope-triage)
- [uphiago/recon-skills — 401/403 bypass](https://github.com/uphiago/recon-skills/tree/main/recon/401-403-bypass)
- [uphiago/recon-skills — API no-auth hunt](https://github.com/uphiago/recon-skills/tree/main/recon/api-noauth-hunt)
- [uphiago/recon-skills — cache attack](https://github.com/uphiago/recon-skills/tree/main/recon/cache-attack)
- [uphiago/recon-skills — source leak hunt](https://github.com/uphiago/recon-skills/tree/main/recon/source-leak-hunt)
- [uphiago/recon-skills — hardcoded credential hunt](https://github.com/uphiago/recon-skills/tree/main/recon/hardcoded-credential-hunt)
- [uphiago/recon-skills — HTTP/2 header impersonation](https://github.com/uphiago/recon-skills/tree/main/recon/http2-header-impersonation)
- [uphiago/recon-skills — humanize automation](https://github.com/uphiago/recon-skills/tree/main/recon/humanize-automation)
- [uphiago/recon-skills — IoT camera recon](https://github.com/uphiago/recon-skills/tree/main/recon/iot-camera-recon)
- [uphiago/recon-skills — port mass scan](https://github.com/uphiago/recon-skills/tree/main/recon/port-mass-scan)
- [uphiago/recon-skills — stealth browser launch](https://github.com/uphiago/recon-skills/tree/main/recon/stealth-browser-launch)
- [uphiago/recon-skills — TLS fingerprint impersonation](https://github.com/uphiago/recon-skills/tree/main/recon/tls-fingerprint-impersonation)
- [uphiago/recon-skills — unauthenticated API flow hijack](https://github.com/uphiago/recon-skills/tree/main/recon/unauth-api-flow-hijack)
