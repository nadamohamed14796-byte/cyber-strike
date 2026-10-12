---
name: attack-subdomain-takeover
description: "Subdomain takeover — CNAME detection, cloud service fingerprinting, dangling DNS exploitation"
category: "web-application"
version: "1.1.0"
author: "cyberstrike-official"
tags:
  - subdomain-takeover
  - dns
  - cloud
  - web
  - attack
tech_stack:
  - aws
  - azure
  - gcp
  - web
cwe_ids:
  - CWE-284
chains_with: []
prerequisites: []
severity_boost: {}
---

# Subdomain Takeover

## Objective

Identify subdomains with dangling DNS records (CNAME pointing to unclaimed cloud resources) and claim them to serve attacker content.

## Testing Methodology

### Phase 1: Subdomain Enumeration

```bash
# Passive enumeration
subfinder -d TARGET.com -silent | tee subdomains.txt

# Certificate transparency
curl --max-time 15 --connect-timeout 5 -s "https://crt.sh/?q=%25.TARGET.com&output=json" | jq -r '.[].name_value' | sort -u >> subdomains.txt

# DNS brute force
puredns bruteforce wordlist.txt TARGET.com -r resolvers.txt >> subdomains.txt
```

### Phase 2: Automated Takeover Check

```bash
# Check all subdomains for takeover
attack_script subdomain_takeover subdomains.txt --json-output
```

Checks 20 cloud services:
- GitHub Pages, Heroku, Shopify, Tumblr, WordPress
- AWS S3, AWS Elastic Beanstalk, Azure Web Apps
- Netlify, Vercel, Fastly, Fly.io
- Bitbucket, Surge, Ghost, Pantheon
- Zendesk, README.io, Cargo, Feedpress

### Phase 3: Manual CNAME Verification

```bash
# Check CNAME records
dig +short CNAME subdomain.TARGET.com

# Verify the pointed service is unclaimed
curl --max-time 15 --connect-timeout 5 -s https://subdomain.TARGET.com
# Look for: "There isn't a GitHub Pages site here"
# "No such app" (Heroku)
# "NoSuchBucket" (S3)
```

### Phase 4: Cloud Storage Enumeration

```bash
# Check related cloud buckets
attack_script cloud_storage_enum TARGET --json-output
```

### Phase 5: Claim & Verify

After confirming a dangling CNAME:
1. Create the resource on the target service (e.g., GitHub Pages repo, S3 bucket)
2. Serve a harmless proof page (e.g., `cyberstrike-takeover-proof.html`)
3. Verify it's accessible at `subdomain.TARGET.com`

## What Constitutes a Finding

| Finding | Severity |
|---------|----------|
| Takeover confirmed on an in-scope hostname with a harmless proof of control | Severity depends on hostname trust, content reach, and impact |
| Public write access to an in-scope storage resource with impact validated safely | Severity depends on writable content, permissions, and affected users |
| Public listing exposes non-public objects or sensitive metadata | Severity depends on exposed data and access controls |
| Dangling CNAME without confirmed claimability | Not a confirmed takeover; do not report as exploitable without provider-specific validation |
| Public read exposes non-public or sensitive test data | Severity depends on data sensitivity and scope |

## Evidence Requirements

- Subdomain with dangling CNAME record
- Target cloud service identified
- Service fingerprint (error message)
- For takeover: proof of content hosting on subdomain
- For buckets: listing output or write proof

## Tools

- `attack_script subdomain_takeover` — automated CNAME + fingerprint checker
- `attack_script cloud_storage_enum` — S3/Azure/GCP enumeration
- `subfinder`, `puredns` — subdomain enumeration

## Verification and False Positives

- A dangling CNAME or stale DNS record is a lead, not proof of takeover. Confirm the target service is unclaimed and that the provider-specific error/claim flow matches the documented takeover condition.
- Do not register, claim, delete, or modify the target resource unless the program explicitly authorizes ownership-claim validation. Prefer non-invasive provider fingerprinting and a unique harmless proof under a permitted test setup.
- Distinguish abandoned service responses from provider-wide outages, custom error pages, DNS propagation, and misconfigured but non-claimable resources.
- Confirm the hostname is in scope and controlled by the organization. A third-party or vendor-owned hostname may be excluded even if its DNS appears stale.
- Record DNS chain, TTL, provider fingerprint, timestamp, and evidence of claimability. Avoid serving malicious content or collecting visitors.
## DNS Ownership and Claimability Decision Tree

Treat dangling DNS as a lead, not proof. For each in-scope hostname, record the authoritative CNAME/alias chain, final provider, current DNS status, and whether the provider returns a documented unclaimed-resource signature.

1. Confirm the hostname is in scope and capture DNS answers with a timestamp.
2. Resolve the complete alias chain and distinguish NXDOMAIN, provider-side not-found, parked resources, and transient DNS failures.
3. Check the provider's current documented claimability conditions and whether registration is actually possible; a generic error page is insufficient.
4. Do not register the target resource, upload content, or take control of the hostname unless the program explicitly permits takeover simulation. Use provider documentation and a controlled equivalent to validate claimability.
5. Recheck DNS and provider response before reporting because resource ownership can change.

Evidence should include the hostname, sanitized DNS chain, provider-specific response, relevant claimability documentation, and realistic impact. Avoid claiming account takeover or cookie theft without proving applicable cookie scope and browser behavior.


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Use the 20-attempt budget as a ceiling for independent evidence-producing hypotheses, not as a quota for payload mutations. Follow relevant signal-led branches only while the candidate remains plausible; stop early on decisive evidence, scope/safety limits, or when no meaningful branch remains. Cosmetic variants are not separate hypotheses.

Track each attempt as hypothesis, one variable changed, baseline/control, observed signal, interpretation, confidence, and next branch. Prefer paired requests and controlled test identities/fixtures; save only minimal sanitized evidence.

### Skill-specific hypothesis order

Choose distinct low-impact checks supported by the skill's existing matrix and avoid equivalent probes.

### Verdict gates

- **Confirmed:** repeatable impact at an explicit in-scope boundary is demonstrated using a controlled identity/fixture and a meaningful control.
- **Likely / needs corroboration:** independent indicators support the candidate, but the consequence or root cause remains uncertain.
- **Unconfirmed:** evidence is generic, ambiguous, cached, or not tied to a security property.
- **Refuted / false positive:** a relevant negative control or valid implementation/policy explanation accounts for the observation. Document tested branches; do not claim all imaginable variants were exhausted.
- Scanner alerts, version strings, banner text, status codes, and response length alone are not proof.

### Stop, cleanup, and handoff

Stop on scope ambiguity, unexpected user data, state changes, service degradation, secret exposure or prohibited behavior. Clean disposable test state and revoke temporary sessions/tokens where possible. Return scope proof, baseline, hypothesis, attempts used, impact, negative controls, verdict/confidence, sanitized evidence and cleanup status. Start a chained skill only when its trigger has been independently observed.

## References

- [Can I Take Over XYZ](https://github.com/EdOverflow/can-i-take-over-xyz)
- [HackerOne: Subdomain Takeover](https://www.hackerone.com/vulnerability-management/guide-subdomain-takeovers)
