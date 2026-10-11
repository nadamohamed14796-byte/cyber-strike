---
name: attack-subdomain-enumeration
description: "Discover and validate candidate subdomains within an explicitly authorized scope"
category: "recon"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [recon, subdomains, dns, asset-inventory]
tech_stack: [dns, tls, http]
prerequisites:
  - "Written authorization and canonical scope rules"
  - "Approval for any third-party passive lookup provider"
chains_with: [attack-web-recon, attack-port-service-discovery, attack-triage-validation]
sources:
  - "https://github.com/uphiago/recon-skills/blob/main/recon/subdomain-enumeration/SKILL.md"
---

# Subdomain Enumeration

## When to use

Use at recon kickoff, when scope changes, or when an in-scope application points to related hostnames. The output is a candidate asset list, not permission to test every result.

## Prerequisites

Confirm wildcard scope, exclusions, rate limits, permitted active DNS resolution, and whether sending domain names to public data providers is allowed. Tools such as subfinder, dnsx, dig, and httpx are optional dependencies; verify availability and flags locally before use.

## Procedure

1. **Normalize the root domain.** Reject malformed inputs, record the authorized root, wildcard rules, exclusions, and the source of authorization.
2. **Start passively.** Use approved certificate-transparency data, public archives, program asset lists, and configured passive sources. Record source and retrieval time.
3. **Deduplicate candidates.** Normalize case and trailing dots; remove wildcard prefixes while retaining the original source. Keep a separate record of names that fail validation.
4. **Resolve in batches.** Use a batch resolver where available. Record A/AAAA/CNAME results and distinguish unresolved names, wildcard DNS, aliases, and catch-all responses.
5. **Validate ownership and scope.** A hostname appearing in CT or DNS does not prove current ownership or eligibility. Review third-party hosting, SaaS, shared infrastructure, and exclusions.
6. **Probe HTTP only when allowed.** Use low request rates and timeouts. Record redirects, title, status, content type, and fingerprint; avoid deep crawling at this stage.
7. **Prioritize.** Flag staging, admin, API, auth, upload, preview, and legacy hosts as leads for manual review, not as findings.
8. **Persist provenance.** Each result should retain its source, timestamp, scope decision, resolution status, and next action.

## Output contract

Each candidate should include hostname, root-domain relationship, source, first/last seen, DNS records, HTTP observation if authorized, scope status, confidence, and deduplication key. Never store credentials or target-specific sensitive data in the skill repository.

## Verification

- Confirm the candidate is under an authorized domain or explicitly listed asset.
- Check wildcard DNS and parked-domain behavior before treating a host as a real service.
- Confirm that redirects do not lead out of scope.
- Keep ambiguous ownership or third-party SaaS results in a review queue.
- Re-run a low-impact check before handing the host to active testing.

## Pitfalls

- Assuming every discovered subdomain is in scope.
- Treating a CNAME or certificate as proof of ownership.
- Losing provenance while deduplicating.
- Confusing wildcard DNS with thousands of unique live hosts.
- Sending proprietary target names to unapproved third-party sources.
- Launching port scans or vulnerability checks before scope validation.

## CyberStrike integration contract

Verify the real scope resolver, asset store, DNS tool wrappers, and deduplication schema before runtime wiring. This skill must produce candidate assets; it must not authorize active testing on its own.

## Attribution

Adapted from the recon-skills subdomain-enumeration methodology: https://github.com/uphiago/recon-skills/blob/main/recon/subdomain-enumeration/SKILL.md
