---
name: attack-subdomain-takeover
description: "Validate dangling DNS and orphaned service bindings before classifying a subdomain takeover risk"
category: "recon"
version: "1.1.0"
author: "CyberStrike contributors; consolidated with upstream attribution"
tags: [subdomain, takeover, dns, cname, cloud]
tech_stack: [dns, http, cloud, cdn]
cwe_ids: [CWE-350]
chains_with: [recon-methodology, attack-triage-validation]
prerequisites:
  - "The hostname must be explicitly in scope"
  - "Permission for DNS/service validation; no unauthorized resource claiming"
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-subdomain/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
---

# Subdomain Takeover Assessment

## Objective

Determine whether an in-scope hostname points to a deprovisioned third-party service or unclaimed resource and whether the binding is actually claimable under the provider's current rules. A dangling CNAME or provider error page is a lead, not a confirmed takeover.

## Scope and safety

Only assess hostnames included by the program's scope rules. Do not register, claim, or attach the target's hostname to an account/service unless the program explicitly authorizes a controlled proof. Never serve content to visitors or collect traffic. Use DNS and provider documentation first.

## Procedure

### 1. Establish scope and DNS chain

Record the exact hostname, CNAME/A/AAAA chain, TTL, authoritative DNS, and source of discovery. Confirm wildcard and excluded-host rules. Resolve again to rule out transient DNS failures.

### 2. Identify provider and binding state

Map the DNS target to the likely hosting/CDN/storage provider using current provider documentation. Record the exact error or unbound-resource indicator. Do not infer a vulnerable state from branding or an HTTP 404 alone.

### 3. Verify current claimability safely

Use provider-specific verification rules and a test resource only when explicitly authorized. If safe non-invasive verification cannot establish claimability, mark the issue as a dangling-DNS lead rather than takeover. Do not create an account or claim a resource merely to prove impact unless permitted.

### 4. Exclude benign explanations

Check for maintenance, decommissioned-but-intentionally-retained DNS, provider migration, custom error pages, delayed DNS propagation, wildcard records, and ownership verification controls. Confirm the resource is not already bound to the legitimate owner.

### 5. Assess impact and remediation

Explain which hostname is affected, the DNS record and provider, whether takeover is confirmed or only suspected, and the potential trust impact. Recommend removing stale DNS records or restoring/claiming the intended resource through the legitimate owner.

## Common false positives

- A provider-branded 404 with a valid resource binding.
- A dangling-looking CNAME that cannot be claimed due to ownership verification.
- A transient provider outage or DNS propagation delay.
- A hostname outside the program's scope.
- A takeover claim based only on a scanner signature.

## Output contract

Return `hostname`, `scope_evidence`, `dns_chain`, `provider`, `orphan_signal`, `claimability_status`, `proof_method`, `impact`, `confidence`, and redacted evidence.


## Targeted quality-loop enrichment (2026-10-19)

### Current ownership, not stale DNS alone
Record the DNS chain, target provider, record freshness, provider-specific claimability evidence, and the intended scope/ownership decision. A dangling CNAME, NXDOMAIN, generic provider error, or archived screenshot is not proof that an attacker can claim the resource today. Prefer provider documentation and read-only confirmation; never register a target's namespace, publish content, or alter DNS as a proof. Exclude shared CDN/cloud tenancy and domains that the program does not authorize. Chain to source-leak or certificate-transparency recon only as a discovery source; report takeover only when current claimability is demonstrated under permitted conditions, otherwise preserve an inconclusive lead with exact evidence gaps.


## Agent-executable CLI tooling, resources, and helper scripts

Use CLI tools and local scripts the agent can invoke directly; browser UI, extensions, and interactive intercepting proxies are not dependencies. Verify official install docs, version, license, platform compatibility, and operational impact before use.

### Recommended tools
- dig/drill — DNS and CNAME chain checks
- dnsx — resolve candidate records
- subzy or dnsReaper — fingerprint potential dangling services when explicitly authorized
- Python — compare provider signatures and DNS state

### Resources
- https://github.com/projectdiscovery/subzy
- https://github.com/michenriksen/aquatone
- https://github.com/vavkamil/awesome-bugbounty-tools
- https://github.com/vavkamil/awesome-bugbounty-tools

Community lists are discovery aids, not a substitute for reviewing source, release provenance, and supported behavior.

### Helper-script contract
Record CNAME chain, provider signature, authoritative DNS state, and false-positive controls. Do not claim takeover from a dangling-looking CNAME alone; never register or claim a resource as part of automated validation.

Preserve native evidence; normalize to a separate file. Keep source, timestamp, tool/version, error state, confidence, and redaction. Use explicit paths, machine-readable output, and local test fixtures. Never silently treat missing data as a pass.

### Handoff
Return actual commands/tool versions, input/output paths, records checked, failures, confidence, limitations, and next skill. A detected service or misconfiguration is a lead until impact is confirmed.
