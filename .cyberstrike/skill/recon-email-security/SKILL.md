---
name: recon-email-security
description: "Assess SPF, DKIM, DMARC, MX, MTA-STS, TLS-RPT, and mail transport configuration for domain spoofing and delivery risks."
category: "recon"
version: "1.0.0"
author: "cyberstrike-official"
tags: [email-security, SPF, DKIM, DMARC, DNS, SMTP]
tech_stack: [DNS, SMTP, TLS]
chains_with: [recon-methodology, attack-information-disclosure]
prerequisites:
  - "A confirmed organization-owned domain"
severity_boost:
  high: "A controlled, non-deceptive validation proves that an unauthorized message can pass recipient-side authentication and materially impersonate the organization."
---

# Email Domain Security Assessment

## Objective

Evaluate whether DNS policy and mail authentication allow sender impersonation or expose weaknesses in mail transport. DNS posture alone does not prove that a spoofed message will reach an inbox; receiver policy, alignment, and actual message authentication results matter.

## Methodology

### 1. Inventory mail identity and routing

Collect MX records, SPF TXT records, the _dmarc policy, DKIM selectors known from legitimate messages or provider documentation, and MTA-STS/TLS-RPT records. Record DNS TTLs and delegated subdomains. Assess the organizational domain and mail-sending subdomains separately.

### 2. Evaluate SPF correctly

Check for one valid SPF record, syntax errors, excessive DNS lookups, unintended broad mechanisms, and the terminal qualifier. The qualifiers -all, ~all, ?all, and +all have materially different semantics. SPF authorizes sending hosts for the SMTP envelope domain; it does not alone authenticate the visible From header and must be interpreted with DMARC alignment.

### 3. Evaluate DKIM coverage

Review DKIM signatures from legitimate organization mail and verify selector DNS records, key strength, and signing-domain alignment. A missing guessed selector is not proof DKIM is absent; selectors are sender-specific. A published key proves configuration, not that every mail stream is signed.

### 4. Evaluate DMARC policy and alignment

Parse p, sp, pct, adkim, aspf, rua, and ruf. Determine whether the visible From domain aligns with SPF and/or DKIM. Assess root-domain and subdomain policy. p=none requests monitoring rather than enforcement, but does not automatically prove successful impersonation or total lack of receiver-side protection.

### 5. Evaluate transport controls

Inspect MTA-STS policy and TLS-RPT reporting configuration where published. Check MX host TLS behavior with a normal protocol-aware client, certificate validity, and support for modern TLS. Separate transport encryption posture from sender identity authentication.

### 6. Validate practical impact carefully

Prefer passive DNS and analysis of legitimate test messages. If active spoofing validation is explicitly approved, use a controlled mailbox and a clearly labeled non-deceptive test message; do not target employees, customers, or third parties. Preserve the recipient's Authentication-Results and relevant message headers, then stop.

## What Constitutes a Finding

- A reproducible policy gap creates a meaningful impersonation risk, supported by alignment analysis or a permitted controlled test.
- SPF/DKIM/DMARC syntax or policy weaknesses are described accurately with domain and subdomain scope.
- A weak DNS record alone should be rated by practical impact and recipient behavior, not by a simplistic "spoofable" label.
- MX presence, a missing guessed DKIM selector, or p=none without impact context is not by itself proof of compromise.

## Evidence Requirements

- Sanitized DNS outputs with timestamps and TTLs.
- Parsed SPF/DMARC values and lookup-count analysis.
- If approved, a controlled test message's sanitized Authentication-Results, From, Return-Path, DKIM d=, and DMARC alignment result.
- Never include recipient personal data, session material, or deceptive-message content in reusable artifacts.

## Tools

- dig/host for DNS records.
- A reputable SPF/DMARC parser for syntax and lookup analysis.
- Mail clients or test inboxes controlled by the tester for approved validation.
- openssl s_client or mail-testing tools for SMTP TLS negotiation where permitted.
- MTA-STS and TLS-RPT policy checkers.

## Email Control Matrix

| Control | Strong posture | Weak signal | Interpretation caveat |
|---|---|---|---|
| SPF | One valid record, narrow senders, deliberate terminal policy | Permissive +all, invalid record, excessive lookups | SPF authenticates envelope sender, not visible From alone |
| DKIM | Relevant streams signed with aligned domain and adequate key | Unsigned stream or misaligned signature | Unknown selector does not mean no DKIM |
| DMARC | p=reject after monitoring, correct alignment and subdomain policy | p=none, partial rollout, weak alignment | Receiver handling can differ; policy is not delivery proof |
| MX | Expected mail providers only | Stale/unexpected MX | MX is routing metadata, not spoofing proof |
| MTA-STS | Valid policy with enforce mode where appropriate | Missing/expired policy or testing mode | Applies to SMTP transport, not sender identity |
| TLS-RPT | Reports configured and reviewed | No reporting visibility | Reporting absence is usually hardening, not direct exploit |
| Subdomains | Explicit sending and DMARC strategy | Unmanaged subdomain mail | Parent policy and sp behavior must be checked |

## Verification and False Positives

- Re-query DNS from independent resolvers and account for TTL/propagation.
- Check for duplicate SPF records and parse nested includes rather than judging one TXT string.
- Evaluate SPF and DKIM alignment with the exact visible From domain.
- Distinguish transport TLS findings from spoofing findings.
- Do not infer that any third-party service allowed by SPF can freely send as the domain; provider-side account/domain verification controls matter.
- Avoid claims of complete spoofing without a controlled recipient-side result or strong technical proof.


## Signal Confidence, Attempt Budget, and Handoff

Treat recon output as a candidate lead, not a finding. The validation budget is at most 20 distinct hypotheses per candidate asset; it is not permission for 20 scans or repeated probes. Prefer passive sources first, deduplicate candidates, and use active checks only when the asset and activity are explicitly in scope.

### Evidence record and confidence

For each candidate, preserve normalized asset, source/provenance, observation time, scope proof, resolver/HTTP/tool and relevant version, raw-evidence location, corroborating source, negative control, attribution confidence, next action, and related-skill trigger. Separate **asset confidence** (is it related to the organization?) from **security confidence** (is a vulnerability demonstrated?).

Use this scale consistently: **C0** unverified string; **C1** one passive source; **C2** independently corroborated attribution or service response; **C3** specific configuration/exposure verified with a control; **C4** security impact independently reproduced within scope. C1/C2 are not confirmed vulnerabilities.

### Skill-specific next steps

undefined

### Deduplication and stop rules

Normalize case, trailing dots, scheme/port, redirects, canonical names and resolved addresses before deduplication. Detect wildcard DNS, shared hosting, CDN/edge responses, soft-404s and stale records before ranking counts. Stop on exclusions, ownership ambiguity, unexpected sensitive data, throttling, instability or boundaries requiring further permission. Never claim ownership or register dangling resources.

### Handoff format

Return candidates with scope/provenance, confidence level, evidence path, deduplication key, negative control, priority rationale, safe next step and trigger for any linked attack skill. Promote a candidate to active testing only after scope and attribution are confirmed; promote it to a finding only after the relevant attack skill verifies the security boundary.

## References

- Source merged: [uphiago/recon-skills — recon/email-security/SKILL.md](https://github.com/uphiago/recon-skills/blob/main/recon/email-security/SKILL.md)
- [RFC 7208 — SPF](https://www.rfc-editor.org/rfc/rfc7208)
- [RFC 6376 — DKIM](https://www.rfc-editor.org/rfc/rfc6376)
- [RFC 7489 — DMARC](https://www.rfc-editor.org/rfc/rfc7489)
- [RFC 8461 — MTA-STS](https://www.rfc-editor.org/rfc/rfc8461)
- [RFC 8460 — TLS Reporting](https://www.rfc-editor.org/rfc/rfc8460)
