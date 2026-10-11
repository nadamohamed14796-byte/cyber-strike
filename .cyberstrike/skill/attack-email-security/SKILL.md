---
name: attack-email-security
description: "Review authorized email-domain controls and messaging exposure with evidence-led checks"
category: "recon"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [email, spf, dkim, dmarc, mx]
tech_stack: [dns, smtp, email]
prerequisites:
  - "Authorized domain list and engagement rules"
  - "DNS and mail checks limited to in-scope domains"
chains_with: [attack-web-recon, attack-triage-validation, attack-report-writing]
sources:
  - "https://github.com/uphiago/recon-skills/blob/main/recon/email-security/SKILL.md"
---

# Email Domain Security Assessment

## When to use

Use when assessing domain-level email authentication, mail routing, exposed mail services, and publicly accessible email security configuration.

## Scope and safety

Only assess authorized domains. Prefer DNS and configuration checks; do not send phishing messages, test real mailboxes, attempt password login, or conduct mail flooding.

## Procedure

1. Normalize the authorized domain list and preserve source/scope evidence.
2. Query MX, SPF, DKIM selectors known from public configuration, and DMARC records using approved DNS tooling.
3. Evaluate whether SPF is syntactically valid and appropriately scoped; note excessive lookups or overly broad mechanisms without overclaiming impact.
4. Check DMARC policy, alignment, reporting configuration, and whether the policy is monitoring-only or enforcement.
5. Verify DKIM only where a published selector is known; absence of a guessed selector is not proof that DKIM is missing.
6. Record mail-host exposure from public DNS and banners only where active checks are permitted.
7. Separate spoofing risk, configuration hygiene, and confirmed deliverability behavior. Do not send spoofed mail to real recipients as proof.
8. Recommend incremental enforcement, selector rotation planning, reporting review, and removal of stale DNS records.

## Pitfalls

- SPF, DKIM, and DMARC solve different parts of sender authentication.
- A DMARC `p=none` policy is weaker enforcement but may be intentional during rollout.
- A missing record on one subdomain does not prove the organizational domain is misconfigured.
- Public MX records are expected and not a finding.

## Verification

Include queried domain, record type, DNS response and TTL, evaluation date, policy interpretation, and limitations. Avoid claims about real-world spoofability unless a safe authorized validation demonstrates it.
