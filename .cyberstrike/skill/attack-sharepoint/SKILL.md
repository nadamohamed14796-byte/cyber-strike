---
name: attack-sharepoint
description: "Review authorized SharePoint exposure, permissions, sharing links, and identity boundaries"
category: "enterprise-security"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [sharepoint, microsoft-365, permissions, identity]
tech_stack: [sharepoint, m365, entra, graph-api]
prerequisites:
  - "Written authorization for the tenant, sites, and test accounts"
  - "Read-only configuration access and synthetic test documents where possible"
chains_with: [attack-m365-entra, attack-oauth, attack-idor-automation, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-sharepoint/SKILL.md"
---

# SharePoint Security Assessment

## When to use

Use when reviewing authorized SharePoint sites, external sharing, guest access, application permissions, search exposure, or document-level access controls.

## Safety gate

Use only the approved tenant and test identities. Do not enumerate or download real users' documents, alter sharing on production content, or create external sharing links without explicit approval.

## Procedure

1. Confirm tenant, site collection, test accounts, and exclusions.
2. Review external sharing defaults, guest invitation policy, link types, expiry, and access restrictions from configuration.
3. Create or use a synthetic test document to compare owner, internal user, guest, and anonymous access where permitted.
4. Verify whether search results, preview endpoints, download APIs, and sharing links enforce the same document permissions.
5. Review app registrations and Graph permissions relevant to SharePoint access; distinguish delegated from application permissions.
6. Check whether offboarding/group membership changes revoke access as expected using test identities.
7. Record only minimal metadata and synthetic document evidence.
8. Recommend least privilege, constrained sharing, expiry, access reviews, and app-permission reduction.

## Pitfalls

- A share link may intentionally grant access to anyone who has it.
- Search indexing is not proof of unauthorized document access.
- A permission shown in an app registration may not be granted or effective.

## Verification

Demonstrate access with a controlled identity to a synthetic resource or confirm effective policy through read-only configuration. Do not expose real document contents.
