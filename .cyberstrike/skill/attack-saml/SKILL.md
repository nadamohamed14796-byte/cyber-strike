---
name: attack-saml
description: "Assess SAML SSO signature, assertion, audience, recipient, and replay validation"
category: "authentication"
version: "1.0.0"
author: "CyberStrike contributors; adapted with attribution"
tags: [saml, sso, identity, assertions]
tech_stack: [xml, saml2, http, identity-provider]
prerequisites:
  - "Explicit authorization for SSO testing and a controlled test IdP/SP"
  - "A captured assertion from a test account, with secrets handled locally"
chains_with: [attack-auth-bypass, attack-oauth, attack-mfa-bypass, attack-triage-validation]
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-saml/SKILL.md"
---

# SAML and SSO Assessment

## When to use

Use when a scoped application supports SAML SSO, an Assertion Consumer Service, or a federation flow between an identity provider and service provider.

## Preconditions and safety

Use a controlled test IdP/SP or program-approved test identity. Do not impersonate real users or submit modified assertions to production identities. Keep assertion contents and signing material private; redact identifiers and tokens from evidence.

## Procedure

1. **Map the trust relationship.** Record IdP and SP identifiers, metadata, signing certificate, ACS URL, audience, recipient, and allowed clock skew.
2. **Capture a valid baseline.** Complete a normal test login and preserve a sanitized assertion locally.
3. **Review signature validation.** Confirm the signature covers the assertion or response element the application actually consumes, and that the trusted key comes from the configured IdP.
4. **Review assertion constraints.** Check issuer, audience, recipient, destination, subject confirmation, validity window, and InResponseTo binding where applicable.
5. **Review identity mapping.** Determine which signed claim controls the user identifier, role, and tenant. Check that unsigned or duplicate elements cannot override the trusted identity.
6. **Review replay handling.** In a test environment, determine whether a consumed assertion is rejected when reused within the validity window.
7. **Review parser behavior.** Look for inconsistent interpretation of duplicate XML elements, namespaces, comments, or signature references using safe test fixtures.
8. **Validate rejection behavior.** Invalid or mismatched test assertions should fail closed and should not create an authenticated session.
9. **Document the control failure.** Record the sanitized request, the relevant assertion structure, expected rejection, and observed session result.

## Verification

A finding requires a repeatable failure of a SAML trust check that produces an unintended authenticated identity or privilege in a controlled test. XML parser oddities without an authentication consequence are not sufficient.

## Pitfalls

- Editing a production assertion for a real user's identity.
- Assuming an XML signature validates every field in the document.
- Confusing IdP authentication with the SP's authorization decision.
- Reporting a parser discrepancy without showing which identity the SP accepted.
- Publishing raw assertions or signing material.

## Remediation guidance

Use maintained SAML libraries, validate signatures against trusted metadata, bind the consumed identity to the signed element, enforce issuer/audience/recipient/destination/expiry checks, and reject replayed assertions.

## CyberStrike integration contract

Verify the real SAML parser/flow harness and test fixture support before runtime integration. Do not claim SAML bypass based on XML mutation alone.

## Attribution

Adapted from Claude-BugHunter hunt-saml: https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/hunt-saml/SKILL.md
