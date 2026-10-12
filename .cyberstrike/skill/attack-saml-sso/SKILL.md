---
name: attack-saml-sso
description: "Assess SAML service-provider validation of signatures, audience, recipient, issuer, timestamps, replay, and identity mapping using controlled IdP/SP test tenants."
category: "identity"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - saml
  - sso
  - federation
  - xml-signature
  - authentication
tech_stack:
  - saml2
  - xml
  - identity-provider
  - service-provider
  - adfs
cwe_ids:
  - CWE-347
  - CWE-287
  - CWE-611
chains_with:
  - attack-ato
  - attack-auth-bypass
  - attack-xxe
  - attack-oauth
prerequisites: []
severity_boost:
  attack-ato: "SAML assertion validation becomes ATO only if a test SP establishes the wrong test principal or role."
---

# SAML Single Sign-On Assessment

## Objective

Verify that a service provider validates the exact signed assertion it consumes and enforces issuer, audience, recipient, destination, time, replay, and identity-mapping controls. Use only an owned test IdP/SP or a program-provided federated test tenant.

## Testing Methodology

### Phase 1: Map IdP/SP metadata and bindings

Identify assertion consumer service (ACS), entity IDs, signing keys, supported bindings, NameID format, and attribute-to-role mapping. Confirm both IdP and SP are in scope before sending modified assertions.

### Phase 2: Capture a valid baseline assertion

Perform a normal SAML login for a test account and save a sanitized assertion structure. Record issuer, assertion ID, subject, audience, recipient, destination, NotBefore/NotOnOrAfter, signature reference, and resulting test principal.

### Phase 3: Test signature and assertion binding in a lab

Use a test signing key and harness to mutate harmless assertion fields, duplicate assertions, alter references, or omit a signature. Verify invalid or ambiguous inputs are rejected. Do not forge assertions for real identities or send untrusted assertions to production unless explicitly authorized.

### Phase 4: Verify audience, recipient, issuer, and time

In the test environment, alter one constraint at a time or use fixtures from another test SP/issuer. Check cross-SP assertions, expired assertions, wrong destination, replayed IDs, and untrusted issuer/key are rejected.

### Phase 5: Review XML parsing and XXE safely

Check parser configuration disables external entities and unsafe DTD processing. Use static configuration/source review or local harnesses; never request local files or external entity callbacks from a production SP.

### Phase 6: Confirm principal and role mapping

Verify the accepted test assertion maps to the intended subject and allowed roles. Confirm display-name or locale changes do not alter identity authorization. Revoke test sessions and clean up.

## What Constitutes a Finding

- **Candidate / lead:** public metadata, parser warnings, unusual XML responses, or weak signature/configuration settings.
- **Confirmed finding:** a test SP accepts a tampered, wrong-issuer, wrong-audience, expired, replayed, or unsigned test assertion contrary to its trust policy.
- **Impact-qualified finding:** the accepted test assertion establishes a different controlled principal or unauthorized role.
- **Not a finding:** metadata exposure alone, XML manipulation that changes only cosmetic attributes, or a parser error without an authorization outcome.

## Evidence Requirements

- Sanitized valid and invalid test assertions, source tenant, SP/IdP IDs, and timestamp.
- Signature reference and validation result, issuer/audience/recipient/time checks, replay result, and resulting test principal.
- Redact assertion values, personal attributes, certificates/private keys, and session tokens as appropriate.
- Note whether validation was performed in a lab harness or approved test tenant.

## Tools

- **SAML-tracing browser extension:** capture test SAMLRequest/SAMLResponse flow.
- **xmlsec tooling:** verify signatures and references in controlled fixtures.
- **Metadata parser:** inspect entity IDs, ACS endpoints, and signing certificates.
- **Source review / XML parser tests:** verify secure parser options and subject mapping.

## SAML Assertion Validation Matrix

| Control | Test fixture | Expected behavior |
|---|---|---|
| Signature presence/validity | Modified or unsigned assertion signed only in test harness | Reject invalid or missing required signature |
| Signature-to-consumed-node binding | Multiple/duplicated test assertions | Consume only the exact cryptographically verified assertion |
| Issuer and key trust | Assertion from a different test issuer | Reject unknown issuer or untrusted signing key |
| Audience / recipient / destination | Controlled mismatch per field | Reject assertion intended for another SP/ACS |
| Time / replay | Expired test assertion and reused assertion ID | Reject outside validity window and replay per policy |
| Subject/attribute mapping | Alter harmless test claim; compare principal | Claims cannot select an unauthorized real or test identity |
| XML external entities | Review parser config and local harness | DTD/external entity resolution disabled unless expressly required |

**Mitigation:** validate signatures with a maintained SAML library, bind validation to the consumed assertion, enforce issuer/audience/recipient/time, prevent replay, harden XML parsers, and use immutable subject identifiers.

## Verification and False Positives

- Public IdP metadata is expected and does not itself imply authentication bypass.
- Signature presence is not enough; it must cover the exact assertion being consumed.
- An assertion can be validly signed but intended for a different issuer/audience/recipient.
- Do not edit production assertions to impersonate real users, test third-party IdPs, or attempt external entity file/network access.


## Adaptive Verification Contract (maximum 20 distinct hypotheses)

Use the 20-attempt budget as a ceiling for independent, evidence-producing hypotheses—not as a target number of payloads. If the finding remains plausible, follow distinct signal-led branches up to the ceiling; stop earlier when the effect is decisive, no relevant branch remains, or scope/safety limits apply. Cosmetic variants do not count as independent attempts.

Keep an attempt ledger: hypothesis, one variable changed, baseline/control, signal, interpretation, confidence and next branch. Use controlled identities/fixtures, independent corroboration, low-impact requests and minimum sanitized evidence.

### Skill-specific hypothesis order

Choose independent, low-impact hypotheses supported by this skill's existing coverage matrix.

### Verdict gates

- **Confirmed:** repeatable impact at an explicit in-scope boundary is demonstrated with a controlled fixture/identity and relevant control.
- **Likely / needs corroboration:** multiple independent signals support the candidate but the effect or cause remains uncertain.
- **Unconfirmed:** signal is generic, timing/cache-dependent, or not tied to a security property.
- **Refuted / false positive:** a relevant control or valid product/security behavior explains the observation; preserve the test ledger rather than claiming all theoretical vectors were attempted.
- A status code, banner, parser error, timing fluctuation, version string, or scanner alert alone is not proof.

### Safety, cleanup, and handoff

Stop on scope ambiguity, unexpected state changes, sensitive data, service degradation, secret exposure or prohibited actions. Restore synthetic state and revoke temporary credentials/sessions where possible. Report scope proof, baseline, hypothesis, attempt count, impact, controls, verdict/confidence, sanitized evidence and cleanup status. Chain into another skill only after observing its required signal.

## References

- [uphiago — saml-sso-attack](https://github.com/uphiago/recon-skills/tree/main/auth/saml-sso-attack)
- [uphiago — hunt-saml](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-saml)
- [Claude-BugHunter — hunt-saml](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-saml)
- [OWASP — SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
