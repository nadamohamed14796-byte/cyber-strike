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


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue with materially distinct, authorized checks while evidence can change the conclusion; deduplicate equivalent assertion mutations and retries. Stop when direct evidence resolves the hypothesis, meaningful branches are exhausted, a prerequisite is unavailable, or scope/safety requires stopping. Use only owned test IdP/SP artifacts.

Keep an attempt ledger: hypothesis, one variable changed, baseline/control, signal, interpretation, confidence and next branch. Use controlled identities/fixtures, independent corroboration, low-impact requests and minimum sanitized evidence.

### Skill-specific hypothesis order

1. Use a dedicated test IdP/service-provider tenant and test users; capture a successful baseline assertion, audience/recipient, issuer, destination, signature, and relay state.
2. Change one protocol property at a time in controlled fixtures: audience, recipient, issuer, timestamp/expiry, signature coverage, response/assertion pairing, or relay-state binding.
3. Check signature validation and account/tenant binding against the service provider's expected configuration; do not modify or replay assertions belonging to real users.
4. Validate acceptance only by signing into a test account and confirming its identity/privileges, with a fresh valid assertion as the positive control and one invalid assertion as the negative control.
5. Capture sanitized metadata and the exact violated invariant, discard test assertions after use, and recommend strict signature/canonicalization validation, replay protection, and explicit audience/recipient checks.


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


## Targeted quality-loop enrichment (2026-10-19)

### Assertion-to-session binding map
Use an IdP/SP configuration and tester-owned identities. Record issuer, audience, recipient, destination, InResponseTo, signature reference, assertion subject, time conditions, relay state, and final SP principal. Change only one binding dimension at a time in a lab or sanctioned test integration; do not forge assertions for real accounts or bypass an external provider. Signature validity alone is not enough if the application maps the assertion to the wrong tenant or role. Confirm the resulting controlled identity and revoke sessions after testing. Route XML parser defects to XXE review and identity-linking outcomes to ATO only when the terminal account-control state is reproduced.


## Signature and identity-binding review checklist

For source/configuration review, verify these as separate invariants rather than treating “signature valid” as the entire SAML security decision.

- The signature is verified with an explicitly trusted IdP key and the exact assertion/response consumed by the application.
- XML canonicalization and reference resolution are delegated to a maintained SAML library; application code does not select a different unsigned node after verification.
- Response issuer, assertion issuer, audience, recipient, destination, InResponseTo, and time conditions match the expected SP transaction.
- Assertion IDs are replay-protected, and relay state is integrity-protected and bound to the initiating browser transaction.
- Subject mapping uses stable provider + tenant + subject identifiers, not display name or mutable email alone.
- Role/group claims are allowlisted and mapped according to explicit trust policy; arbitrary attributes cannot grant privileged roles.
- XML parser configuration blocks external entities and unsafe DTD resolution; verify in a local harness, never by reading production files or calling external entities.

### Correlated transaction fields

Record transaction_id, idp_entity_id, sp_entity_id, acs_url, response_issuer, assertion_issuer, signature_reference_target, audience, recipient, destination, in_response_to, relay_state_integrity, time_window_result, replay_result, mapped_test_subject, effective_test_role, and cleanup_status. Do not save raw assertions or session tokens in shared notes.

### Chain gates

- Wrong principal or role accepted in the test SP → ATO/auth-bypass review after terminal-state proof.
- Unsafe XML parsing is present → XXE review only with separate local/source evidence.
- Redirect/relay-state destination issue → OAuth/open-redirect review only when a trusted redirect boundary is violated.
- Signature validation warning with no accepted wrong assertion → configuration lead, not ATO.


## Agent-executable CLI tooling, resources, and helper scripts

Use non-interactive CLI tools and local fixtures the agent can run and parse. Browser UI, extensions, and interactive proxies are not agent dependencies.

### Tools and purpose
- Python `lxml` or the standard XML parser — inspect synthetic SAML messages and validate XML structure locally; do not treat parse success as signature or trust validation.
- `xmlsec1` — inspect/verify XML signatures only against a controlled fixture and known test keys.
- `curl` or Python `httpx` — reproduce an observed, authorized protocol flow with tester-owned identities.
- `jq` — parse structured service metadata and redact fields in saved outputs.
- Existing helper `python3 .cyberstrike/skill/scripts/http_response_diff.py baseline-redacted.txt candidate-redacted.txt` — compare saved redacted responses offline.

### Install and verify
Install XML tooling from official OS repositories or the upstream project documentation. Verify with `xmlsec1 --version`, `curl --version`, and `python3 -c "import lxml; print(lxml.__version__)"` when selected. If unavailable, inspect synthetic fixtures with the standard library and record the limitation. Do not upload live assertions, private keys, or session material to public decoders.

### Resources
- https://www.oasis-open.org/standard/saml/
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- https://owasp.org/www-project-web-security-testing-guide/
- https://github.com/lxml/lxml
- https://github.com/lsh123/xmlsec

### Evidence and result handling
Use a test identity and authorized relying party. Preserve synthetic or redacted assertions, issuer/audience/recipient/destination checks, signature-validation result, and the relying party's resulting session behavior. A malformed message or XML parse result alone does not prove authentication bypass. Never expose another user's data.
