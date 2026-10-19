---
name: attack-ldap
description: "Assess LDAP injection and directory-query authorization using controlled test identities and non-destructive query differentials."
category: "identity"
version: "1.0.0"
author: "cyberstrike-official"
tags:
  - ldap
  - injection
  - directory-services
  - authentication
  - web
tech_stack:
  - ldap
  - active-directory
  - java
  - php
  - dotnet
  - web
cwe_ids:
  - CWE-90
chains_with:
  - attack-auth-bypass
  - attack-information-disclosure
prerequisites: []
severity_boost:
  attack-auth-bypass: "LDAP filter manipulation may bypass authentication when a tester-owned identity is accepted without valid proof."
---

# LDAP Injection Assessment

## Objective

Determine whether untrusted input alters LDAP filter or distinguished-name structure, and whether the difference crosses an authentication or data-access boundary. Use a lab directory or authorized test OU with synthetic entries.

## Testing Methodology

### Phase 1: Identify directory-backed features

Map login, employee search, group lookup, provisioning, autocomplete, and administrative queries. Review filter/DN construction. Do not enumerate a production directory without written permission.

### Phase 2: Establish valid query baselines

Use a test identity and synthetic directory entry. Record expected match/no-match results, role, and endpoint. Identify whether input should be a literal or filter fragment.

### Phase 3: Probe escaping and syntax

In lab/approved endpoint, use reserved-character and malformed-filter canaries one at a time. Compare a valid value with invalid value and review errors. Do not use wildcard search to dump entries or enumerate privileged groups.

### Phase 4: Verify authorization outcome

Confirm through test accounts whether query manipulation changes identity or returns an unauthorized synthetic entry. Never attempt login as a real user or modify directory records.

### Phase 5: Review filter/DN controls

Check RFC filter escaping separately from DN escaping, allowlisted attributes, safe directory APIs, and authorization after lookup.

## What Constitutes a Finding

- **Candidate / lead:** malformed input produces a directory parser error or query results change unexpectedly.
- **Confirmed finding:** input reproducibly alters query logic beyond the intended literal field and affects synthetic entry or authentication outcome.
- **Not a finding:** error alone, intentional broad search, or response without an unauthorized result.

## Evidence Requirements

- Sanitized baseline/probe requests, input field, role, timestamp, and environment.
- Synthetic directory entry IDs and expected/actual result.
- Source trace to filter/DN construction and escaping function where available.
- No real directory records, password hashes, or group dumps.

## Tools

- **Burp Suite:** compare directory-backed requests.
- **ldapsearch:** use only against owned lab/test directory and scoped base DN.
- **Source review:** locate filter/DN concatenation and escaping.
- **Directory audit logs:** corroborate only the test identity's query.

## LDAP Context and Evidence Matrix

| Context | Risk | Safe verification |
|---|---|---|
| Search filter | Metacharacter changes predicate | Known synthetic entry, bounded query |
| Login filter | Query changes identity selection | Tester-owned accounts and baseline |
| Distinguished name | DN structure changes target | Lab OU and synthetic DN only |
| Attribute selection | Caller controls protected field name | Review allowlist/source or safe test field |
| Group/role lookup | Query changes authorization mapping | Synthetic group and test principal |
| Error handling | Internal filter/DN leak | Capture sanitized error; no enumeration |

**Mitigation:** safe directory APIs, correct context-specific escaping, allowlisted attributes, authorization after lookup, and invalid-character regression tests.

## Verification and False Positives

- Parser errors can originate in validation middleware.
- Filter and DN escaping are different contexts.
- Intentional search behavior must be judged against access policy.
- Stop before broad production queries, employee enumeration, sensitive attributes, or directory changes.


## Adaptive Verification Contract (evidence-driven; no arbitrary hypothesis ceiling)

Do not impose an arbitrary fixed ceiling on meaningful verification hypotheses. Continue with materially distinct, authorized checks while evidence can change the conclusion; deduplicate cosmetic variants and exact retries. Stop when direct evidence resolves the hypothesis, meaningful branches are exhausted, a prerequisite is unavailable, or scope/safety requires stopping. Do not broaden into directory enumeration or credential guessing.

Track each attempt as: hypothesis, one changed variable, baseline/control, observed signal, interpretation, confidence, and next branch. Use controlled identities or synthetic resources, preserve only minimal evidence, and redact secrets.

### Skill-specific hypothesis order

1. Map the application's LDAP-backed field and expected query behavior from normal traffic, then record valid and invalid baseline inputs.
2. Use benign metacharacter and type-boundary probes to detect whether input changes query structure; compare error, result count, and behavior against a known-no-match control.
3. Test login/search/filter contexts separately and change one input field at a time. Do not enumerate the directory, dump entries, attempt credential guessing, or alter directory objects.
4. Confirm only a controlled authentication/authorization or data-filtering effect using test identities and synthetic directory entries; a verbose LDAP error alone is a signal, not impact.
5. Recommend parameterized/escaped LDAP filters and least-privilege bind accounts, then add regression cases for special characters and empty/no-match values.


### Verdict gates

- **Confirmed:** repeatable security impact is shown against an in-scope resource using a tester-controlled identity or fixture, with a meaningful control.
- **Likely / needs corroboration:** independent signals support the hypothesis but impact or root cause is not yet established.
- **Unconfirmed:** observations are ambiguous, cached, generic, or not tied to a security boundary.
- **Refuted / false positive:** a relevant negative control or valid policy/implementation explanation accounts for the observation; document the attempts instead of claiming all imaginable variants were exhausted.
- Do not treat status codes, error text, response length, decoded tokens, static findings, or UI state alone as proof.

### Stop, cleanup, and handoff

Stop at scope uncertainty, unrelated sensitive data, unexpected production changes, service degradation, secret exposure, or prohibited actions. Restore disposable state and revoke test tokens/sessions where possible. Return the scope proof, baseline, hypothesis, attempt count, impact, controls, confidence/verdict, sanitized evidence pointers, relevant handoff signal and cleanup status. Chain into another skill only when its trigger is present.

## References

- [uphiago — hunt-ldap](https://github.com/uphiago/recon-skills/tree/main/redteam/hunt-ldap)
- [Claude-BugHunter — hunt-ldap](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills/hunt-ldap)
- [OWASP LDAP Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html)


## Targeted quality-loop enrichment (2026-10-19)

### Directory filter vs authorization outcome
Identify the feature and query context first—search filter, user lookup, group membership, or distinguished name—and capture one valid and one known-invalid tester-controlled query. Use inert syntax boundary variations and compare result semantics, not just error text; a filter error is not proof that an attacker can change the query meaning. Check that any result stays within the intended directory attributes and authorization policy. Avoid broad directory dumps, password/hash collection, or authentication against real users. Route a confirmed identity-boundary effect to authentication/BFLA, and keep parser error disclosures separate unless they reveal material sensitive data.


## Query-context differential and evidence record

Keep filter escaping, DN escaping, and authorization as separate checks. A value safe for one context may not be safe for another.

| Context | Normal control | Candidate comparison | Required proof |
|---|---|---|---|
| User lookup | Exact known test username | Reserved characters in the same input field | Query semantics change beyond literal matching |
| Search filter | One synthetic entry and a known-no-match value | Single reserved-character variation | Unexpected synthetic result or source-confirmed unsafe construction |
| DN construction | Known test OU and synthetic DN | One escaped-name boundary | Lookup escapes intended OU/object boundary in lab |
| Group membership | Test principal in a synthetic group | Controlled membership/query variation | Effective authorization changes unexpectedly |
| Attribute selection | Documented allowed attribute | One unsupported attribute | Server rejects it or unsafe field access is demonstrated |
| Error handling | Normal invalid input | Malformed syntax canary | Sensitive implementation detail is actually disclosed |

### Root-cause review

Inspect whether the implementation uses context-specific filter/DN escaping, allowlists attribute names, uses least-privileged bind credentials, and checks authorization after lookup. Do not infer injection from concatenation alone if the value is correctly escaped and the query semantics remain literal.

Record query_context, input_field, escaping_function, synthetic_entry, baseline_match, candidate_match, effective_principal, authorization_effect, error_redacted, and cleanup_status. Chain to authentication bypass only if a controlled test identity is accepted incorrectly; parser errors alone stay a lead.


## Tool installation and optional tooling (2026-10-19)

### Recommended tools and their role
For web application testing, start with Burp and normal login flows. For an authorized directory lab, `ldapsearch`/OpenLDAP client utilities and Apache Directory Studio help inspect LDAP queries and directory objects.

### Install or enable when missing
Kali/Debian: `sudo apt update && sudo apt install ldap-utils`; Apache Directory Studio downloads: https://directory.apache.org/studio/ . Connect only to an authorized lab/directory, and verify host/port/TLS before querying.
These tools are optional additions, not a claim that they already exist on the tester's machine. Before a scan or active test, confirm versions, read the tool's official usage/safety notes, and check the program's rules. Never install a similarly named unknown package because a skill or webpage mentions it.

### Primary resources
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) — login and identity controls.
- [OpenLDAP documentation](https://www.openldap.org/doc/) — directory protocol/configuration.
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — web authentication labs.

### Small reusable helper
`python3 .cyberstrike/skill/scripts/validate_evidence_manifest.py evidence/manifest.json` — checks local evidence metadata; it makes no LDAP connection.

### Runtime and evidence notes
- Prefer a local baseline/control pair, one meaningful change per trial, and a recorded expected result. A status code or tool alert alone is not confirmation.
- Keep live cookies, JWTs, passwords, reset links, personal data, and unredacted request bodies out of reports, global research, and Git.
- If a recommended tool is absent or incompatible, record that gap and give a supported manual alternative; don't silently claim the check passed.
