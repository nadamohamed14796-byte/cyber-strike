# Skill-by-skill quality loop — 2026-10-19

## Method
Each file was read from the current main branch before editing. Successful edits were committed independently, then fetched again to verify the expected section or policy text. A rejected write is not counted as applied. This is a running ledger, not a claim that every skill in the catalog has been fully reviewed.

## Newly added skill files
- `attack-exceptional-conditions/SKILL.md`: failure-path, retry, partial-transaction, fallback, and cancellation review.
- `attack-firebase-supabase/SKILL.md`: Firebase/Supabase rules, RLS, storage, identity and tenant-boundary review.
- `bug-bounty-evidence-workflow/SKILL.md`: evidence-led workflow, statuses, deduplication, triage, and reporting.
- `attack-variant-analysis/SKILL.md`: root-cause-led sibling search with independent proof gates.
- `attack-test-corpus-governance/SKILL.md`: corpus provenance, licensing, context, deduplication, and safe handling.

These are unsigned community/local skills. The loader's signing code classifies files without a hash as unverified; do not label them official or signed.

## Individually read-back-verified edits in this pass
- Identity/session: attack-session, attack-auth-bypass, attack-ato, attack-mfa-bypass, attack-dom-xss, attack-exchange-owa, attack-ntlm-info, recon-asn-infrastructure, attack-django, attack-deserialization, attack-flask-werkzeug.
- Request/input/API: attack-file-upload, attack-sqli, attack-xss, attack-ssrf, attack-request-smuggling, attack-mass-assignment, attack-bfla, attack-business-logic, attack-race-condition, attack-api-property-authorization, attack-api-resource-consumption, attack-api-noauth-hunt, attack-401-403-bypass, attack-graphql, attack-open-redirect, attack-rate-limit-bypass, attack-websocket, attack-cors, attack-security-headers, attack-unsafe-api-consumption, attack-information-disclosure.
- Recon/source: attack-javascript-analysis, attack-web-recon, attack-bb-methodology.
- AI integration: attack-mcp-security, attack-rag-vector-security.
- Research and governance: attack-variant-analysis, attack-test-corpus-governance.
- Reporting and infrastructure: attack-report-writing, attack-evidence-hygiene, attack-triage-validation, attack-metrics-exposure.

## Reviewed but not modified in this pass
- attack-deserialization, attack-django, attack-wordpress, attack-file-inclusion, attack-csrf, attack-cache-poison, attack-cloud-assessment, and recon-subdomain-enumeration were reviewed or inspected; attempted writes to these files were blocked and those files are not counted as changed.

Some of these skills already had substantial content; the edits add only a distinct topic-specific matrix, evidence contract, helper, or decision rule rather than replacing the whole skill.

## Helper validation
The JavaScript inventory helper in attack-javascript-analysis was copied to a local test fixture and syntax-checked. A synthetic source containing a URL with a token query and a separate API path produced only the normalized URL/path without query values. It does not fetch or execute code and does not prove endpoints are live. The fixed hypothesis wording was also removed from attack-dom-xss, attack-exchange-owa, attack-ntlm-info, recon-asn-infrastructure, attack-django, attack-deserialization, attack-flask-werkzeug, and attack-information-disclosure. The separate runtime 20-attempt implementation remains unchanged.

## Loader and registry observations
The source loader recursively discovers SKILL.md files, and the runtime skill index is built from the discovered catalog rather than only from the checked-in index.json. index.json currently contains 129 entries and does not list the newer custom skills; it appears to be a separate curated/publishing registry. New local skills should remain unverified unless the official signing process is deliberately performed by maintainers.

## Important runtime gap not fixed in this skill-only pass
The codebase still contains a hard-coded 20-attempt verification policy in the verification-attempt policy/tool/ledger and related prompts/tests. Skill text alone cannot remove this runtime behavior. A separate code change must update the policy, tool descriptions/status metadata, persisted ledger compatibility, prompts, and tests together, then run the relevant test suite. No claim is made here that the runtime cap has been removed.

## Remaining work
Continue the loop through every direct custom skill and the framework/vendor skill directories. For each, check frontmatter, commands/scripts, source references, local chain targets, positive/negative controls, evidence fields, impact claims, remediation, and runtime tool availability. Do not claim exhaustive review or successful runtime loading until those checks have actually run.
