# Canonical Skill Library Consolidation

## Objective

Merge the useful methods from CyberStrike's existing skills and the two upstream libraries into **existing CyberStrike skill files**:
- https://github.com/elementalsouls/Claude-BugHunter
- https://github.com/uphiago/recon-skills

The expected result is one comprehensive, CyberStrike-native file per existing canonical skill name—not parallel files named after upstream skills.

## Non-negotiable rules

1. Preserve the existing CyberStrike skill name/path and frontmatter contract.
2. Compare all three inputs: current CyberStrike file, relevant Claude-BugHunter skill(s), and relevant recon-skills skill(s).
3. Merge complementary material into the existing canonical destination. Do not duplicate a topic in a newly invented root skill.
4. When multiple upstream files cover one topic, synthesize them into one coherent procedure and retain all relevant source links.
5. Where a topic is already represented by a nested OWASP WSTG or standards skill, merge into that existing destination rather than creating a parallel `attack-*` file.
6. If no existing skill semantically fits, record the source as `unmapped` and explain the gap. Do not create a new skill unless the owner explicitly changes this canonical-only rule.
7. Remove unverified commands and dangerous production examples. Any CLI/tool reference must be verified against CyberStrike's real registry and runtime before being presented as executable.
8. Include scope, authorization, safe preconditions, baseline, bounded procedure, impact validation, false positives, evidence requirements, remediation, cleanup, output contract, and related-skill links where relevant.
9. Preserve license notices and attribution. Do not copy secrets, tokens, target-specific artifacts, or private program data.
10. Distinguish content completion from runtime integration. A file existing in the repository or registry does not prove the agent loads it.

## Source inventory

- Claude-BugHunter: 83 skills.
- recon-skills: 146 skills.
- Total before semantic deduplication: 229 source files.
- CyberStrike registry on `main`: 129 skills.
- CyberStrike has 39 root skill directories and additional nested WSTG/standards/ATT&CK trees.

## Canonical files consolidated in this first batch

- IDOR/BOLA: `attack-idor-automation`
- CORS: `attack-cors`
- GraphQL: `attack-graphql`
- JWT: `attack-jwt`
- Open redirect: `attack-open-redirect`
- Cache poisoning: `attack-cache-poison`
- Host header: `attack-host-header`
- Prototype pollution: `attack-prototype-pollution`
- Race condition: `attack-race-condition`
- Rate limits: `attack-rate-limit-bypass`
- Request smuggling: `attack-request-smuggling`
- SSRF: `attack-ssrf`
- SSTI: `attack-ssti`
- Subdomain takeover: `attack-subdomain-takeover`
- WebSocket: `attack-websocket`
- XXE: `attack-xxe`
- Recon: `recon-methodology`
- Cloud assessment: `cloud-assessment`
- CI/CD review: `ci-assessment` and `cicd-attacks`
- LLM application security: `llm-security`
- Existing WSTG targets: `wstg-inpv-01` (reflected XSS), `wstg-inpv-02` (stored XSS), `wstg-inpv-05` (SQLi), `wstg-inpv-11.1` (LFI/RFI), `wstg-clnt-09` (clickjacking), `wstg-apit-00` (API assessment overview), `wstg-busl-01` (business logic), and `wstg-athn-09` (password reset).

These are the first consolidation batch: 29 existing CyberStrike skill files expanded. The two upstream catalogs have **not** yet been fully audited and merged source-by-source.

## Remaining work

1. Build a source-path → canonical-path mapping for all 229 upstream files.
2. Review authentication/SSO, business logic, API, CMS, framework, cloud, container, mobile, enterprise identity, OSINT, and platform-specific sources against existing WSTG/ATT&CK/platform skills.
3. Merge source material into existing nested WSTG/standards skills where appropriate.
4. Mark each upstream source as merged, partially merged, duplicate, not applicable, or unmapped, with evidence.
5. Verify all references to tools/scripts, frontmatter fields, cross-links, registry entries, and loader triggers.
6. Add structural tests and runtime tests where the repository provides a test harness.
7. Report exact coverage and unresolved gaps; do not claim complete consolidation until all source files have a terminal status.

## Acceptance criteria

- No new parallel root skills were introduced by this consolidation.
- Canonical CyberStrike names remain unchanged.
- Every upstream source file has a traceable mapping/status.
- No unverified tool command is represented as confirmed executable.
- Related-skill links resolve to existing paths.
- All evidence and test examples are safe for the authorized context.
- Loader, registry, and end-to-end runtime behavior are verified separately from documentation quality.


## Additional methodology, validation, evidence, and reporting batch

A second, reviewable batch adds CyberStrike-native drafts for:
- `attack-bb-methodology`
- `attack-web-recon`
- `attack-triage-validation`
- `attack-evidence-hygiene`
- `attack-report-writing`

These are supplementary skills; the canonical IDOR/BOLA file remains the newer `main` version, including its runtime verification-ledger discipline and bounded distinct-attempt policy. The new drafts do not by themselves prove dynamic selection, tool execution, or end-to-end runtime integration.

Before declaring the library fully consolidated, verify all prerequisite and `chains_with` references against loaded skill paths, confirm each command against the real tool registry, test relevant trigger/routing behavior, and finish the source-path-to-canonical-path inventory described above.
