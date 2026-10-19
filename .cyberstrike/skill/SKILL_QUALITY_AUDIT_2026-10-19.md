# CyberStrike Skill Quality Audit — 2026-10-19

## Scope and measured inventory

Repository: https://github.com/nadamohamed14796-byte/cyber-strike  
Target branch: main. Starting commit: 3faead966aa52135166409b99fa561c8f299132a.

The starting recursive Git tree contained 19,641 paths and 7,734 SKILL.md files under .cyberstrike/skill. Of these, 105 were purpose-built local/community skills directly under .cyberstrike/skill/<name>/SKILL.md; these are the editable workflow/specialist layer. The rest are predominantly vendor/reference mirrors and benchmark/test modules (including CIS, NIST, MITRE ATT&CK and OWASP WSTG). This pass adds six new skill files, so the expected post-commit total is 7,740 SKILL.md files and 111 direct local skill directories. Upstream copies are left intact to preserve provenance and avoid silently diverging from their published baselines.

All 105 pre-existing purpose-built skills were reviewed individually by their stated purpose, frontmatter, workflow structure, confirmation/false-positive gates, chain targets, runtime assumptions, and obvious arbitrary hypothesis ceilings. Each received a skill-specific enrichment or a frontmatter safety overlay where its topic is internal post-exploitation rather than public-web bug bounty. SKILL_GUIDE.md was also corrected because it prescribed an arbitrary 20-hypothesis ceiling and required repeated attempts to earn a false-positive verdict; those rules are now evidence-driven.

## Main improvements made

- Expanded the 105 pre-existing custom skill files with topic-specific baselines, request/state differential steps, disconfirming controls, impact evidence, next-skill handoffs, and safer stop/cleanup conditions.
- Removed fixed “maximum 20 distinct hypotheses” and “at most 20 hypotheses per asset” limits from the affected hunt/recon skills. There is no arbitrary hypothesis-count ceiling; actual program rules, permitted rates, availability, authorization, and safety boundaries still apply.
- Added six specialists: API property-level authorization; API resource consumption; file inclusion/path traversal; server-side parameter pollution; unsafe API consumption; and skill-supply-chain auditing.
- Added BUG_BOUNTY_CHAINING_PLAYBOOK.md so header, cache, auth, JS, GraphQL, object/field authorization, business logic, recon, file-handling, information-disclosure, and imported-skill signals route to a next skill only when the triggering evidence actually exists.
- Added a stdlib-only structural validator for frontmatter, directory/name consistency, chain references, duplicate names, and fixed hypothesis caps.
- Added safety overlays at the top of internal post-exploitation skill references. They distinguish internal, explicitly authorized lab work from public-web bug bounty and prohibit automatic use for credential collection, persistence, evasion, lateral movement, or exfiltration on third-party systems.
- Avoided copying upstream prompts or internal command names verbatim. Commands and integrations are treated as available only if the CyberStrike runtime confirms them.

## Coverage gaps addressed

The additions map closely to OWASP API Security Top 10 2023:
- API1 BOLA: existing attack-idor-automation.
- API2 Broken Authentication: existing attack-auth-bypass, attack-ato, attack-session, attack-mfa-bypass, attack-oauth.
- API3 Broken Object Property Level Authorization: new attack-api-property-authorization.
- API4 Unrestricted Resource Consumption: new attack-api-resource-consumption.
- API5 Broken Function Level Authorization: existing attack-bfla.
- API6 Sensitive Business Flows: existing attack-business-logic and attack-race-condition.
- API7 SSRF: existing attack-ssrf.
- API8 Security Misconfiguration: existing cloud/header/framework configuration skills.
- API9 Improper Inventory Management: existing attack-shadow-api plus recon/API inventory workflows.
- API10 Unsafe Consumption of APIs: new attack-unsafe-api-consumption.

Additional gaps addressed with specialist skills for path traversal/file inclusion, server-side parameter pollution, and imported-skill/supply-chain auditing.

## Source synthesis

Research was used to identify coverage and quality practices, then translated to the local CyberStrike naming/runtime conventions rather than copied as upstream implementations.

- Recon Skills (passive/active recon, asset attribution and practical bug-bounty workflow): https://github.com/uphiago/recon-skills
- Claude-BugHunter (hunting taxonomy, differential validation, chaining and reporting): https://github.com/elementalsouls/Claude-BugHunter
- Agentic Bug Hunter / bug bounty workflow references: https://github.com/AmesianX/claude-bughunter
- Superagent Security Skills (skill trust, claimed-purpose-vs-behavior, supply-chain and prompt-injection review): https://github.com/superagent-ai/skills
- UseOSINT Skills (passive-first collection, source provenance, confidence, corroboration): https://github.com/useosint/skills
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/editions/2023/en/0x00-header/
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/cheatsheets/
- PortSwigger API testing: https://portswigger.net/web-security/api-testing

## Validation status and limits

The current staged Git tree preserves every original path and adds the six skill directories plus the playbook, audit and validator files. After the commit, verify the new paths, tree counts, and sample frontmatter/chain links by fetching from main. The local validator is supplied for a checkout-based full scan; it has not been run against the complete 7,740-file catalog in this remote-only pass, so no claim of a full automated content scan is made here.

The current .cyberstrike/skill/index.json contains 129 registry entries and predates many newer custom specialist skills. It is not regenerated or marked official here because the new local skills are not signed. The local skill loader recursively discovers SKILL.md files; the publishing script packages direct skill folders, so regenerating the distributable registry should be an intentional separate action with review of which unverified skills are meant to be published.


## Updated inventory and validation status — 2026-10-19

The earlier path/skill counts above are a historical baseline from the starting commit, not the current tree. A fresh recursive Git tree inspection later on 2026-10-19 counted 19,683 paths, 7,746 `SKILL.md` files under `.cyberstrike/skill`, and 117 direct local skill directories. This count verifies inventory only; it does not establish that every skill has been reviewed or can be invoked successfully. The checked-in `index.json` remains a separate curated/publishing registry (129 entries in the inspected snapshot) and should not be regenerated blindly to mark unsigned skills official. Runtime lookup uses the recursively discovered catalog; registry publishing must preserve verification status and intended package contents.
