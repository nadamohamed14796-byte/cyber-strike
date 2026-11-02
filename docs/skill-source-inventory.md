# Canonical Skill Consolidation Inventory

## Goal

Consolidate the original CyberStrike skills with relevant material from:
- https://github.com/elementalsouls/Claude-BugHunter
- https://github.com/uphiago/recon-skills

**Canonical skill rule:** prefer existing CyberStrike skill paths and names and avoid parallel duplicates. Reconnaissance is the explicit umbrella exception: `recon-master` is the single canonical recon entry point, and its specialist procedures live as chapters rather than separately registered skills. For other topics, map each upstream skill to the closest existing CyberStrike or OWASP WSTG/standards skill; if no safe semantic match exists, document it as unmapped.

## Source inventory

- Claude-BugHunter: 83 upstream skill files.
- recon-skills: 146 upstream skill files.
- Source total: 229 files, before deduplication and semantic mapping.
- CyberStrike registry on `main`: 129 registered skills.
- CyberStrike has 39 root skill directories plus nested standards/reference skill trees.
- No claim is made that all 229 upstream source skills have been merged. Consolidation is staged and must be tracked by source path.

## Consolidation completed in this branch

Existing CyberStrike canonical files expanded (no new parallel skill names):
- `.cyberstrike/skill/attack-idor-automation/SKILL.md`
- `.cyberstrike/skill/attack-cors/SKILL.md`
- `.cyberstrike/skill/attack-graphql/SKILL.md`
- `.cyberstrike/skill/attack-jwt/SKILL.md`
- `.cyberstrike/skill/attack-open-redirect/SKILL.md`
- `.cyberstrike/skill/attack-cache-poison/SKILL.md`
- `.cyberstrike/skill/attack-host-header/SKILL.md`
- `.cyberstrike/skill/attack-prototype-pollution/SKILL.md`
- `.cyberstrike/skill/attack-race-condition/SKILL.md`
- `.cyberstrike/skill/attack-rate-limit-bypass/SKILL.md`
- `.cyberstrike/skill/attack-request-smuggling/SKILL.md`
- `.cyberstrike/skill/attack-ssrf/SKILL.md`
- `.cyberstrike/skill/attack-ssti/SKILL.md`
- `.cyberstrike/skill/attack-subdomain-takeover/SKILL.md`
- `.cyberstrike/skill/attack-websocket/SKILL.md`
- `.cyberstrike/skill/attack-xxe/SKILL.md`
- `.cyberstrike/skill/recon-master/SKILL.md`
- `.cyberstrike/skill/cloud-assessment/SKILL.md`
- `.cyberstrike/skill/ci-assessment/SKILL.md`
- `.cyberstrike/skill/cicd-attacks/SKILL.md`
- `.cyberstrike/skill/llm-security/SKILL.md`
- `.cyberstrike/skill/WEB/OWASP_WSTG_4.2/wstg-inpv-01/SKILL.md` — reflected XSS
- `.cyberstrike/skill/WEB/OWASP_WSTG_4.2/wstg-inpv-02/SKILL.md` — stored XSS
- `.cyberstrike/skill/WEB/OWASP_WSTG_4.2/wstg-inpv-05/SKILL.md` — SQL injection overview
- `.cyberstrike/skill/WEB/OWASP_WSTG_4.2/wstg-inpv-11.1/SKILL.md` — file inclusion
- `.cyberstrike/skill/WEB/OWASP_WSTG_4.2/wstg-clnt-09/SKILL.md` — clickjacking
- `.cyberstrike/skill/WEB/OWASP_WSTG_4.2/wstg-apit-00/SKILL.md` — API testing overview
- `.cyberstrike/skill/WEB/OWASP_WSTG_4.2/wstg-busl-01/SKILL.md` — business logic validation
- `.cyberstrike/skill/WEB/OWASP_WSTG_4.2/wstg-athn-09/SKILL.md` — password change/reset

This is the first canonical consolidation batch: 29 existing skill files expanded. It is not full completion of the two upstream libraries.

## Mapping rules

1. Compare source skill purpose and procedure with the existing CyberStrike file, not just its name.
2. Merge complementary techniques into the canonical file while preserving CyberStrike frontmatter, name, and runtime assumptions.
3. Use existing nested OWASP WSTG skills for classes already covered there (for example, authentication, authorization, business logic, client-side testing, configuration, input validation, and API testing).
4. Use existing platform/assessment skills for cloud, CI/CD, Kubernetes, Active Directory, mobile, and operating-system content.
5. Fold cross-cutting workflows (recon, evidence hygiene, triage, attack chains, reporting) into existing canonical methodology/assessment skills and relevant cross-reference sections.
6. Do not copy source commands blindly. Verify each referenced command/tool against the CyberStrike tool registry and current runtime.
7. Preserve upstream attribution and applicable licenses; do not import target-specific credentials, secrets, or engagement artifacts.
8. Each source file needs a traceable status: `merged`, `partially merged`, `duplicate`, `not applicable`, or `unmapped`. A link in frontmatter alone does not prove content was merged.
9. A skill is not runtime-integrated until loader/registry selection, schema, tool availability, and tests are verified.

## Existing canonical destinations by domain

| Source topic | Canonical CyberStrike destination(s) |
|---|---|
| IDOR/BOLA, object/tenant authorization | `attack-idor-automation`; existing WSTG authorization/API testing skills |
| CORS, GraphQL, JWT, redirects, cache/host header, prototype pollution, race conditions, rate limits, request smuggling, SSRF, SSTI, subdomain takeover, WebSocket, XXE | Matching existing `attack-*` skill with the same CyberStrike name |
| Recon playbooks, subdomains, ports, web/API enumeration, JavaScript endpoints, source leaks, origin discovery | `recon-master`; existing WSTG reconnaissance/configuration skills |
| API no-auth, API misconfiguration, mass assignment, GraphQL and gRPC testing | Existing WSTG API skills plus `attack-graphql` and `attack-idor-automation` where semantically appropriate |
| Authentication, ATO, password reset, MFA, OAuth/SAML/session | Existing WSTG authentication/authorization/session skills and `attack-jwt` where relevant |
| Business logic and workflow integrity | Existing WSTG business-logic skills; `attack-race-condition` only for concurrency hypotheses |
| Cloud IAM, cloud configuration, storage, network, federation | `cloud-assessment` and provider-specific existing skills |
| CI/CD, build pipeline, dependencies, runners, artifacts | `ci-assessment` and `cicd-attacks` |
| LLM prompt injection, RAG, tool-use authorization, agentic actions | `llm-security` |
| Kubernetes, Docker, AD, Kerberos, M365/Entra, Okta, SharePoint, VPN, mobile, OS post-exploitation | Existing platform-specific assessment/technique trees; no new root skill by default |
| Reporting, evidence, triage, attack chains | Existing methodology and reporting structures plus relevant skill output contracts |

## Verification status

- Canonical names preserved: yes for the listed consolidation batch.
- Parallel draft skill files removed from this branch: yes.
- Registry restored to the original `main` registry: yes.
- Full source-by-source 229-file semantic audit: pending.
- Referenced tool/script existence checks: pending.
- Runtime trigger/loader and end-to-end tests: pending.

## Source licenses and attribution

- Claude-BugHunter: review its repository's content-specific license/notice before redistributing source-derived text; retain required attribution.
- recon-skills: retain applicable MIT copyright/license notice for reused material.
- Prefer original synthesis over verbatim copying and keep source URLs in the canonical skill's `sources` field.


## Workflow consolidation — 2026-11-02

The following semantic overlaps have been consolidated into canonical responsibilities. This is a workflow cleanup, not a merge of unrelated specialist skills.

| Previous skill/workflow | Canonical destination | Result |
|---|---|---|
| `attack-web-recon` | `.cyberstrike/skill/recon-master/SKILL.md` | The seven-step web recon pipeline, iterative source expansion, validation controls, source coverage, endpoint normalization, and recon handoff are represented by the single recon entry point and its conditional chapters. The duplicate skill file and its phase pin are retired. |
| `bug-bounty-evidence-workflow` | `.cyberstrike/skill/attack-bb-methodology/SKILL.md` | Intake, inventory handoff, hypothesis planning, execution/evidence records, status discipline, deduplication, chaining, reporting, learning, and closeout are consolidated into the canonical methodology. The duplicate skill file and index entry are retired; the consolidated methodology is now the canonical entry in the curated registry. |
| Broad workflow and workspace instructions | `.cyberstrike/skill/target-workspace-workflow/SKILL.md` + `packages/cyberstrike/src/agent/prompt/methodology/target-workflow.txt` | The runtime prompt retains global orchestration. The skill is narrowed to workspace identity, canonical paths, artifact persistence, state-ledger ownership, and target isolation. |

The following remain separate by design because they perform different work:
- `recon-master`: reconnaissance execution guidance and conditional asset-discovery procedures.
- `attack-javascript-analysis`: JavaScript/source-map acquisition, local analysis, and source-linked endpoint candidates.
- `attack-finding-correlation`: normalized evidence aggregation, graph updates, and evidence-driven skill handoffs.
- `attack-triage-validation`: the required finding validation gate, counterevidence, verdict, and severity controls.
- `attack-evidence-hygiene` and `attack-report-writing`: evidence sanitization/review and final report construction.

Routing and regression coverage were updated so active reconnaissance loads the canonical recon skill without a parallel web-recon skill, and reporting discovers the canonical bug-bounty methodology rather than the retired evidence-workflow skill. Runtime test execution remains to be verified in the package environment.
