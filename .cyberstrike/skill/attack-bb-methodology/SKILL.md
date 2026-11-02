---
name: attack-bb-methodology
description: "Plan and run evidence-led bug bounty work from authorized scope through focused hypotheses, validation handoff, triage, and reporting"
category: "methodology"
version: "1.1.0"
author: "CyberStrike contributors; consolidated from CyberStrike evidence-workflow guidance"
tags: [bug-bounty, workflow, prioritization, evidence, hypothesis, chaining, deduplication, scope, triage, reporting]
tech_stack: [web, api, infrastructure]
prerequisites:
  - "Written authorization and defined engagement type"
  - "Program scope, exclusions, and testing policy"
chains_with:
  - recon-master
  - attack-idor-automation
  - attack-finding-correlation
  - attack-triage-validation
  - attack-evidence-hygiene
  - attack-report-writing
  - skill-supply-chain-audit
sources:
  - "https://github.com/elementalsouls/Claude-BugHunter/blob/main/skills/bb-methodology/SKILL.md"
  - "https://github.com/uphiago/recon-skills"
  - "https://owasp.org/www-project-web-security-testing-guide/"
  - "https://owasp.org/www-project-api-security/"
---

# Bug Bounty Methodology

## 1. Purpose and responsibility boundary

Decide what to investigate, why it matters, when to change direction, and what evidence is required before describing behavior as a vulnerability. The goal is reproducible security impact within the authorized engagement—not the highest request, endpoint, or finding count.

This is the canonical bug-bounty methodology and evidence lifecycle. It combines intake, inventory handoff, hypothesis planning, test recording, deduplication, chaining, closeout, and learning. It does **not** replace:
- The shared Target Workflow Contract for authorization, workspace ownership, checkpoint/resume, execution order, retries, and closeout.
- `recon-master` for reconnaissance and asset discovery procedures.
- `attack-javascript-analysis` for JavaScript acquisition and code-level analysis.
- `attack-finding-correlation` for canonical evidence aggregation and graph updates.
- `attack-triage-validation` for the required finding-validation gate and verdict discipline.
- `attack-evidence-hygiene` and `attack-report-writing` for redaction, evidence review, and report construction.

Load only the relevant specialist skills when evidence or a real decision requires them. Do not run every skill listed in `chains_with` automatically.

## 2. Confirm engagement mode and working context

Record the applicable engagement mode:
- **Bug bounty / VDP:** follow the program's scope, safe-harbor, test restrictions, and reporting policy.
- **Authorized penetration test:** follow the signed statement of work and rules of engagement.
- **Red-team assessment:** stay within the agreed objectives, assets, and operational boundaries.
- **Lab / CTF:** stay within the permitted lab environment.

Use the persisted scope and workspace from the shared workflow. Do not create a second scope manifest, workspace, or phase ledger here. Public reachability, a related hostname, a certificate entry, a source-code reference, or a historical report is not authorization.

For each focused workstream, make the objective concrete:
1. Target, canonical endpoint/operation, and persisted scope basis.
2. Feature, actor, role, object, tenant, or trust boundary under review.
3. Security property expected from the application.
4. Current observation and its provenance.
5. Hypothesis and evidence needed to confirm or refute it.
6. Permitted test class, required identities/fixtures, and stop condition.

Keep one or two closely related security properties in focus for a test pass. Broaden only when a new observation justifies a distinct branch.

## 3. Evidence-led lifecycle

### A. Establish the evidence base

Use `recon-master` for scope-aware asset, host, application, and URL discovery. Use `attack-javascript-analysis` for collected JavaScript/source maps and the canonical endpoint model. Merge browser traffic, forms, API contracts, static source candidates, and other observations into the existing target inventories.

Do not create parallel endpoint roots for each source or method. Endpoint identity is normalized origin + route template + API version; keep HTTP methods as separate operations under that endpoint. Preserve operation-specific parameters, content type, authentication context, source provenance, confidence, and observed-versus-inferred status. A method seen only in captured traffic is traffic evidence, not proof that JavaScript declared it.

For every observation, separate:
- **Discovery:** where the candidate came from.
- **Attribution/scope:** why the asset belongs to the authorized engagement.
- **Reachability:** whether the relevant route or code path was actually reached.
- **Security interpretation:** what control or invariant may be violated.
- **Validation:** whether the relevant behavior and impact were independently demonstrated.

A scanner alert, version string, HTTP 200, route name, source-map string, or unusual response is a lead—not a confirmed finding.

### B. Create a testable hypothesis

Every candidate hypothesis must state:
- The observed parent signal and its source/evidence reference.
- The expected security rule or invariant.
- The actor and prerequisites (anonymous/authenticated, role, tenant, session, ownership, feature state).
- The exact endpoint/operation, object, field, or workflow step.
- The single boundary or variable to compare.
- A safe test fixture and baseline.
- The expected secure result and the result that would support the hypothesis.
- A relevant negative control or competing explanation.
- The minimum evidence required to establish impact.
- A bounded next step, cleanup requirement, and stop condition.
- The specialist skill that matches the observed signal, if any.

Prefer one discriminating experiment over a large set of equivalent payloads. A new endpoint or neighboring route should be mapped first; do not infer its security behavior from a sibling.

### C. Request targeted testing only when permitted

Reconnaissance and passive collection do not automatically authorize vulnerability testing. Execute a test only when the user explicitly requested testing and the persisted engagement policy and runtime controls permit that specific action.

For an authorized test:
1. Prefer a previously captured, in-scope baseline request.
2. Use tester-owned accounts, controlled roles, and synthetic or disposable objects.
3. Change one meaningful variable at a time (for example principal, object, tenant, method, field, content type, origin, or workflow state).
4. Compare against a relevant negative control and the expected policy.
5. Record the actual request/response and, when relevant, authoritative application state.
6. Stop before messages are sent, money is moved, records are deleted, access is changed, real users are affected, or a production service becomes unstable unless that exact effect is explicitly authorized and safely controlled.
7. Restore test state, revoke temporary sessions/tokens, and record cleanup.

A failed request, timeout, tool error, blocked credential, missing account, or unavailable fixture is not a passed security test.

### D. Maintain the execution and evidence ledger

Persist each meaningful attempt against its canonical target, endpoint/operation, hypothesis, and test context. Use the runtime's existing records and status vocabulary where available; do not create a competing global ledger.

Useful per-attempt dispositions are:
- **CANDIDATE:** an observation supports further investigation but the control failure or impact is not proved.
- **CONFIRMED:** the relevant path, failed control, and concrete impact have been reproducibly demonstrated and passed the validation lifecycle.
- **REFUTED:** a relevant test or effective control contradicts this specific hypothesis.
- **INCONCLUSIVE:** evidence is ambiguous, noisy, or insufficient to decide.
- **BLOCKED:** a required permission, identity, fixture, tool, or other prerequisite is unavailable.
- **NOT-RUN:** deliberately deferred or not executed, including recon-only work.
- **OUT-OF-SCOPE:** the asset or action is not authorized.

A **PASS-SECURE** observation is appropriate only when the test actually exercised the intended security boundary and the result supports the expected secure behavior. Do not convert BLOCKED, NOT-RUN, tool failure, or missing evidence into PASS-SECURE or a false positive.

Each evidence record should link:
- Canonical asset, endpoint ID, method/operation, and scope decision.
- Hypothesis ID/fingerprint and discovery source.
- Request/response artifact IDs or immutable paths, timestamp, and tool/version when applicable.
- Test identity, role, tenant, object, and relevant application state.
- Baseline, changed variable, negative control, expected policy, and observed result.
- Impact demonstrated (or exact impact still unproved), confidence, and disposition.
- Redaction/cleanup status, blocker, resume condition, and next action.

Keep raw credentials, complete cookies, reset links, authorization headers, and unrelated personal data out of ordinary notes, graph summaries, commits, and reports.

### E. Correlate and deduplicate

Use `attack-finding-correlation` to normalize observations, enrich canonical endpoint/evidence records, update the evidence graph, and calculate signal-driven handoffs. Keep the graph and authoritative target/finding records as the source of evidence; this methodology is not a second graph implementation.

Deduplicate by root cause + affected security boundary + endpoint/operation + impact—not title similarity or URL alone. Several observations can support one root cause; one endpoint can contain several independent authorization or business-logic flaws. Preserve different roles, tenants, objects, states, methods, and controls as separate evidence rows when they change the security property.

Do not suppress a materially different branch because a related route, parameter, or test was previously rejected. Conversely, do not create duplicate findings from repeated captures or cosmetic request variations.

### F. Chain only from observed signals

A chain must identify the observed parent signal, child hypothesis, exact trust boundary, actor/prerequisites, controlled fixture, independent proof required for the next link, and combined effect. A child skill or finding never inherits the parent's verdict.

Use `BUG_BOUNTY_CHAINING_PLAYBOOK.md` as the canonical signal-to-skill routing reference. It owns the detailed signal matrix, hop lifecycle, request-comparison rules, false-positive memory, and cleanup guidance; do not copy a second routing matrix here.

Execute the next specialist only when its trigger is actually observed and the target is authorized for that test. A chain is confirmed only when every required link and the reported end state are independently reproducible. If a downstream link is unverified, report only the confirmed primitive and label the remainder as a hypothesis. Do not raise severity based on a theoretical chain.

### G. Validate, sanitize, and report

Before a candidate is presented as a finding:
1. Run `attack-triage-validation` and its required `validate_finding` evidence gate. Missing evidence remains unknown/inconclusive; do not replace the required gate with this methodology's summary.
2. Confirm that the verdict matches the direct evidence and that alternative benign explanations have been assessed.
3. Use `attack-evidence-hygiene` to review redaction, integrity, provenance, and minimum necessary disclosure.
4. Use `attack-report-writing` and the applicable program-specific reporting skill to prepare the report.
5. Ensure every material claim maps to a request/response, state observation, source trace, or other reproducible evidence reference.
6. Include a relevant negative control, role/account context, expected versus actual behavior, actual impact, limitations, and remediation.
7. Check program duplicate rules, severity taxonomy, disclosure requirements, and whether the issue is already known.

Never report a candidate as confirmed merely because the workflow reached the reporting stage.

## 4. Prioritization and adaptive branch selection

Rank work by:
- The significance of the trust boundary and protected asset/action.
- Whether the relevant path is reachable and first-party/in-scope.
- Strength and independence of the evidence.
- Realistic impact and attacker prerequisites.
- Whether one low-impact experiment can distinguish competing explanations.
- Cost, service risk, and program constraints.

Do not prioritize solely by CVE age, product name, scanner count, number of endpoints, or an unverified severity label.

At the end of a focused pass, record the most useful observation, the assumption it changed, and one next experiment that distinguishes competing explanations. When evidence is interesting, cluster related routes by controller, API version, workflow, or trust boundary. Test the same security property on sibling routes only with their own baseline and control; never copy an exploit blindly.

Use the following branch prompts to guide—but not replace—specialist selection:

| Observation | Competing explanations | Useful discriminating review |
|---|---|---|
| HTTP 200 on a protected-looking route | Public route, login shell, cache, actual protected data | Compare anonymous and permitted authenticated baselines; inspect a synthetic marker |
| Input appears in a response | Safe encoding, inert reflection, executable context | Identify the exact output context and controlled browser behavior |
| Secret-like string appears in JavaScript | Public client identifier, dummy value, secret candidate, dead code | Preserve only type/location/fingerprint; never use the value |
| URL parameter is accepted | Browser redirect, server-side fetch, ignored field | Correlate navigation or a controlled callback to identify the actor |
| Header is absent | Hardening gap, equivalent control, irrelevant response type | Inspect effective behavior on the affected route |
| Two requests both succeed | Idempotent behavior, duplicate response, duplicate side effect | Compare authoritative state with a sequential control |

For full signal-to-skill routes, use `BUG_BOUNTY_CHAINING_PLAYBOOK.md`.

## 5. Coverage, learning, and closeout

Maintain separate counts from persisted records for assets discovered, endpoints normalized, hypotheses created, attempts made, distinct findings confirmed, hypotheses refuted, blocked cases, inconclusive cases, and not-run/out-of-scope items. Do not estimate counts from chat prose.

A workstream can close with no findings when its relevant evidence supports that outcome. It cannot be described as fully covered while sources, files, roles, routes, or required tests remain inaccessible, unsupported, blocked, or unprocessed. Report gaps explicitly.

Before ending a session, report:
- Completed work and canonical artifact references.
- New/changed observations and what changed in the evidence graph.
- Confirmed, refuted, candidate, inconclusive, blocked, not-run, and out-of-scope dispositions.
- Actual source/tool coverage and meaningful failures or skipped branches.
- Cleanup performed or still required.
- Remaining uncertainty and one concrete next action.

Preserve useful negative results with the exact identity, object, method, and state that were exercised. Reopen a rejected hypothesis only when the asset, role, object, state, version, source, or relevant prerequisite materially changes.

Use public reports and research as sources of hypotheses and reusable preconditions, not as proof about the current target. Preserve source attribution and distinguish the researcher's narrative from independently verified technical facts. Never replay historical payloads blindly against a live target.

## Shared tool catalog

Use the single shared `TOOLING_CATALOG.md` reference exposed by `community-tool-selection` for candidate tools, helper scripts, official project resources, and availability guidance. Do not duplicate its tool inventory here. For each selected executable, verify it with `command -v <tool>` and its documented version/help flags; install only when the evidence gap genuinely requires it, using official project instructions. Tool availability never grants target authorization.

- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- HackerOne quality reports: https://docs.hackerone.com/en/articles/8475116-quality-reports

## 6. Runtime and tool boundaries

Tool selection is dynamic. Use the shared `community-tool-selection` catalog and actual registered tool schemas for available capabilities. Examples in upstream material do not prove that a command, helper, API, or runtime tool exists. Verify only candidates relevant to the current evidence gap; do not install or preflight the entire catalog, and do not copy a generic tool inventory into this skill.

This skill defines methodology and evidence expectations. It does not claim that any particular runtime command exists, authorize a test, bypass scope enforcement, or create a second target workspace, checkpoint, evidence graph, or finding ledger.

## References

- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP API Security Top 10: https://owasp.org/www-project-api-security/
- HackerOne quality reports: https://docs.hackerone.com/en/articles/8475116-quality-reports
- Bugcrowd Vulnerability Rating Taxonomy: https://bugcrowd.com/vulnerability-rating-taxonomy/
- CyberStrike signal-to-skill and chain lifecycle reference: `BUG_BOUNTY_CHAINING_PLAYBOOK.md`
- Merged CyberStrike source: Evidence-Led Bug Bounty Workflow (now consolidated into this skill)
