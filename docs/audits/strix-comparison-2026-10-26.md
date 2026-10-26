# Strix vs CyberStrike: architecture and agent-quality comparison

**Review date:** 2026-10-26  
**Repositories reviewed:** [usestrix/strix](https://github.com/usestrix/strix) and [nadamohamed14796-byte/cyber-strike](https://github.com/nadamohamed14796-byte/cyber-strike)  
**Purpose:** transfer useful agent-quality practices without duplicating CyberStrike systems, weakening scope enforcement, or adding fixed recon caps.

## Executive summary

CyberStrike does not need a wholesale redesign or a copy of Strix's Python architecture. On the current `main` tree, CyberStrike already has a substantially broader skill catalog, a richer searchable skill runtime, signature-aware skill acquisition, phase-aware skill pinning, persistent recon checkpoints, target-local canonical artifacts, and a dedicated resumable JavaScript collection/correlation path. Those are strengths to preserve.

The clearest improvement identified in the reviewed Strix methodology is the **explicit, always-on counterevidence and severity-calibration contract**. CyberStrike's existing triage skill already covers reproducibility, impact, false positives, and confidence versus severity, but its general shared methodology did not make the exact closure standard equally explicit. This review adds those rules both to the shared methodology prompt and to the specialist triage skill, then adds a regression test.

## Repository-level comparison

Tree counts are approximate inventory signals, not quality scores: the projects use different languages, packaging conventions, and skill formats.

| Area | Strix | CyberStrike | Decision |
| --- | --- | --- | --- |
| Main architecture | Python package; Jinja system prompt; root and specialist agents | TypeScript/Bun monorepo; agent prompts, tools, methodology state, target workspace | Keep each project's native architecture. Do not port Strix's implementation wholesale. |
| Skill content | Compact set of focused internal skills plus user-facing `SKILL.md` integrations | Around 7,750 paths matching `.cyberstrike/skill/**/SKILL.md`, including large imported compliance/framework collections | Preserve the broader corpus. Improve quality gates and loading behavior rather than adding duplicate general skills. |
| Skill runtime | Prompt renderer selects a deduplicated ordered set; scan mode, browser/Python, counterevidence and severity guidance are common additions; `load_skill` can load up to five names | Recursive catalog discovery; lazy load/unload/outline/search/list; phase ranking and required-skill pinning; aliases, technologies, CWE and chains; signature-aware remote skill acquisition and path/archive validation | CyberStrike already has equal or broader core mechanics. Keep them and test their contracts. |
| Recon orchestration | Specialized agents coordinated by a root agent; coverage tool records test outcomes | Canonical `/recon` prompt, persistent `recon_checkpoint`, resumable canonical workspace, phase artifacts, adaptive tool choice, provenance and final reconciliation | Preserve CyberStrike's recon flow. Do not copy a fixed phase-to-tool allowlist or impose arbitrary caps. |
| JavaScript recon | Tool/browser and specialist skills support application testing | Dedicated ingest/correlation tools and analysis code: accepts URLs from multiple sources, fetches actual content under persisted scope checks, handles redirects, hashes/deduplicates assets, tracks source-map status and resumes partial work | CyberStrike is already more purpose-built for the requested JS-first recon workflow. Avoid a parallel JS collector or manifest. |
| Candidate closure | Explicit `counterevidence` skill defines confirmed, ruled-out and unresolved proof-gap states | Existing `attack-triage-validation`, `validate_finding`, false-positive memory and evidence-hygiene guidance cover much of the lifecycle, but general methodology was less explicit about when a candidate may be ruled out | Adopt the sharper closure test, mapped to CyberStrike's existing lifecycle rather than adding a second ledger. |
| Severity | Dedicated `severity_calibration` skill requires reachability and counterevidence before rating | Triage guidance distinguishes confidence from severity, but a concise, always-on rubric was missing from shared methodology | Add a short shared rule plus a detailed rubric in the existing triage skill. |
| White-box review | Dedicated source-aware discovery and fix-verification guidance | JavaScript skill contains frontend-to-server tracing; general code review is handled through the existing methodology and specialist skills | Keep as a possible future, task-specific enhancement; not necessary for the primary recon/bug-bounty workflow in this change. |
| Test style | Dedicated tests cover prompt contracts, coverage state, skill directories, and agent coordination | Existing tests already check phase-critical skill availability, ranking, loader safety, JavaScript analysis, checkpoints and workspace persistence | Add a focused regression assertion to the existing phase-skill test suite; do not introduce a new test framework. |

## Strix practices examined

The review inspected the Strix repository tree and representative implementation files:

- `strix/agents/prompt.py` and `strix/agents/prompts/system_prompt.jinja`: ordered and deduplicated prompt assembly, shared versus task-specific skill content, and explicit root-agent coordination behavior.
- `strix/skills/analysis/counterevidence.md`: a candidate can be ruled out only when a specific control is shown to apply on the actual reachable path before the sensitive operation. Missing prerequisites and missing proof remain unresolved, not safe.
- `strix/skills/analysis/severity_calibration.md`: calibrate only after reachability and counterevidence; rate demonstrated impact rather than the worst hypothetical chain.
- `strix/skills/coordination/root_agent.md` and `strix/skills/scan_modes/{quick,standard,deep,diff}.md`: delegation and scan-mode overlays.
- `strix/tools/load_skill/tool.py`, `strix/skills/__init__.py`, and tests for prompt rendering, skill extension, graph coordination and coverage.

These are implementation/design observations, not a claim that every file in Strix or CyberStrike received a line-by-line security audit.

## Changes applied to CyberStrike main

1. **Shared methodology:** `packages/cyberstrike/src/agent/prompt/methodology/common-methodology.txt` now includes a concise counterevidence/closure contract and severity-calibration rules so the guidance is present during ordinary work, not only after a specialist skill happens to be loaded.
2. **Specialist triage:** `.cyberstrike/skill/attack-triage-validation/SKILL.md` now states the evidence required to confirm, rule out, or leave a candidate inconclusive; distinguishes blocked/not-run/out-of-scope outcomes; and adds an illustrative critical/high/medium/low severity rubric subordinate to the target program's policy.
3. **Specialist-agent prompt:** `packages/cyberstrike/src/agent/prompt/vuln/common-prompt.txt` now makes evidence-first severity calibration explicit for vulnerability-testing agents, not only the default orchestrator.
4. **Regression tests:** `packages/cyberstrike/test/methodology/phase-skills.test.ts` checks the runtime-loaded triage skill, the shared methodology prompt, and the common vulnerability-agent prompt for these guardrails.

The new wording uses CyberStrike's existing `validate_finding` and evidence lifecycle. It does not add a duplicate coverage ledger, duplicate finding statuses, or another orchestration prompt.

## Deliberately not copied

- **Strix's Python/Jinja internals:** would duplicate the existing TypeScript/Bun agent and prompt runtime rather than improve behavior.
- **Root-agent-only delegation:** CyberStrike already has direct tool access, proxy/browser orchestration and its own specialist workflows; forcing every action through a separate child agent would add latency and coordination overhead.
- **Quick/standard/deep fixed testing recipes:** the user's recon requirements prioritize useful unbounded discovery, resume support and adaptive tool choice. Scan recipes must not silently turn into result, host or time caps.
- **Strix's separate coverage ledger:** CyberStrike already has durable phase checkpoints, methodology coverage, validation gates and cursor-based reconciliation. A parallel ledger would risk conflicting sources of truth.
- **Per-tool skill duplication:** CyberStrike already has shared tool-selection/catalog guidance and specialist recon skills. More tool-specific documents should be added only when they fill a demonstrated tool-usage gap, not to inflate skill count.

## Verification and limits

- The changes were saved to the repository's `main` branch through GitHub's file-update interface.
- GitHub Actions results are reported against the exact commit under test; never infer success from a saved file or a run that is still pending.
- No local checkout was available in this review context; tests/build/typecheck are validated through the repository's own CI workflows.
- Repository-wide counts are based on the current recursive Git trees; counts can change as upstream content changes.

## Key source links

- [Strix system prompt](https://github.com/usestrix/strix/blob/main/strix/agents/prompts/system_prompt.jinja)
- [Strix prompt renderer](https://github.com/usestrix/strix/blob/main/strix/agents/prompt.py)
- [Strix counterevidence skill](https://github.com/usestrix/strix/blob/main/strix/skills/analysis/counterevidence.md)
- [Strix severity calibration skill](https://github.com/usestrix/strix/blob/main/strix/skills/analysis/severity_calibration.md)
- [CyberStrike shared methodology](https://github.com/nadamohamed14796-byte/cyber-strike/blob/main/packages/cyberstrike/src/agent/prompt/methodology/common-methodology.txt)
- [CyberStrike triage skill](https://github.com/nadamohamed14796-byte/cyber-strike/blob/main/.cyberstrike/skill/attack-triage-validation/SKILL.md)
- [CyberStrike vulnerability-agent common prompt](https://github.com/nadamohamed14796-byte/cyber-strike/blob/main/packages/cyberstrike/src/agent/prompt/vuln/common-prompt.txt)
- [CyberStrike phase/skill tests](https://github.com/nadamohamed14796-byte/cyber-strike/blob/main/packages/cyberstrike/test/methodology/phase-skills.test.ts)
