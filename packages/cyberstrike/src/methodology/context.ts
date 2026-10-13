import { Database, eq } from "../storage/db"
import { IntelEntryTable } from "./methodology.sql"
import { Methodology } from "./methodology"
import { Intel } from "./intel"
import { Chain } from "./chain"
import { AgentPerformance } from "./performance"
import { Phase } from "./phase"
import { Validation } from "./validation"
import { categoryInLane } from "../tool/vuln-scope"
import { SkillIndex } from "../skill/index-engine"

// Phase-aware skill discovery is intentionally separate from loading: the agent must
// use the skill tool to load the selected skill so normal per-agent permissions apply.
const PHASE_SKILL_QUERIES: Record<Phase.Id, string[]> = {
  scope_analysis: ["attack-bb-methodology", "scope", "attack surface"],
  mobile_application_testing: ["mobile application security", "OWASP MASVS", "OWASP MSTG", "Android security", "iOS security"],
  passive_recon: ["recon-methodology", "recon-subdomain-enumeration", "osint"],
  active_recon: ["attack-web-recon", "recon-port-service-discovery", "recon-vhost-enumeration"],
  technology_profiling: ["technology profiling", "technology fingerprinting", "framework detection"],
  authentication_testing: ["authentication", "auth bypass", "login"],
  session_management: ["session management", "cookie", "JWT"],
  authorization_testing: ["attack-idor-automation", "authorization", "IDOR"],
  input_validation: ["injection", "XSS", "SQL injection", "SSRF"],
  business_logic: ["business logic", "race condition", "attack-bb-methodology"],
  data_protection: ["data protection", "sensitive data", "TLS"],
  api_security: ["API security", "GraphQL", "REST API"],
  infrastructure: ["recon-asn-infrastructure", "cloud security", "network exposure"],
  reporting: ["attack-triage-validation", "attack-evidence-hygiene", "attack-report-writing"],
}

export function skillQueriesForPhase(phaseId: Phase.Id): string[] {
  return [...PHASE_SKILL_QUERIES[phaseId]]
}

async function formatPhaseSkillGuidance(phaseId: Phase.Id): Promise<string> {
  await SkillIndex.ensureBuilt()
  const queries = skillQueriesForPhase(phaseId)
  const candidates = new Map<string, SkillIndex.Entry>()
  // Gather results across every phase query before limiting candidates. Otherwise,
  // a generic first query can crowd out exact matches from later, more specific queries.
  for (const query of queries) {
    for (const entry of SkillIndex.search(query, 20)) {
      if (entry.verified === "tampered") continue
      candidates.set(entry.name, entry)
    }
  }

  const ranked = [...candidates.values()].map((entry) => {
    let bestScore = 0
    let matchedQuery = queries[0] ?? phaseId
    for (const query of queries) {
      const q = query.toLowerCase().trim()
      let score = 0
      if (entry.name.toLowerCase() === q) score += 100
      else if (entry.name.toLowerCase().startsWith(q)) score += 50
      else if (entry.name.toLowerCase().includes(q)) score += 20
      if (entry.tags.some((tag) => tag.toLowerCase() === q)) score += 40
      else if (entry.tags.some((tag) => tag.toLowerCase().includes(q))) score += 15
      if (entry.owasp_id?.toLowerCase().includes(q)) score += 30
      if (entry.category?.toLowerCase().includes(q)) score += 10
      if (entry.description.toLowerCase().includes(q)) score += 5
      if (score > bestScore) {
        bestScore = score
        matchedQuery = query
      }
    }
    return { entry, score: bestScore, query: matchedQuery }
  }).sort((a, b) => b.score - a.score || a.entry.name.localeCompare(b.entry.name))

  const selected = ranked.slice(0, 4).map(({ entry, query }) => ({
    name: entry.name,
    description: entry.description,
    query,
  }))

  const lines = [
    "## Required Skill Preflight",
    "Before testing this phase, use the `skill` tool to load at least one relevant skill listed below. A name in this list is only a recommendation; it is not loaded until the tool returns its skill content.",
    "If loading is denied or a skill is unavailable, search for an allowed alternative and note the gap. Do not claim a skill was loaded unless the tool call succeeded.",
  ]
  if (selected.size === 0) {
    lines.push("No matching catalog skill was found for this phase. Search the skill catalog using the phase name and required tags, then load an allowed match before testing.")
  } else {
    lines.push("", "Phase-specific candidates:")
    for (const match of selected) lines.push(`- ${match.name} — ${match.description} (matched: ${match.query})`)
  }
  return lines.join("\n")
}

// ============================================================
// METHODOLOGY CONTEXT — System prompt injection for
// methodology-aware sessions. Only activates when the session
// has intel entries (meaning methodology is in use).
// ============================================================

export namespace MethodologyContext {
  /**
   * Generate methodology context for system prompt injection.
   * Returns null if methodology is not active (no intel entries).
   */
  /**
   * @param agentClass when set to a proxy-tester class (e.g. "idor"), the context
   *   is scoped to that lane (Phase 2.3): the untested-items list is filtered to
   *   the lane and orchestrator-only sections (delegation briefing, work queue)
   *   are dropped — a tester is handed only its own work, not the routing view.
   *   Leave undefined for the orchestrator / non-tester agents (full context).
   */
  export async function generate(sessionID: string, agentClass?: string): Promise<string | null> {
    const isTester = !!agentClass
    // Check if any intel entries exist for this session
    const count = Database.use((db) =>
      db
        .select({ id: IntelEntryTable.id })
        .from(IntelEntryTable)
        .where(eq(IntelEntryTable.session_id, sessionID))
        .limit(1)
        .all(),
    )
    if (count.length === 0) {
      // Skill preflight must also run before the first intel entry is recorded;
      // otherwise the initial scope-analysis phase would be the one phase that
      // never receives phase-aware skill guidance.
      const initialState = Methodology.computeState(sessionID)
      if (!initialState.currentPhase) return null
      return [
        "# Methodology Skill Preflight",
        "",
        "No target intelligence has been recorded yet. Establish scope and initialize the target workspace before reconnaissance or active testing.",
        "",
        await formatPhaseSkillGuidance(initialState.currentPhase),
      ].join("\n")
    }

    const sections: string[] = ["# Methodology Engine Active", ""]

    // 1. Methodology progress
    const state = Methodology.computeState(sessionID)
    sections.push("## Phase Progress")
    sections.push("")
    for (const phase of state.phases) {
      const icon =
        phase.status === "completed"
          ? "[x]"
          : phase.status === "in_progress"
            ? "[>]"
            : phase.status === "blocked"
              ? "[!]"
              : "[ ]"
      sections.push(`${icon} ${phase.name} (${phase.deliverableCount} entries)`)
    }
    sections.push(`\nOverall: ${state.completionPercent}% (${state.completedCount}/${state.totalCount})`)

    // 2. Blocking violations
    const blocking = state.violations.filter((v) => v.severity === "blocking")
    if (blocking.length > 0) {
      sections.push("")
      sections.push("## BLOCKING VIOLATIONS — Fix before proceeding")
      for (const v of blocking) {
        sections.push(`- [${v.gate}] ${v.message}`)
      }
    }

    // 3. Current phase directive
    if (state.currentPhase) {
      const directive = Methodology.getPhaseDirectives(state.currentPhase)
      if (directive) {
        sections.push("")
        sections.push(`## Current Phase Directive`)
        sections.push(directive)
      }
    }
    // Phase-specific skill guidance is injected into every methodology-aware turn.
    // The agent must still call SkillTool.load, which enforces its permission policy.
    if (state.currentPhase) {
      sections.push("", await formatPhaseSkillGuidance(state.currentPhase))
    }

    // 4. Coverage summary (brief)
    const coverage = Intel.computeCoverage(sessionID)
    if (coverage.totalChecks > 0) {
      sections.push("")
      sections.push(
        `## Coverage: ${coverage.coveragePercent}% (${coverage.completedChecks}/${coverage.totalChecks} VRT checks)`,
      )
      if (coverage.vulnerableChecks > 0) {
        sections.push(`Vulnerable: ${coverage.vulnerableChecks} findings`)
      }
      if (coverage.redFlags.length > 0) {
        sections.push("RED FLAGS:")
        for (const flag of coverage.redFlags.slice(0, 3)) {
          sections.push(`  - [${flag.severity}] ${flag.message}`)
        }
      }
    }

    // 5. Chain opportunities
    const chains = Chain.load(sessionID)
    const active = chains.filter((c) => c.status === "detected" || c.status === "testing")
    if (active.length > 0) {
      sections.push("")
      sections.push(`## Chain Opportunities (${active.length})`)
      for (const c of active.slice(0, 5)) {
        const conf = c.confidence >= 80 ? "HIGH" : c.confidence >= 60 ? "MED" : "LOW"
        sections.push(`- [${conf}] ${c.pattern}: ${c.entryTitles.join(" + ")} -> ${c.expectedImpact}`)
      }
    }

    // 6. Untested items (top 5). For a tester, filter to its own lane (Phase 2.3)
    // so it sees only its hints/work, not every other specialist's queue.
    const untested = isTester
      ? coverage.untestedItems.filter((item) => categoryInLane(agentClass!, item.vrtCategory))
      : coverage.untestedItems
    if (untested.length > 0) {
      const scope = isTester ? ` for proxy-tester-${agentClass}` : ""
      sections.push("")
      sections.push(`## Priority Untested${scope} (${untested.length} total)`)
      for (const item of untested.slice(0, 5)) {
        sections.push(`- ${item.entryTitle}: ${item.vrtCategory} (${item.asset})`)
      }
    }

    // 7. Intelligence protocol reminder
    sections.push("")
    sections.push("## Protocol Reminders")
    sections.push(
      "- Log ALL discoveries via `add_intel` — endpoints, subdomains, technologies, credentials, parameters",
    )
    sections.push("- After testing a VRT check, update it via `update_vrt_check` with evidence")
    sections.push("- Check `methodology_status` before reporting done")
    sections.push("- Use `scope_check` before testing new targets")

    // 8 & 9. Delegation briefing + work queue are ORCHESTRATOR-only routing views
    // (which specialist to dispatch next). Testers can't delegate, so skip them for
    // a tester (Phase 2.3) — removes cross-lane noise and tokens.
    if (!isTester) {
      const briefing = generateDelegationBriefing(sessionID, state, coverage, active)
      if (briefing) sections.push(briefing)

      const workQueue = generateWorkQueue(sessionID, state, coverage, active)
      if (workQueue) sections.push(workQueue)
    }

    // 10. Inter-agent intelligence — shareable discoveries
    const intelBrief = generateIntelBrief(sessionID)
    if (intelBrief) sections.push(intelBrief)

    // 11. Evidence quality feedback — retry guidance
    const feedback = generateEvidenceFeedback(sessionID)
    if (feedback) sections.push(feedback)

    return sections.join("\n")
  }

  /**
   * Check if the session should be forced to continue (coverage/phases incomplete).
   * Returns specific, actionable delegation directives instead of generic messages.
   */
  export function shouldForceContinue(sessionID: string): { force: boolean; directive: string } {
    const count = Database.use((db) =>
      db
        .select({ id: IntelEntryTable.id })
        .from(IntelEntryTable)
        .where(eq(IntelEntryTable.session_id, sessionID))
        .limit(1)
        .all(),
    )
    if (count.length === 0) return { force: false, directive: "" }

    const state = Methodology.computeState(sessionID)
    const coverage = Intel.computeCoverage(sessionID)

    // Force continue if coverage is below threshold and phases are incomplete
    if (state.completionPercent < 50 && coverage.coveragePercent < 30) {
      const directive = buildSmartDirective(sessionID, state, coverage)
      return { force: true, directive }
    }

    // Force continue if there are blocking violations
    const blocking = state.violations.filter((v) => v.severity === "blocking")
    if (blocking.length > 0) {
      const directive = buildViolationDirective(sessionID, blocking, state)
      return { force: true, directive }
    }

    // Force continue if HIGH-confidence chains are untested
    const chains = Chain.load(sessionID)
    const untestedHighChains = chains.filter((c) => c.status === "detected" && c.confidence >= 80)
    if (untestedHighChains.length > 0) {
      const chain = untestedHighChains[0]
      const best = AgentPerformance.selectAgentForMission(sessionID, chain.pattern.replace(/_/g, " "))
      return {
        force: true,
        directive: `HIGH-confidence chain opportunity untested: ${chain.pattern} (${chain.confidence}%). Delegate to ${best.agent}: "${chain.entryTitles.join(" + ")}" → ${chain.expectedImpact}. Test plan: ${chain.testingPlan}`,
      }
    }

    return { force: false, directive: "" }
  }

  // --- Smart Force-Continue Directives ---

  function buildSmartDirective(
    sessionID: string,
    state: ReturnType<typeof Methodology.computeState>,
    coverage: Intel.CoverageReport,
  ): string {
    const lines: string[] = [
      `Methodology ${state.completionPercent}% complete, coverage ${coverage.coveragePercent}%. DO NOT STOP.`,
    ]

    // Find worst coverage asset
    const assetCoverages = Intel.computePerAssetCoverage(sessionID)
    const worstAsset = assetCoverages
      .filter((a) => a.totalChecks > 0)
      .sort((a, b) => a.coveragePercent - b.coveragePercent)[0]

    // Find current phase's recommended agent
    if (state.currentPhase) {
      const ranked = AgentPerformance.selectAgentsForPhase(sessionID, state.currentPhase)
      const primary = ranked[0]
      if (primary && worstAsset) {
        lines.push(
          `NEXT ACTION: Delegate to ${primary.codename} (${primary.name}) for ${state.currentPhase} on ${worstAsset.asset} (${worstAsset.coveragePercent}% coverage).`,
        )
      } else if (primary) {
        lines.push(`NEXT ACTION: Delegate to ${primary.codename} (${primary.name}) for ${state.currentPhase}.`)
      }
    }

    // Show top 3 untested items
    if (coverage.untestedItems.length > 0) {
      lines.push("Untested priorities:")
      for (const item of coverage.untestedItems.slice(0, 3)) {
        lines.push(`  - ${item.entryTitle}: ${item.vrtCategory} (${item.asset})`)
      }
    }

    return lines.join("\n")
  }

  function buildViolationDirective(
    sessionID: string,
    violations: Array<{ gate: string; message: string; field?: string; affectedAsset?: string }>,
    state: ReturnType<typeof Methodology.computeState>,
  ): string {
    const lines: string[] = [`${violations.length} blocking violations. Fix before finishing:`]

    for (const v of violations.slice(0, 3)) {
      lines.push(`- [${v.gate}] ${v.message}`)

      // Generate specific fix instructions per violation type
      if (v.gate === "per_asset_coverage" && v.affectedAsset) {
        const ranked = state.currentPhase ? AgentPerformance.selectAgentsForPhase(sessionID, state.currentPhase) : []
        const agent = ranked[0]?.name ?? "web-application"
        lines.push(`  FIX: Delegate to ${agent} — focus testing on ${v.affectedAsset}`)
      } else if (v.gate === "evidence_quality") {
        lines.push(
          `  FIX: Re-delegate with instruction "provide full PoC — requestSent, responseSummary (50+ chars), reasoning (100+ chars), requestCount ≥ 1"`,
        )
      } else if (v.gate === "methodology_ordering") {
        lines.push(`  FIX: Complete prerequisite phases first before advancing`)
      }
    }

    return lines.join("\n")
  }

  // --- Delegation Briefing ---

  function generateDelegationBriefing(
    sessionID: string,
    state: ReturnType<typeof Methodology.computeState>,
    coverage: Intel.CoverageReport,
    chains: Chain.Candidate[],
  ): string | null {
    if (!state.currentPhase) return null

    const lines: string[] = ["", "## Agent Delegation Briefing"]

    // 1. Recommended agents for current phase
    const ranked = AgentPerformance.selectAgentsForPhase(sessionID, state.currentPhase)
    if (ranked.length > 0) {
      const phaseDef = Phase.get(state.currentPhase)
      lines.push(`### Recommended for: ${phaseDef?.name ?? state.currentPhase}`)
      lines.push("| Agent | Codename | Score | Missions | Morale | Role |")
      lines.push("|-------|----------|-------|----------|--------|------|")
      for (const agent of ranked) {
        lines.push(
          `| ${agent.name} | ${agent.codename} | ${agent.score} | ${agent.stats.missionsCompleted} | ${agent.stats.morale}% | ${agent.role.toUpperCase()} |`,
        )
      }
    }

    // 2. Coverage gaps → agent assignments
    const assetCoverages = Intel.computePerAssetCoverage(sessionID)
    if (assetCoverages.length > 1) {
      const avg = assetCoverages.reduce((sum, a) => sum + a.coveragePercent, 0) / assetCoverages.length
      const neglected = assetCoverages.filter((a) => a.totalChecks > 0 && a.coveragePercent < avg * 0.3)
      if (neglected.length > 0) {
        lines.push("")
        lines.push("### Coverage Gaps")
        for (const asset of neglected.slice(0, 5)) {
          const rec = ranked.length > 0 ? ranked[0].name : "web-application"
          lines.push(`- **${asset.asset}**: ${asset.coveragePercent}% (avg ${Math.round(avg)}%) → delegate to ${rec}`)
        }
      }
    }

    // 3. Chain opportunities → agent routing
    const highChains = chains.filter((c) => c.confidence >= 70)
    if (highChains.length > 0) {
      lines.push("")
      lines.push("### Chain Opportunities → Agent Routing")
      for (const chain of highChains.slice(0, 3)) {
        const conf = chain.confidence >= 80 ? "HIGH" : "MED"
        const best = AgentPerformance.selectAgentForMission(sessionID, chain.pattern.replace(/_/g, " "))
        lines.push(
          `- [${conf}-${chain.confidence}%] ${chain.pattern}: "${chain.entryTitles[0]}" + "${chain.entryTitles[1]}" → delegate to **${best.agent}** (${best.reason})`,
        )
      }
    }

    // 4. Red flags → agent quality
    const agentNames = AgentPerformance.allAgentNames().filter((n) => n !== "cyberstrike")
    const lowMorale = agentNames
      .map((name) => ({
        name,
        meta: AgentPerformance.getAgentMeta(name),
        stats: AgentPerformance.getOrCreate(sessionID, name),
      }))
      .filter((a) => a.stats.missionsCompleted > 0 && a.stats.morale < 30)
    if (lowMorale.length > 0) {
      lines.push("")
      lines.push("### Agent Quality Alerts")
      for (const agent of lowMorale) {
        lines.push(
          `- **${agent.meta?.codename ?? agent.name}** (${agent.name}): morale=${agent.stats.morale}% LOW — consider reassigning missions`,
        )
      }
    }

    return lines.length > 2 ? lines.join("\n") : null
  }

  // --- Work Queue ---

  export interface WorkItem {
    priority: "critical" | "high" | "medium" | "low"
    action: string
    agent: string
    asset?: string
    context: string
  }

  export function generateWorkQueue(
    sessionID: string,
    state: ReturnType<typeof Methodology.computeState>,
    coverage: Intel.CoverageReport,
    chains: Chain.Candidate[],
  ): string | null {
    const items: WorkItem[] = []

    // Priority 1: HIGH-confidence chains (critical)
    for (const chain of chains.filter((c) => c.confidence >= 80)) {
      const best = AgentPerformance.selectAgentForMission(sessionID, chain.pattern.replace(/_/g, " "))
      items.push({
        priority: "critical",
        action: `Test chain: ${chain.pattern}`,
        agent: best.agent,
        asset: chain.assets[0],
        context: chain.testingPlan,
      })
    }

    // Priority 2: Blocking violations (high)
    for (const v of state.violations.filter((v) => v.severity === "blocking").slice(0, 3)) {
      const agent = state.currentPhase
        ? (AgentPerformance.selectAgentsForPhase(sessionID, state.currentPhase)[0]?.name ?? "web-application")
        : "web-application"
      items.push({
        priority: "high",
        action: `Fix violation: ${v.gate}`,
        agent,
        asset: v.affectedAsset,
        context: v.message,
      })
    }

    // Priority 3: Coverage gaps per asset (high)
    const assetCoverages = Intel.computePerAssetCoverage(sessionID)
    const zeroCoverage = assetCoverages.filter((a) => a.totalChecks > 0 && a.coveragePercent === 0)
    for (const asset of zeroCoverage.slice(0, 3)) {
      items.push({
        priority: "high",
        action: `Start testing on untouched asset`,
        agent: "web-application",
        asset: asset.asset,
        context: `${asset.totalChecks} VRT checks pending, 0% coverage`,
      })
    }

    // Priority 4: MED-confidence chains (medium)
    for (const chain of chains.filter((c) => c.confidence >= 60 && c.confidence < 80)) {
      const best = AgentPerformance.selectAgentForMission(sessionID, chain.pattern.replace(/_/g, " "))
      items.push({
        priority: "medium",
        action: `Investigate chain: ${chain.pattern}`,
        agent: best.agent,
        asset: chain.assets[0],
        context: chain.testingPlan,
      })
    }

    // Priority 5: Incomplete phases with available agents (medium)
    const incompletePhases = state.phases.filter((p) => p.status === "not_started" && !p.blockReason)
    for (const phase of incompletePhases.slice(0, 2)) {
      const ranked = AgentPerformance.selectAgentsForPhase(sessionID, phase.id)
      if (ranked.length > 0) {
        items.push({
          priority: "medium",
          action: `Start phase: ${phase.name}`,
          agent: ranked[0].name,
          context: Methodology.getPhaseDirectives(phase.id) || `Begin ${phase.name}`,
        })
      }
    }

    if (items.length === 0) return null

    const lines: string[] = ["", `## Work Queue (${items.length} items)`]
    const priorityIcon: Record<string, string> = { critical: "!!!", high: "!!", medium: "!", low: "." }

    for (const item of items.slice(0, 8)) {
      const icon = priorityIcon[item.priority] ?? "."
      const assetStr = item.asset ? ` [${item.asset}]` : ""
      lines.push(`${icon} [${item.priority.toUpperCase()}] ${item.action}${assetStr} → ${item.agent}`)
      lines.push(`    ${item.context.slice(0, 150)}`)
    }

    return lines.join("\n")
  }

  // --- Inter-Agent Intelligence Brief ---

  function generateIntelBrief(sessionID: string): string | null {
    const entries = Intel.get(sessionID)
    if (entries.length === 0) return null

    const credentials = entries.filter((e) => e.type === "credential")
    const authFlows = entries.filter((e) => e.type === "authentication_flow")
    const configs = entries.filter((e) => e.type === "configuration" || e.type === "sensitive_data")
    const endpoints = entries.filter((e) => e.type === "endpoint")

    const hasShareable = credentials.length > 0 || authFlows.length > 0 || configs.length > 0

    if (!hasShareable) return null

    const lines: string[] = ["", "## Shared Intelligence — Pass to delegated agents"]

    if (credentials.length > 0) {
      lines.push("### Credentials Discovered")
      for (const cred of credentials.slice(0, 5)) {
        const conf = cred.confidenceLevel ?? "low"
        lines.push(`- [${conf}] "${cred.title}" on ${cred.asset} (id: ${cred.id})`)
        if (cred.detail) lines.push(`  Detail: ${cred.detail.slice(0, 120)}`)
      }
      lines.push("**When delegating auth/authz testing, include these credentials in the prompt.**")
    }

    if (authFlows.length > 0) {
      lines.push("")
      lines.push("### Authentication Flows Mapped")
      for (const flow of authFlows.slice(0, 3)) {
        lines.push(`- "${flow.title}" on ${flow.asset}`)
      }
    }

    if (configs.length > 0) {
      lines.push("")
      lines.push("### Configurations / Sensitive Data Found")
      for (const cfg of configs.slice(0, 5)) {
        lines.push(`- "${cfg.title}" on ${cfg.asset} (id: ${cfg.id})`)
      }
      lines.push("**When delegating SSRF/infrastructure testing, reference these as potential targets.**")
    }

    // Endpoint summary by asset
    if (endpoints.length > 3) {
      const assetEndpoints = new Map<string, number>()
      for (const ep of endpoints) {
        assetEndpoints.set(ep.asset, (assetEndpoints.get(ep.asset) ?? 0) + 1)
      }
      lines.push("")
      lines.push("### Endpoint Map")
      for (const [asset, count] of [...assetEndpoints.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5)) {
        lines.push(`- ${asset}: ${count} endpoints discovered`)
      }
    }

    return lines.join("\n")
  }

  // --- Evidence Quality Feedback ---

  function generateEvidenceFeedback(sessionID: string): string | null {
    const results = Validation.validateEvidenceQuality(sessionID)
    const failed = results.filter((r) => !r.passed)
    if (failed.length === 0) return null

    const lines: string[] = ["", "## Evidence Quality Issues — Re-delegation Required"]

    for (const result of failed.slice(0, 5)) {
      lines.push(`### "${result.entryTitle}" (${result.checkCategory})`)
      for (const v of result.violations) {
        lines.push(`- [${v.severity}] ${v.message}`)
        if (v.field === "requestSent") {
          lines.push(`  FIX: Re-delegate with "send actual HTTP request using curl/httpx, include full request line"`)
        } else if (v.field === "responseSummary") {
          lines.push(
            `  FIX: Re-delegate with "capture actual HTTP response, summarize in 50+ chars with status code and key data"`,
          )
        } else if (v.field === "reasoning") {
          lines.push(
            `  FIX: Re-delegate with "explain why this is vulnerable — describe the flaw, impact, and how it differs from expected behavior (100+ chars)"`,
          )
        } else if (v.field === "requestCount") {
          lines.push(`  FIX: Re-delegate with "send at least 1 real HTTP request to verify the vulnerability"`)
        }
      }
    }

    lines.push("")
    lines.push("**When re-delegating, include the specific fix instructions above in the agent's prompt.**")

    return lines.join("\n")
  }
}
