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
  scope_analysis: ["attack-bb-methodology", "target-workspace-workflow", "scope", "attack surface"],
  mobile_application_testing: ["mitre_attack_mobile", "mobile application security", "OWASP MASVS", "OWASP MSTG", "Android security", "iOS security"],
  passive_recon: [
    "recon-methodology", "wstg-recon-config", "wstg-info", "recon-subdomain-enumeration", "recon-email-security",
    "recon-gitlab-public-recon", "recon-origin-ip-discovery", "recon-error-log-mining",
    "recon-visual-recon", "target-workspace-workflow", "osint",
  ],
  active_recon: [
    "attack-web-recon", "wstg-info", "wstg-conf-05", "wstg-conf-10", "wstg-apit-01", "recon-port-service-discovery", "recon-vhost-enumeration",
    "recon-cms-detection", "recon-subdomain-enumeration", "recon-origin-ip-discovery",
    "attack-subdomain-takeover", "recon-asn-infrastructure", "target-workspace-workflow",
  ],
  technology_profiling: [
    "technology profiling", "technology fingerprinting", "framework detection", "wstg-info-08", "wstg-info-09", "wstg-recon-config",
    "attack-django", "attack-fastapi", "attack-flask-werkzeug", "attack-laravel",
    "attack-nestjs", "attack-nextjs", "attack-nodejs", "attack-springboot",
    "attack-wordpress", "attack-exchange-owa", "attack-zimbra", "attack-hikvision-isapi",
    "attack-vmware-vcenter", "attack-minio-s3", "llm-security",
  ],
  authentication_testing: [
    "wstg-athn", "wstg-idnt", "wstg-auth-session", "attack-auth-bypass", "attack-401-403-bypass", "attack-ato", "attack-mfa-bypass",
    "attack-captcha-bypass", "attack-forgot-password", "attack-oauth", "attack-saml-sso",
    "authentication", "auth bypass", "login",
  ],
  session_management: [
    "wstg-sess", "wstg-auth-session", "attack-session", "attack-jwt", "attack-csrf", "attack-oauth", "attack-saml-sso",
    "session management", "cookie", "JWT",
  ],
  authorization_testing: [
    "wstg-authz", "wstg-apit-02", "wstg-auth-session", "attack-idor-automation", "attack-mass-assignment", "attack-bfla",
    "attack-api-noauth-hunt", "attack-401-403-bypass", "attack-cors",
    "authorization", "IDOR", "access control",
  ],
  input_validation: [
    "wstg-inpv", "wstg-clnt", "wstg-injection", "attack-xss", "attack-dom-xss", "attack-sqli", "attack-nosqli", "attack-ssrf",
    "attack-ssti", "attack-xxe", "attack-deserialization", "attack-file-upload",
    "attack-rce", "attack-prototype-pollution", "attack-request-smuggling",
    "attack-open-redirect", "attack-host-header", "attack-cache-poison", "llm-security", "injection",
    "XSS", "SQL injection", "SSRF",
  ],
  business_logic: [
    "wstg-busl", "wstg-logic-client-api", "attack-business-logic", "attack-race-condition", "attack-mass-assignment",
    "attack-rate-limit-bypass", "attack-csrf", "attack-clickjacking",
    "attack-host-header", "attack-cache-poison", "business logic", "race condition",
    "attack-bb-methodology",
  ],
  data_protection: [
    "wstg-cryp", "wstg-errh", "wstg-conf", "attack-information-disclosure", "attack-source-leak", "attack-phpinfo-exposure",
    "attack-ntlm-info", "data protection", "sensitive data", "TLS",
  ],
  api_security: [
    "wstg-apit", "wstg-authz-05", "wstg-logic-client-api", "attack-graphql", "attack-bfla", "attack-api-noauth-hunt", "attack-schema-enumeration",
    "attack-grpc", "attack-mass-assignment", "attack-nosqli", "attack-rate-limit-bypass",
    "attack-websocket", "attack-cors", "attack-host-header", "attack-cache-poison",
    "attack-clickjacking", "attack-open-redirect", "attack-jwt", "llm-security",
    "API security", "GraphQL", "REST API",
  ],
  infrastructure: [
    "recon-asn-infrastructure", "recon-origin-ip-discovery", "attack-cloud-misconfig",
    "cloud-assessment", "ci-assessment", "cicd-attacks", "attack-docker-privesc",
    "k8s-assessment", "ad-security", "attack-ldap", "attack-ntlm-info",
    "aws-postexploit", "azure-postexploit", "gcp-postexploit", "k8s-postexploit",
    "windows-postexploit", "linux-postexploit", "macos-postexploit", "ebpf-attacks",
    "kerberos-attacks", "mitre_attack", "mitre_attack_ics", "CIS benchmarks", "NIST controls",
    "cloud security", "network exposure",
  ],
  reporting: [
    "attack-triage-validation", "attack-evidence-hygiene", "attack-report-writing",
    "bugcrowd-reporting", "triage-validation", "evidence-hygiene", "report-writing",
  ],
}

export function skillQueriesForPhase(phaseId: Phase.Id): string[] {
  // Include methodology-defined required tags as first-class search terms. These are
  // the canonical phase taxonomy; hand-maintained queries are additional aliases.
  const configured = PHASE_SKILL_QUERIES[phaseId] ?? []
  const requiredTags = Phase.get(phaseId)?.requiredTags ?? []
  return [...new Set([...requiredTags, ...configured])]
}

type RankedPhaseSkill = { entry: SkillIndex.Entry; score: number; query: string }

const normalizeSkillText = (value: string) =>
  value.toLowerCase().replace(/[_/.-]+/g, " ").replace(/[^a-z0-9 ]+/g, " ").replace(/\s+/g, " ").trim()

const skillTokens = (value: string) =>
  normalizeSkillText(value).split(" ").filter((token) => token.length > 2)

export function rankSkillsForPhase(
  phaseId: Phase.Id,
  entries: SkillIndex.Entry[],
  limit = 10,
  observedTechStack: string[] = [],
): Array<{ name: string; description: string; query: string; score: number }> {
  const queries = skillQueriesForPhase(phaseId)
  const observedTechnologies = observedTechStack.map(normalizeSkillText).filter(Boolean)
  const phase = Phase.get(phaseId)
  const requiredTags = new Set((phase?.requiredTags ?? []).map(normalizeSkillText))
  const queryTokens = new Set(queries.flatMap(skillTokens))
  const ranked: RankedPhaseSkill[] = []

  for (const entry of entries) {
    if (entry.verified === "tampered") continue
    const name = normalizeSkillText(entry.name)
    const tags = entry.tags.map(normalizeSkillText).filter(Boolean)
    const category = normalizeSkillText(entry.category ?? "")
    const description = normalizeSkillText(entry.description)
    // Empty metadata values must not match every observed technology via includes("").
    const tech = entry.tech_stack.map(normalizeSkillText).filter(Boolean)
    const searchable = [name, category, description, ...tags, ...tech, normalizeSkillText(entry.owasp_id ?? "")].join(" ")
    let score = 0
    let matchedQuery = queries[0] ?? phaseId

    // Prefer exact skill aliases and exact phase tags over broad prose matches.
    for (const query of queries) {
      const normalizedQuery = normalizeSkillText(query)
      let queryScore = 0
      if (name === normalizedQuery) queryScore += 120
      else if (name.startsWith(normalizedQuery)) queryScore += 70
      else if (name.includes(normalizedQuery)) queryScore += 35
      if (tags.includes(normalizedQuery)) queryScore += 90
      else if (tags.some((tag) => tag.includes(normalizedQuery) || normalizedQuery.includes(tag))) queryScore += 30
      if (category === normalizedQuery) queryScore += 25
      if (description.includes(normalizedQuery)) queryScore += 8
      if (tech.includes(normalizedQuery)) queryScore += 35
      if (queryScore > score) {
        score = queryScore
        matchedQuery = query
      }
    }

    // Token overlap handles differences such as "active-recon" vs "reconnaissance"
    // and uses metadata beyond the skill's display name.
    const searchableTokens = new Set(searchable.split(" ").filter(Boolean))
    const matchedTokens = [...queryTokens].filter((token) => searchableTokens.has(token))
    score += Math.min(matchedTokens.length, 8) * 3
    for (const tag of tags) if (requiredTags.has(tag)) score += 45
    for (const skillTech of tech) {
      if (observedTechnologies.some((observed) => observed === skillTech || observed.includes(skillTech) || skillTech.includes(observed))) {
        score += 35
      }
    }
    if (phaseId === "passive_recon" || phaseId === "active_recon") {
      if (/\brecon\b|reconnaissance|subdomain|osint|enumeration|port scan|vhost|virtual host/.test(searchable)) {
        score += 55
      }
    }
    // A single generic token (for example "tech" from "tech-profile") is not enough\n    // to select an otherwise unrelated skill. Require either multiple token matches\n    // or a substantive exact/tag/description/technology signal.\n    if (score >= 6) ranked.push({ entry, score, query: matchedQuery })
  }

  ranked.sort((a, b) => b.score - a.score || a.entry.name.localeCompare(b.entry.name))
  const selected: RankedPhaseSkill[] = []
  const seen = new Set<string>()

  // Recon preflight has a hard coverage requirement: reserve one slot for a
  // recon-specific skill even when a generic high-scoring skill ranks first.
  if (phaseId === "passive_recon" || phaseId === "active_recon") {
    const recon = ranked.find(({ entry }) => {
      const text = normalizeSkillText([
        entry.name, entry.category ?? "", entry.description, ...entry.tags,
      ].join(" "))
      return /\brecon\b|reconnaissance|subdomain|osint|enumeration|port scan|vhost|virtual host/.test(text)
    })
    if (recon) {
      selected.push(recon)
      seen.add(recon.entry.name)
    }
  }

  for (const item of ranked) {
    if (selected.length >= Math.max(0, limit)) break
    if (seen.has(item.entry.name)) continue
    selected.push(item)
    seen.add(item.entry.name)
  }

  return selected.slice(0, Math.max(0, limit)).map(({ entry, score, query }) => ({
    name: entry.name,
    description: entry.description,
    query,
    score,
  }))
}

async function formatPhaseSkillGuidance(phaseId: Phase.Id, sessionID: string): Promise<string> {
  const lines = [
    "## Required Skill Preflight",
    "Before doing phase work, use the `skill` tool action=`search` to discover relevant skills for each distinct task, then action=`load` with the exact skill name. Wait for each tool result and verify the skill content was returned before claiming it is loaded.",
    "The candidate list below is a ranked shortlist, not the complete catalog. Search again for every applicable subtask, observed technology/framework, protocol, and vulnerability class; load all skills that materially apply to the current evidence, not unrelated skills from the whole catalog.",
    "Load the general phase methodology plus specialized skills for each distinct work area. A recommendation is not a loaded skill, and a generic skill does not satisfy coverage for a specialized task. Re-check the catalog when new endpoints, assets, authentication flows, technologies, or vulnerability signals appear.",
    "For passive_recon and active_recon, load recon-methodology (or the closest available methodology skill) and at least one task-specific recon skill before reconnaissance. Search and load additional relevant skills for subdomain/DNS, service/port discovery, virtual hosts, CMS/framework detection, origin-IP, email/DNS security, exposed repositories, historical URLs, visual recon, and takeover checks when applicable. Do not claim a task was covered merely because a skill was recommended.",
    "If loading is denied or unavailable, search for an allowed alternative and record the exact gap. Never claim success when the tool failed. Do not proceed to active testing when scope validation or required scope checks fail.",
  ]

  try {
    await SkillIndex.ensureBuilt()
    const observedTechStack = Intel.get(sessionID)
      .filter((entry) => entry.type === "technology")
      .flatMap((entry) => [entry.title, ...entry.tags])
    const selected = rankSkillsForPhase(phaseId, SkillIndex.all(), 10, observedTechStack)
    if (selected.length === 0) {
      lines.push("No matching catalog skill was found for this phase. Search the skill catalog using the phase name and required tags, then load an allowed match before testing.")
    } else {
      lines.push("", "Phase-specific candidates (ranked by phase tags and skill metadata):")
      for (const match of selected) {
        lines.push(`- ${match.name} — ${match.description} (matched: ${match.query}; relevance: ${match.score})`)
      }
    }
  } catch {
    // Skill catalog failures must not prevent session prompt generation.
    lines.push("Skill catalog lookup failed. Do not claim a skill was loaded; search the available skill catalog manually and record the limitation before testing.")
  }

  return lines.join("\n")
}

// ============================================================
// METHODOLOGY CONTEXT — System prompt injection for methodology-aware sessions.
// Phase-specific skill preflight also runs before the first intel entry;
// progress, coverage, and routing context require recorded intelligence.
// ============================================================

export namespace MethodologyContext {
  /**
   * Generate methodology context for system prompt injection.
   * Returns null only when no applicable phase is available.
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
        await formatPhaseSkillGuidance(initialState.currentPhase, sessionID),
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
      sections.push("", await formatPhaseSkillGuidance(state.currentPhase, sessionID))
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
