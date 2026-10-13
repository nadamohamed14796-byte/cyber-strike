import z from "zod"
import { Tool } from "./tool"
import DESCRIPTION from "./generate_report.txt"
import { Vulnerability } from "../session/vulnerability"
import { Session } from "../session"
import { Methodology } from "../methodology/methodology"
import { Intel } from "../methodology/intel"
import { CoverageNote } from "../session/coverage-note"
import { Chain } from "../methodology/chain"
import { Validation } from "../methodology/validation"
import { Request } from "../session/request"
import { AgentPerformance } from "../methodology/performance"
import { TargetMemory, type Workspace } from "../target"

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
}

const AGENT_NAMES = [
  "web-application",
  "proxy-agent",
  "explore",
  "cloud-security",
  "internal-network",
  "mobile-application",
  "cyberstrike",
] as const

const AGENT_CODENAMES: Record<string, string> = {
  "web-application": "STRIKER",
  "proxy-agent": "INTERCEPTOR",
  explore: "GHOST",
  "cloud-security": "AURORA",
  "internal-network": "PHANTOM",
  "mobile-application": "CIPHER",
  cyberstrike: "COMMANDER",
}

const ALL_SECTIONS = [
  "executive_summary",
  "findings",
  "coverage",
  "methodology",
  "chains",
  "attack_surface",
  "timeline",
  "agent_performance",
  "validation",
] as const

export const GenerateReportTool = Tool.define("generate_report", {
  description: DESCRIPTION,
  parameters: z.object({
    include_sections: z.array(z.enum(ALL_SECTIONS)).optional().describe("Sections to include (default: all)"),
    target_url: z.string().url().optional().describe("Optional saved target workspace URL. When supplied, only findings attributed to this workspace and its selected descendants are included."),
    include_children: z.boolean().optional().describe("For target_url reports, include all nested child assets (default: true). Set false for only this one workspace."),
  }),
  async execute(params, ctx) {
    const rootSession = Session.root(ctx.sessionID)
    const session = await Session.get(rootSession)
    const allWorkspaces = TargetMemory.list()
    const workspacesByID = new Map(allWorkspaces.map((target) => [target.id, target]))
    const targetURLs = new Map(allWorkspaces.map((target) => [target.id, target.targetURL]))
    const allVulns = Vulnerability.confirmed(rootSession)
    const allIntel = Intel.get(rootSession)
    const allRequests = Request.get(rootSession)

    let reportTarget = params.target_url ? await TargetMemory.get(params.target_url) : undefined
    if (params.target_url && !reportTarget) {
      throw new Error("Report target workspace was not found. Initialize the target and configure its saved scope first.")
    }

    // Select the only root program observed by this session by default. If the session
    // spans multiple roots, fail closed instead of creating a mixed-program report.
    if (!params.target_url) {
      const observedWorkspaceIDs = new Set<string>()
      for (const finding of allVulns) {
        if (finding.target_id && workspacesByID.has(finding.target_id)) observedWorkspaceIDs.add(finding.target_id)
      }
      for (const entry of allIntel) {
        for (const workspace of allWorkspaces) {
          if (assetMatchesWorkspace(entry.asset, workspace)) observedWorkspaceIDs.add(workspace.id)
        }
      }
      for (const request of allRequests) {
        for (const workspace of allWorkspaces) {
          if (requestMatchesWorkspace(request, workspace)) observedWorkspaceIDs.add(workspace.id)
        }
      }
      const roots = new Map<string, Workspace>()
      for (const observedID of observedWorkspaceIDs) {
        let current = workspacesByID.get(observedID)
        const visited = new Set<string>()
        while (current?.parentTargetID && !visited.has(current.id)) {
          visited.add(current.id)
          current = workspacesByID.get(current.parentTargetID)
        }
        if (current) roots.set(current.id, current)
      }
      if (roots.size > 1) {
        throw new Error(
          "This session contains more than one target program. Choose target_url explicitly so reports and findings from separate programs are not mixed. Available roots: " +
          [...roots.values()].map((root) => root.targetURL).join(", "),
        )
      }
      const inferredRoot = [...roots.values()][0]
      if (inferredRoot) reportTarget = (await TargetMemory.get(inferredRoot.targetURL)) ?? undefined
    }

    const includeChildren = Boolean(reportTarget && params.include_children !== false)
    const selectedWorkspaces = reportTarget
      ? selectReportWorkspaces(reportTarget, allWorkspaces, includeChildren)
      : allWorkspaces
    const selectedTargetIDs = new Set(selectedWorkspaces.map((target) => target.id))
    const assetInReport = (asset: string) =>
      !reportTarget || selectedWorkspaces.some((target) => assetMatchesWorkspace(asset, target))
    const requestInReport = (request: Request.Info) =>
      !reportTarget || selectedWorkspaces.some((target) => requestMatchesWorkspace(request, target))

    const vulns = reportTarget
      ? allVulns.filter((v) => Boolean(v.target_id && selectedTargetIDs.has(v.target_id)))
      : allVulns
    const excludedFindingCount = reportTarget ? allVulns.length - vulns.length : 0
    const unattributedFindingCount = reportTarget ? allVulns.filter((v) => !v.target_id).length : 0

    const intel = allIntel.filter((entry) => assetInReport(entry.asset))
    const coverage = Intel.computeCoverage(rootSession, (entry) => assetInReport(entry.asset))
    const assetCoverage = Intel.computePerAssetCoverage(rootSession, (entry) => assetInReport(entry.asset))
    const coverageNotes = CoverageNote.listBySession(rootSession).filter((note) => assetInReport(note.asset))
    const state = Methodology.computeState(rootSession)
    const chains = Chain.load(rootSession).filter((chain) =>
      !reportTarget || chain.assets.some((asset) => assetInReport(asset)),
    )
    const requests = allRequests.filter(requestInReport)

    // The target-limited report must not present the session-wide validation result as
    // if it validated only the selected assets. Full-session reports use saved scopes
    // instead of passing an empty scope list (which silently skipped the scope gate).
    let gates: ReturnType<typeof Validation.runAllGates> | undefined
    if (!reportTarget) {
      const scopeItems = new Set<string>()
      for (const workspace of allWorkspaces) {
        try {
          const scope = await TargetMemory.getScope(workspace.targetURL)
          if (scope?.status === "configured") for (const item of scope.scopeItems) scopeItems.add(item)
        } catch {
          // A broken manifest must not widen a scope. Other valid scopes still participate.
        }
      }
      gates = Validation.runAllGates(rootSession, [...scopeItems])
    }

    const breakdown = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    for (const v of vulns) {
      const key = v.severity as keyof typeof breakdown
      if (key in breakdown) breakdown[key]++
    }

    const uniqueAssets = [...new Set(intel.map((e) => e.asset))]
    const duration = session.time.updated - session.time.created
    const sections = params.include_sections ?? [...ALL_SECTIONS]
    const reportLabel = reportTarget
      ? reportTarget.targetURL + (includeChildren ? ` (including ${Math.max(0, selectedWorkspaces.length - 1)} descendant workspaces)` : " (single workspace)")
      : session.title
    const draftTimestamp = new Date().toISOString().replace(/[:.]/g, "-")
    const recommendedReportPath = reportTarget
      ? reportTarget.workspacePath + "/reports/report-" + draftTimestamp + ".md"
      : undefined

    const parts: string[] = []
    parts.push(formatHeader(session, vulns, breakdown, coverage, state, duration, reportLabel))

    if (reportTarget) {
      parts.push(formatReportScope(reportTarget.targetURL, selectedWorkspaces, includeChildren, excludedFindingCount, unattributedFindingCount, reportTarget.workspacePath))
    }

    if (sections.includes("executive_summary")) {
      parts.push("---\n\n<!-- AI: executive_summary -->\n\n---\n\n<!-- AI: risk_assessment -->")
    }

    if (sections.includes("findings")) parts.push(formatVulnTable(vulns, targetURLs))

    if (sections.includes("coverage")) parts.push(formatCoverage(coverage, assetCoverage, coverageNotes))

    if (sections.includes("methodology")) parts.push(formatMethodologySection(state, Boolean(reportTarget)))

    if (sections.includes("chains")) parts.push(formatChains(chains))

    if (sections.includes("attack_surface")) parts.push(formatAttackSurface(intel, requests, uniqueAssets))

    if (sections.includes("timeline")) parts.push(formatTimeline(vulns, session))

    if (sections.includes("agent_performance")) parts.push(formatAgentPerformance(rootSession, Boolean(reportTarget)))

    if (sections.includes("validation")) {
      parts.push(reportTarget
        ? formatScopedValidationNotice()
        : formatValidationSection(gates!))
    }

    parts.push(
      "---\n\n<!-- AI: remediation_priorities -->\n\n---\n\n*Generated by CyberStrike (cyberstrike.io) — AI-Powered Offensive Security Platform*",
    )

    const output = parts.join("\n\n")
    const savedReportPath = reportTarget
      ? await TargetMemory.writeWorkspaceFile(reportTarget, "reports/report-" + draftTimestamp + ".md", output)
      : undefined

    return {
      title: `Report: ${vulns.length} findings | ${coverage.coveragePercent}% coverage`,
      output,
      metadata: {
        findingCount: vulns.length,
        excludedFindingCount,
        unattributedFindingCount,
        criticalCount: breakdown.critical,
        highCount: breakdown.high,
        coveragePercent: coverage.coveragePercent,
        methodologyPercent: state.completionPercent,
        activeChains: chains.filter((c) => c.status !== "disproven").length,
        reportTargetURL: reportTarget?.targetURL,
        reportTargetID: reportTarget?.id,
        includedWorkspaceIDs: reportTarget ? [...selectedTargetIDs] : undefined,
        includeChildren: reportTarget ? includeChildren : undefined,
        automaticallySaved: Boolean(savedReportPath),
        recommendedReportPath: savedReportPath ?? recommendedReportPath,
      },
    }
  },
})

// --- Helper Functions ---

function selectReportWorkspaces(
  root: Workspace,
  allWorkspaces: Workspace[],
  includeChildren: boolean,
): Workspace[] {
  const byParent = new Map<string, Workspace[]>()
  const byID = new Map(allWorkspaces.map((workspace) => [workspace.id, workspace]))
  for (const workspace of allWorkspaces) {
    if (!workspace.parentTargetID) continue
    const siblings = byParent.get(workspace.parentTargetID) ?? []
    siblings.push(workspace)
    byParent.set(workspace.parentTargetID, siblings)
  }

  const selected: Workspace[] = []
  const seen = new Set<string>()
  const visit = (id: string) => {
    if (seen.has(id)) return
    seen.add(id)
    const workspace = byID.get(id)
    if (!workspace) return
    selected.push(workspace)
    if (includeChildren) for (const child of byParent.get(id) ?? []) visit(child.id)
  }
  visit(root.id)
  return selected
}

function pathIsWithin(basePath: string, candidatePath: string): boolean {
  const base = basePath.replace(/\/+$/, "") || "/"
  const candidate = candidatePath.replace(/\/+$/, "") || "/"
  return base === "/" || candidate === base || candidate.startsWith(base + "/")
}

/** Match an intelligence asset to an exact workspace host and path, not a substring. */
function assetMatchesWorkspace(
  asset: string,
  workspace: { targetURL: string },
): boolean {
  const raw = asset?.trim()
  if (!raw || /[\u0000-\u001f]/.test(raw)) return false
  const explicitScheme = /^[a-z][a-z\d+.-]*:\/\//i.test(raw)
  let candidate: URL
  try {
    candidate = new URL(explicitScheme ? raw : "https://" + raw)
  } catch {
    return false
  }
  if (candidate.username || candidate.password || !["http:", "https:"].includes(candidate.protocol)) return false

  const base = new URL(workspace.targetURL)
  if (candidate.hostname.toLowerCase() !== base.hostname.toLowerCase()) return false
  if (explicitScheme && (candidate.protocol !== base.protocol || candidate.port !== base.port)) return false
  if (!explicitScheme && candidate.port && candidate.port !== base.port) return false
  return pathIsWithin(base.pathname, candidate.pathname)
}

/** Filter captured request records by exact origin and the target's saved path boundary. */
function requestMatchesWorkspace(
  request: Request.Info,
  workspace: { targetURL: string },
): boolean {
  const base = new URL(workspace.targetURL)
  const origin = request.origin ?? (request.scheme && request.host
    ? request.scheme + "://" + request.host + (request.port ? ":" + request.port : "")
    : undefined)
  if (!origin) return request.page_url ? assetMatchesWorkspace(request.page_url, workspace) : false
  try {
    const parsedOrigin = new URL(origin)
    if ((parsedOrigin.protocol !== "http:" && parsedOrigin.protocol !== "https:") ||
      parsedOrigin.username || parsedOrigin.password || parsedOrigin.origin !== base.origin) return false
    const requestPath = request.normalized_path || request.canonical_path || "/"
    const parsedPath = new URL(requestPath, parsedOrigin).pathname
    return pathIsWithin(base.pathname, parsedPath)
  } catch {
    return false
  }
}

function formatReportScope(
  targetURL: string,
  workspaces: Workspace[],
  includeChildren: boolean,
  excludedFindingCount: number,
  unattributedFindingCount: number,
  workspacePath: string,
): string {
  const lines = [
    "## Report Scope",
    "",
    `- Selected target: ${targetURL}`,
    `- Included workspaces: ${workspaces.length}${includeChildren ? " (target plus authorized descendants)" : " (selected workspace only)"}`,
    `- Findings excluded because they belong to another workspace or have no target attribution: ${excludedFindingCount}`,
    `- Unattributed findings among those excluded: ${unattributedFindingCount}`,
    `- Final report location: ${workspacePath}/reports/`,
    "",
    "| Workspace | Type |",
    "|---|---|",
    ...workspaces.map((workspace) => `| ${workspace.targetURL.replace(/\|/g, "%7C")} | ${workspace.assetType} |`),
  ]
  return lines.join("\n")
}

function formatScopedValidationNotice(): string {
  return [
    "## Validation Status",
    "",
    "Not computed for this target-limited report. The validation gates operate on session-wide methodology and finding records; presenting that global result here would misstate the validation of the selected asset subset.",
    "Run a program-wide report to see the session-level validation gate.",
  ].join("\n")
}

function formatDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000)
  const minutes = Math.floor(seconds / 60)
  const hours = Math.floor(minutes / 60)
  const days = Math.floor(hours / 24)
  if (days > 0) return `${days}d ${hours % 24}h`
  if (hours > 0) return `${hours}h ${minutes % 60}m`
  if (minutes > 0) return `${minutes}m`
  return `${seconds}s`
}

function formatHeader(
  session: { title: string; time: { created: number; updated: number } },
  vulns: Vulnerability.Info[],
  breakdown: Record<string, number>,
  coverage: Intel.CoverageReport,
  state: Methodology.State,
  duration: number,
  targetLabel = session.title,
): string {
  const date = new Date(session.time.created).toISOString().split("T")[0]
  const openCount = vulns.filter((v) => v.status !== "fixed" && v.status !== "ignored").length
  return [
    "# Security Assessment Report",
    "",
    `**Target:** ${targetLabel}`,
    `**Date:** ${date}`,
    `**Duration:** ${formatDuration(duration)}`,
    `**Findings:** ${vulns.length} total (${openCount} open) — ${breakdown.critical} Critical, ${breakdown.high} High, ${breakdown.medium} Medium, ${breakdown.low} Low, ${breakdown.info} Info`,
    `**Coverage:** ${coverage.coveragePercent}% (${coverage.completedChecks}/${coverage.totalChecks} VRT checks)`,
    `**Methodology:** ${state.completionPercent}% (${state.completedCount}/${state.totalCount} phases)`,
  ].join("\n")
}

function formatVulnTable(vulns: Vulnerability.Info[], targetURLs: Map<string, string> = new Map()): string {
  if (vulns.length === 0) return "## Vulnerability Findings\n\nNo vulnerabilities discovered."

  const sorted = [...vulns].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 4) - (SEVERITY_ORDER[b.severity] ?? 4))

  const counters: Record<string, number> = {}
  const lines: string[] = ["## Vulnerability Findings", "", "### Summary", ""]
  lines.push("| # | Severity | Title | Target workspace | Endpoint | CWE | Status |")
  lines.push("|---|----------|-------|------------------|----------|-----|--------|")

  const details: string[] = ["", "### Finding Details"]

  for (const v of sorted) {
    const sev = v.severity.toUpperCase()
    counters[sev] = (counters[sev] ?? 0) + 1
    const ref = `${sev}-${String(counters[sev]).padStart(3, "0")}`

    const targetURL = v.target_id ? targetURLs.get(v.target_id) : undefined
    lines.push(`| ${ref} | ${sev} | ${v.title} | ${targetURL ? targetURL + " (" + v.target_id + ")" : v.target_id ?? "—"} | ${v.endpoint ?? "—"} | ${v.cwe_id ?? "—"} | ${v.status} |`)

    details.push("")
    details.push(`#### [${ref}] ${v.title}`)
    details.push(`- **Severity:** ${sev}`)
    if (v.target_id) details.push(`- **Target workspace:** ${targetURLs.get(v.target_id) ?? v.target_id}`)
    if (v.endpoint) details.push(`- **Endpoint:** ${v.endpoint}`)
    if (v.cwe_id) details.push(`- **CWE:** ${v.cwe_id}`)
    if (v.attack_vector) details.push(`- **Attack Vector:** ${v.attack_vector}`)
    if (v.business_impact) details.push(`- **Business Impact:** ${v.business_impact}`)
    details.push("")
    details.push(`**Description:** ${v.description}`)
    if (v.steps_to_reproduce) {
      details.push("")
      details.push(`**Steps to Reproduce:** ${v.steps_to_reproduce}`)
    }
    if (v.poc) {
      details.push("")
      details.push("**Proof of Concept:**")
      details.push("```")
      details.push(v.poc)
      details.push("```")
    }
    if (v.recommendation) {
      details.push("")
      details.push(`**Recommendation:** ${v.recommendation}`)
    }
  }

  return lines.join("\n") + "\n" + details.join("\n")
}

function formatCoverage(
  coverage: Intel.CoverageReport,
  assets: Intel.AssetCoverage[],
  notes: CoverageNote.Info[] = [],
): string {
  const lines: string[] = [
    "## Testing Coverage",
    "",
    "### Overall",
    `- Total Intel Entries: ${coverage.totalEntries} (${coverage.entriesWithChecklist} with VRT checklists)`,
    `- VRT Checks: ${coverage.completedChecks}/${coverage.totalChecks} completed (${coverage.coveragePercent}%)`,
    `- Weighted Coverage: ${coverage.weightedCoveragePercent}% (confidence-adjusted)`,
    `- Vulnerable Checks: ${coverage.vulnerableChecks}`,
    `- Pending Checks: ${coverage.pendingChecks}`,
  ]

  if (assets.length > 0) {
    lines.push("")
    lines.push("### Per-Asset Breakdown")
    lines.push("")
    lines.push("| Asset | Entries | Checks | Completed | Vulnerable | Coverage |")
    lines.push("|-------|---------|--------|-----------|------------|----------|")
    for (const a of assets) {
      lines.push(
        `| ${a.asset} | ${a.totalEntries} | ${a.totalChecks} | ${a.completedChecks} | ${a.vulnerableChecks} | ${a.coveragePercent}% |`,
      )
    }
  }

  // What each tester actually recorded as tested, grouped by scope (asset). This is the
  // proxy-lane test memory (coverage_note) — distinct from the VRT checklist above, which
  // is only populated by the methodology lane.
  if (notes.length > 0) {
    const byAsset = new Map<string, CoverageNote.Info[]>()
    for (const n of notes) {
      const arr = byAsset.get(n.asset)
      if (arr) arr.push(n)
      else byAsset.set(n.asset, [n])
    }
    lines.push("")
    lines.push("### Tested (coverage notes)")
    lines.push(`What testers recorded as tested, by scope and class (${notes.length} notes).`)
    for (const [asset, arr] of byAsset) {
      lines.push("")
      lines.push(`**${asset}**`)
      for (const n of arr) lines.push(`- _[${n.scope}/${n.class}]_ ${n.note}${n.testedBy ? ` — ${n.testedBy}` : ""}`)
    }
  }

  if (coverage.redFlags.length > 0) {
    lines.push("")
    lines.push("### Red Flags")
    for (const flag of coverage.redFlags) {
      lines.push(`- **[${flag.severity.toUpperCase()}]** ${flag.message}`)
    }
  }

  return lines.join("\n")
}

function formatMethodologySection(state: Methodology.State, targetScoped = false): string {
  const lines: string[] = [
    targetScoped ? "## Methodology Progress (session-wide)" : "## Methodology Progress",
    ...(targetScoped ? ["", "*This phase progress covers the full session, not only the selected target workspaces.*"] : []),
    "",
    "| Phase | Status | Deliverables |",
    "|-------|--------|-------------|",
  ]

  const statusIcon = (s: string) =>
    s === "completed" ? "DONE" : s === "in_progress" ? "ACTIVE" : s === "blocked" ? "BLOCKED" : "TODO"

  for (const phase of state.phases) {
    lines.push(`| ${phase.name} | [${statusIcon(phase.status)}] | ${phase.deliverableCount} |`)
  }

  lines.push("")
  lines.push(`Progress: ${state.completionPercent}% (${state.completedCount}/${state.totalCount} phases)`)

  const blocking = state.violations.filter((v) => v.severity === "blocking")
  if (blocking.length > 0) {
    lines.push("")
    lines.push("### Blocking Violations")
    for (const v of blocking) lines.push(`- **[${v.gate}]** ${v.message}`)
  }

  const warnings = state.violations.filter((v) => v.severity === "warning")
  if (warnings.length > 0) {
    lines.push("")
    lines.push("### Warnings")
    for (const v of warnings) lines.push(`- [${v.gate}] ${v.message}`)
  }

  return lines.join("\n")
}

function formatChains(chains: Chain.Candidate[]): string {
  const active = chains.filter((c) => c.status !== "disproven")
  if (active.length === 0) return "## Vulnerability Chains\n\nNo chain opportunities detected."

  const sorted = [...active].sort((a, b) => {
    const statusOrder = { confirmed: 0, testing: 1, detected: 2 } as Record<string, number>
    const sa = statusOrder[a.status] ?? 3
    const sb = statusOrder[b.status] ?? 3
    if (sa !== sb) return sa - sb
    return b.confidence - a.confidence
  })

  const lines: string[] = [
    `## Vulnerability Chains (${active.length} detected)`,
    "",
    "| Pattern | Entries | Impact | Severity | Confidence | Status |",
    "|---------|---------|--------|----------|------------|--------|",
  ]

  for (const c of sorted) {
    lines.push(
      `| ${c.pattern} | ${c.entryTitles.join(" + ")} | ${c.expectedImpact} | ${c.severity} | ${c.confidence}% | ${c.status} |`,
    )
  }

  return lines.join("\n")
}

function formatAttackSurface(intel: Intel.Entry[], requests: Request.Info[], assets: string[]): string {
  const lines: string[] = [`## Attack Surface`, "", `### Discovered Assets (${assets.length} unique)`]

  const byType = new Map<string, Intel.Entry[]>()
  for (const entry of intel) {
    const list = byType.get(entry.type) ?? []
    list.push(entry)
    byType.set(entry.type, list)
  }

  for (const [type, entries] of byType) {
    lines.push("")
    lines.push(`**${type}** (${entries.length}):`)
    for (const e of entries.slice(0, 20)) {
      lines.push(`- ${e.title} (${e.asset})${e.severity ? ` [${e.severity}]` : ""}`)
    }
    if (entries.length > 20) lines.push(`- ... and ${entries.length - 20} more`)
  }

  if (requests.length > 0) {
    const byMethod = new Map<string, number>()
    const hosts = new Set<string>()
    for (const r of requests) {
      byMethod.set(r.method, (byMethod.get(r.method) ?? 0) + 1)
      if (r.host) hosts.add(r.host)
    }

    lines.push("")
    lines.push("### Request Summary")
    lines.push(`- Total Requests: ${requests.length}`)
    lines.push(
      `- Methods: ${[...byMethod.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([m, c]) => `${m}:${c}`)
        .join(", ")}`,
    )
    if (hosts.size > 0) lines.push(`- Unique Hosts: ${hosts.size}`)
  }

  return lines.join("\n")
}

function formatTimeline(vulns: Vulnerability.Info[], session: { time: { created: number; updated: number } }): string {
  const lines: string[] = ["## Assessment Timeline", ""]

  const startDate = new Date(session.time.created).toISOString()
  lines.push(`| Time | Event | Severity |`)
  lines.push(`|------|-------|----------|`)
  lines.push(`| ${startDate} | Assessment started | — |`)

  const sorted = [...vulns]
    .filter((v) => v.time?.created)
    .sort((a, b) => (a.time?.created ?? 0) - (b.time?.created ?? 0))

  for (const v of sorted) {
    const time = new Date(v.time!.created).toISOString()
    lines.push(`| ${time} | ${v.title} | ${v.severity.toUpperCase()} |`)
  }

  const endDate = new Date(session.time.updated).toISOString()
  lines.push(`| ${endDate} | Assessment completed | — |`)

  return lines.join("\n")
}

function formatAgentPerformance(rootSession: string, targetScoped = false): string {
  const lines: string[] = [
    targetScoped ? "## Agent Performance (session-wide)" : "## Agent Performance",
    ...(targetScoped ? ["", "*Performance metrics are session-level and are not attributed to only the selected workspaces.*"] : []),
    "",
    "| Agent | Codename | Missions | Findings | Chains | Score | Morale |",
    "|-------|----------|----------|----------|--------|-------|--------|",
  ]

  for (const name of AGENT_NAMES) {
    const stats = AgentPerformance.getOrCreate(rootSession, name)
    const codename = AGENT_CODENAMES[name] ?? name
    lines.push(
      `| ${name} | ${codename} | ${stats.missionsCompleted} | ${stats.findingsReported} | ${stats.chainsContributed} | ${stats.performanceScore} | ${stats.morale} |`,
    )
  }

  return lines.join("\n")
}

function formatValidationSection(gates: ReturnType<typeof Validation.runAllGates>): string {
  const lines: string[] = [
    "## Validation Status",
    "",
    `- **Overall:** ${gates.overallPassed ? "PASSED" : "FAILED"}`,
    `- **Blocking Violations:** ${gates.blockingViolations.length}`,
    `- **Warning Violations:** ${gates.warningViolations.length}`,
  ]

  if (gates.blockingViolations.length > 0) {
    lines.push("")
    lines.push("### Blocking")
    for (const v of gates.blockingViolations) {
      lines.push(`- **[${v.gate}]** ${v.message}`)
    }
  }

  if (gates.warningViolations.length > 0) {
    lines.push("")
    lines.push("### Warnings")
    for (const v of gates.warningViolations) {
      lines.push(`- [${v.gate}] ${v.message}`)
    }
  }

  return lines.join("\n")
}
