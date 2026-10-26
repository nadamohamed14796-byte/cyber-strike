import z from "zod"
import { Tool } from "./tool"
import { Methodology } from "../methodology/methodology"
import { Intel } from "../methodology/intel"
import { Chain } from "../methodology/chain"
import { Validation } from "../methodology/validation"
import { Session } from "../session"

type PendingCoverageItem = Intel.CoverageReport["untestedItems"][number]

export function pendingCoveragePage(
  items: PendingCoverageItem[],
  cursor: { entryID?: string; category?: string },
  limit: number,
) {
  const sorted = items.slice().sort((a, b) => {
    if (a.entryID !== b.entryID) return a.entryID < b.entryID ? -1 : 1
    if (a.vrtCategory !== b.vrtCategory) return a.vrtCategory < b.vrtCategory ? -1 : 1
    return a.asset < b.asset ? -1 : a.asset > b.asset ? 1 : 0
  })
  const afterCursor = sorted.filter((item) => {
    if (!cursor.entryID) return true
    if (item.entryID !== cursor.entryID) return item.entryID > cursor.entryID
    return item.vrtCategory > (cursor.category ?? "")
  })
  const rows = afterCursor.slice(0, limit)
  const hasMore = afterCursor.length > rows.length
  const last = rows[rows.length - 1]
  return {
    rows,
    hasMore,
    nextCursor: hasMore && last ? { entryID: last.entryID, category: last.vrtCategory } : undefined,
  }
}

export const MethodologyStatusTool = Tool.define("methodology_status", {
  description:
    "Get the current methodology state, coverage report, chain opportunities, and validation status. Use this to check progress, identify gaps, and decide what to test next. Shows which phases are complete, which have blocking violations, per-asset coverage, and detected vulnerability chains. When include_pending_checks=true, returns a cursor-stable page of exact pending VRT entry/category rows for final coverage reconciliation.",
  parameters: z.object({
    include_validation: z
      .boolean()
      .optional()
      .default(false)
      .describe("Include full validation gate results (evidence quality, triager checks)"),
    scope_items: z
      .array(z.string())
      .optional()
      .describe("Scope items for validation gates (domains, wildcards, CIDRs)"),
    include_pending_checks: z
      .boolean()
      .optional()
      .default(false)
      .describe("Include a page of exact pending VRT coverage rows so completed work can be reconciled without creating duplicate entries."),
    pending_after_entry_id: z
      .string()
      .optional()
      .describe("Stable cursor from the previous page: entry ID of its last pending row."),
    pending_after_category: z
      .string()
      .optional()
      .describe("Stable cursor from the previous page: VRT category paired with pending_after_entry_id."),
    pending_limit: z
      .number()
      .int()
      .min(1)
      .max(100)
      .optional()
      .default(25)
      .describe("Rows per pending-check page. Follow the returned cursor until hasMore is false; this pages the listing and does not limit coverage work."),
  }),
  async execute(params, ctx) {
    const rootSession = Session.root(ctx.sessionID)
    const state = Methodology.computeState(rootSession)
    const coverage = Intel.computeCoverage(rootSession)
    const chains = Chain.load(rootSession)

    const sections: string[] = []

    // 1. Methodology progress
    sections.push(Methodology.formatForPrompt(rootSession))

    // 2. Coverage
    sections.push("")
    sections.push(Intel.formatCoverageForPrompt(coverage))

    // 3. Chains
    const chainPrompt = Chain.formatForPrompt(chains)
    if (chainPrompt) {
      sections.push("")
      sections.push(chainPrompt)
    }

    // 4. Validation gates (optional)
    if (params.include_validation) {
      const scopeItems = params.scope_items ?? []
      const gates = Validation.runAllGates(rootSession, scopeItems)
      sections.push("")
      sections.push(gates.summary)
    }

    // 5. Per-asset coverage
    const assetCoverages = Intel.computePerAssetCoverage(rootSession)
    if (assetCoverages.length > 0) {
      sections.push("")
      sections.push("## Per-Asset Coverage")
      for (const ac of assetCoverages) {
        sections.push(
          `- ${ac.asset}: ${ac.coveragePercent}% (${ac.completedChecks}/${ac.totalChecks} checks, ${ac.vulnerableChecks} vuln)`,
        )
      }
    }

    // 6. Optional, cursor-stable list of pending VRT checks for final coverage reconciliation.
    let pendingPage: Intel.CoverageReport["untestedItems"] = []
    let pendingHasMore = false
    let nextPendingEntryID: string | undefined
    let nextPendingCategory: string | undefined
    if (params.include_pending_checks) {
      const page = pendingCoveragePage(coverage.untestedItems, {
        entryID: params.pending_after_entry_id,
        category: params.pending_after_category,
      }, params.pending_limit)
      pendingPage = page.rows
      pendingHasMore = page.hasMore
      nextPendingEntryID = page.nextCursor?.entryID
      nextPendingCategory = page.nextCursor?.category
      sections.push("")
      sections.push(`## Pending VRT Checks (${pendingPage.length} shown; ${coverage.pendingChecks} total pending)`)
      for (const item of pendingPage) {
        sections.push(`- Entry ${item.entryID} | ${item.vrtCategory} | ${item.asset} | ${item.entryTitle}`)
      }
      if (pendingHasMore && nextPendingEntryID && nextPendingCategory) {
        sections.push(`Next cursor: pending_after_entry_id=${nextPendingEntryID}; pending_after_category=${nextPendingCategory}`)
      } else {
        sections.push("Pending-check listing complete.")
      }
    }

    // 7. Next steps
    if (state.currentPhase) {
      const directives = Methodology.getPhaseDirectives(state.currentPhase)
      if (directives) {
        sections.push("")
        sections.push("## Next Steps")
        sections.push(directives)
      }
    }

    return {
      title: `Methodology: ${state.completionPercent}% | Coverage: ${coverage.coveragePercent}%`,
      output: sections.join("\n"),
      metadata: {
        completionPercent: state.completionPercent,
        coveragePercent: coverage.coveragePercent,
        totalEntries: coverage.totalEntries,
        activeChains: chains.filter((c) => c.status === "detected" || c.status === "testing").length,
        blockingViolations: state.violations.filter((v) => v.severity === "blocking").length,
        pendingChecks: coverage.pendingChecks,
        pendingReturned: pendingPage.length,
        pendingHasMore,
        nextPendingEntryID,
        nextPendingCategory,
      },
    }
  },
})
