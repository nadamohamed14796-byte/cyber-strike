import fs from "node:fs/promises"
import path from "node:path"
import z from "zod"
import { Session } from "../session"
import { TargetMemory, USER_CONFIRMED_SCOPE_SOURCE } from "../target"
import {
  RECON_PHASES as PHASES,
  invalidateReconDownstreamPhases,
  initialReconRun as initialRun,
  parseReconRun as parseRun,
  reconRunID,
  type ReconPhase,
  type ReconPhaseStatus,
  type ReconRunManifest as ReconRun,
} from "../target/recon-gate"
import { Tool } from "./tool"

export { reconRunID, unresolvedReconPrerequisites } from "../target/recon-gate"
export type { ReconPhase, ReconPhaseRecord, ReconPhaseStatus } from "../target/recon-gate"

function terminal(status: ReconPhaseStatus): boolean {
  return status === "complete" || status === "unavailable" || status === "deferred"
}

const DISCOVERY_TERMINAL_STATUSES = new Set([
  "success",
  "zero-results",
  "failed",
  "unavailable",
  "blocked",
  "skipped",
])

export type AssetDiscoveryLedgerValidation = {
  valid: boolean
  reason?: string
  roots?: number
  sourcePairs?: number
  uniqueHosts?: number
  gaps?: number
}

/**
 * Verify the existing passive-discovery ledger before allowing asset_discovery
 * to be marked complete. The source names are intentionally not allowlisted:
 * any useful source can be recorded, but every root/source pair must be terminal.
 */
export function validateAssetDiscoveryLedger(
  rawLedger: string,
  rawHosts: string,
): AssetDiscoveryLedgerValidation {
  let ledger: Record<string, unknown>
  try {
    const parsed: unknown = JSON.parse(rawLedger)
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { valid: false, reason: "The source ledger must contain a JSON object." }
    }
    ledger = parsed as Record<string, unknown>
  } catch (error) {
    return { valid: false, reason: "The source ledger is not valid JSON: " + (error instanceof Error ? error.message : String(error)) }
  }

  const missingSchemaFields = [
    ...(ledger.schema_version === 1 ? [] : ["schema_version: 1"]),
    ...(Array.isArray(ledger.roots) ? [] : ["roots: string[]"]),
    ...(Array.isArray(ledger.sources) ? [] : ["sources: root/source records[]"]),
    ...(Array.isArray(ledger.hosts) ? [] : ["hosts: normalized host records[]"]),
  ]
  if (missingSchemaFields.length) {
    const observedKeys = Object.keys(ledger).sort()
    return {
      valid: false,
      reason: "The source ledger schema is invalid. Missing or invalid required fields: " + missingSchemaFields.join(", ") +
        ". Expected top-level fields: schema_version, roots, sources, hosts, counts, run_status. " +
        "Observed top-level fields: " + (observedKeys.length ? observedKeys.join(", ") : "(none)") +
        ". Repair the existing JSON using .cyberstrike/skill/TOOLING_CATALOG.md; do not guess a new schema or rerun successful collectors.",
    }
  }
  const roots = ledger.roots as unknown[]
  const sources = ledger.sources as unknown[]
  if (!roots.length || roots.some((root) => typeof root !== "string" || !root.trim()) || new Set(roots).size !== roots.length) {
    return { valid: false, reason: "The source ledger must contain a non-empty, duplicate-free root list." }
  }
  const rootSet = new Set(roots as string[])
  const sourceNames = new Set<string>()
  const pairs = new Map<string, Record<string, unknown>>()
  let gaps = 0

  for (const rawRecord of sources) {
    if (!rawRecord || typeof rawRecord !== "object" || Array.isArray(rawRecord)) {
      return { valid: false, reason: "The source ledger contains a malformed root/source record." }
    }
    const record = rawRecord as Record<string, unknown>
    const root = record.root
    const source = record.source
    const status = record.status
    if (typeof root !== "string" || !rootSet.has(root) || typeof source !== "string" || !source.trim()) {
      return { valid: false, reason: "The source ledger contains a source record with an unknown root or empty source name." }
    }
    const key = JSON.stringify([root, source])
    if (pairs.has(key)) return { valid: false, reason: "The source ledger contains a duplicate record for root " + root + " and source " + source + "." }
    pairs.set(key, record)
    sourceNames.add(source)

    if (status === "pending") {
      return {
        valid: false,
        reason: "Subdomain discovery is unfinished: root " + root + " / source " + source + " is still pending" +
          (typeof record.started_at === "string" && !record.finished_at ? " after an interrupted/in-progress attempt" : "") +
          ". Resume this saved ledger before completing asset_discovery.",
        roots: roots.length,
        sourcePairs: sources.length,
      }
    }
    if (typeof status !== "string" || !DISCOVERY_TERMINAL_STATUSES.has(status)) {
      return { valid: false, reason: "The source ledger has a non-terminal or unknown status for root " + root + " / source " + source + "." }
    }
    if (typeof record.finished_at !== "string" || !record.finished_at.trim()) {
      return { valid: false, reason: "The source ledger has no terminal timestamp for root " + root + " / source " + source + "." }
    }
    if (status !== "skipped" && (!Number.isInteger(record.attempt_count) || Number(record.attempt_count) < 1)) {
      return { valid: false, reason: "The source ledger has no recorded attempt for root " + root + " / source " + source + "." }
    }
    const metricNames = ["raw_records", "valid_observations", "unique_hosts", "duplicate_observations", "rejected_records"]
    for (const name of metricNames) {
      const value = record[name]
      if (!Number.isSafeInteger(value) || Number(value) < 0) {
        return { valid: false, reason: "The source ledger has an invalid " + name + " count for root " + root + " / source " + source + "." }
      }
    }
    const rawRecords = Number(record.raw_records)
    const validObservations = Number(record.valid_observations)
    const uniqueSourceHosts = Number(record.unique_hosts)
    const duplicateObservations = Number(record.duplicate_observations)
    const rejectedRecords = Number(record.rejected_records)
    if (rawRecords !== validObservations + rejectedRecords) {
      return { valid: false, reason: "The source ledger counts do not reconcile for root " + root + " / source " + source + ": raw_records must equal valid_observations + rejected_records." }
    }
    if (validObservations !== uniqueSourceHosts + duplicateObservations) {
      return { valid: false, reason: "The source ledger counts do not reconcile for root " + root + " / source " + source + ": valid_observations must equal unique_hosts + duplicate_observations." }
    }
    if (!Array.isArray(record.hosts) || record.hosts.some((host) => typeof host !== "string") ||
        new Set(record.hosts).size !== record.hosts.length || record.hosts.length !== uniqueSourceHosts) {
      return { valid: false, reason: "The source host list does not match its unique_hosts count for root " + root + " / source " + source + "." }
    }
    const intentionallyNotSelected = status === "skipped" && record.skipped_by_selection === true
    if (["failed", "unavailable", "blocked"].includes(status) || (status === "skipped" && !intentionallyNotSelected)) {
      gaps++
    }
    if (["failed", "unavailable", "blocked", "skipped"].includes(status)) {
      const explanation = record.error ?? record.reason
      if (typeof explanation !== "string" || !explanation.trim()) {
        return { valid: false, reason: "The " + status + " source " + source + " for root " + root + " has no recorded reason." }
      }
    }
  }

  if (!sourceNames.size) return { valid: false, reason: "The source ledger contains no source attempts." }
  for (const root of roots as string[]) {
    for (const source of sourceNames) {
      if (!pairs.has(JSON.stringify([root, source]))) {
        return { valid: false, reason: "The source ledger is missing root/source coverage for " + root + " / " + source + "." }
      }
    }
  }

  const counts = ledger.counts
  if (!counts || typeof counts !== "object" || Array.isArray(counts)) {
    return { valid: false, reason: "The source ledger has no reconciled counts." }
  }
  const savedCounts = counts as Record<string, unknown>
  if (savedCounts.roots !== roots.length || savedCounts.sources_pending !== 0) {
    return { valid: false, reason: "The saved source counters do not reconcile with the root list or still report pending work." }
  }

  const hostRecords = ledger.hosts as unknown[]
  const uniqueHosts: string[] = []
  for (const value of hostRecords) {
    if (!value || typeof value !== "object" || Array.isArray(value) || typeof (value as Record<string, unknown>).host !== "string") {
      return { valid: false, reason: "The source ledger contains a malformed normalized host record." }
    }
    uniqueHosts.push((value as Record<string, unknown>).host as string)
  }
  if (new Set(uniqueHosts).size !== uniqueHosts.length || savedCounts.unique_hosts !== uniqueHosts.length) {
    return { valid: false, reason: "The normalized host inventory contains duplicates or its saved unique-host count does not reconcile." }
  }

  const sourceRows = sources as Array<Record<string, unknown>>
  const expectedCounts: Record<string, number> = {
    sources_attempted: sourceRows.filter((item) => Number.isInteger(item.attempt_count) && Number(item.attempt_count) > 0).length,
    sources_pending: sourceRows.filter((item) => item.status === "pending").length,
    sources_not_started: sourceRows.filter((item) => item.status === "pending" && Number(item.attempt_count ?? 0) === 0).length,
    sources_running_or_interrupted: sourceRows.filter((item) =>
      item.status === "pending" && Number(item.attempt_count ?? 0) > (Array.isArray(item.attempt_history) ? item.attempt_history.length : 0),
    ).length,
    sources_success: sourceRows.filter((item) => item.status === "success").length,
    sources_zero_results: sourceRows.filter((item) => item.status === "zero-results").length,
    sources_failed: sourceRows.filter((item) => item.status === "failed").length,
    sources_blocked: sourceRows.filter((item) => item.status === "blocked").length,
    sources_unavailable: sourceRows.filter((item) => item.status === "unavailable").length,
    sources_skipped: sourceRows.filter((item) => item.status === "skipped" && item.skipped_by_selection !== true).length,
    sources_not_selected: sourceRows.filter((item) => item.status === "skipped" && item.skipped_by_selection === true).length,
    unique_hosts: uniqueHosts.length,
    duplicate_observations: sourceRows.reduce((total, item) => {
      const history = Array.isArray(item.attempt_history) ? item.attempt_history : []
      const duplicateCount = history.length
        ? history.reduce((sum: number, attempt: unknown) => {
            if (!attempt || typeof attempt !== "object" || Array.isArray(attempt)) return sum
            const value = (attempt as Record<string, unknown>).duplicate_observations
            return sum + (typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : 0)
          }, 0)
        : (typeof item.duplicate_observations === "number" && Number.isFinite(item.duplicate_observations) && item.duplicate_observations >= 0 ? item.duplicate_observations : 0)
      return total + duplicateCount
    }, 0),
  }
  for (const [name, expected] of Object.entries(expectedCounts)) {
    const actual = savedCounts[name]
    // Older complete schema-v1 ledgers predate sources_not_selected; that count
    // is backward-compatible only when the rows themselves show none.
    if (name === "sources_not_selected" && actual === undefined && expected === 0) continue
    if (actual !== expected) {
      return { valid: false, reason: "The saved source counter " + name + " is " + String(actual) + ", but the ledger records " + expected + "." }
    }
  }

  const expectedStatus = gaps ? "finished_with_gaps" : "complete"
  if (ledger.run_status !== expectedStatus) {
    return { valid: false, reason: "The source ledger run_status is " + String(ledger.run_status) + ", but terminal source outcomes require " + expectedStatus + "." }
  }

  const expectedHosts = [...uniqueHosts].sort()
  const inventoryLines = rawHosts.split(/\r?\n/).map((host) => host.trim()).filter(Boolean)
  if (new Set(inventoryLines).size !== inventoryLines.length ||
      JSON.stringify([...inventoryLines].sort()) !== JSON.stringify(expectedHosts)) {
    return { valid: false, reason: "subdomains.txt does not exactly match the deduplicated hosts in the source ledger; regenerate the TXT inventory from the saved ledger." }
  }

  return {
    valid: true,
    roots: roots.length,
    sourcePairs: ledger.sources.length,
    uniqueHosts: uniqueHosts.length,
    gaps,
  }
}

export const RECON_PHASE_ARTIFACT_AREAS: Partial<Record<ReconPhase, readonly string[]>> = {
  asset_discovery: ["assets"],
  live_hosts_ports: ["recon"],
  url_collection: ["urls"],
  directory_fuzzing: ["directories"],
  parameter_discovery: ["parameters"],
  parameter_fuzzing: ["parameters"],
  // correlate_javascript atomically writes a source graph, endpoint candidates, and a Tester Survey.
  javascript_analysis: ["javascript", "endpoints", "testing"],
  endpoint_inventory: ["endpoints"],
  vulnerability_testing: ["testing", "findings", "evidence"],
  reporting: ["reports"],
}

export const RECON_PHASE_REQUIRED_FLAT_ARTIFACTS: Partial<Record<ReconPhase, readonly string[]>> = {
  // These are the two canonical handoff files consumed by endpoint_inventory and final reporting.
  javascript_analysis: ["javascript-analysis.md", "endpoints.txt"],
  endpoint_inventory: ["endpoints.txt"],
}

export function missingRequiredReconArtifacts(phase: ReconPhase, reportedPaths: readonly string[]): string[] {
  const normalized = new Set(reportedPaths.map((item) => item.replace(/\\/g, "/").replace(/^\.\/+/, "")))
  return [...(RECON_PHASE_REQUIRED_FLAT_ARTIFACTS[phase] ?? [])].filter((required) => !normalized.has(required))
}

export type ReconBeginDisposition = "start" | "resume_existing" | "already_resolved"

export function reconBeginDisposition(status: ReconPhaseStatus, phase: ReconPhase): ReconBeginDisposition {
  if (status === "running") return "resume_existing"
  if (status === "complete" || (status === "unavailable" && phase !== "scope_validation" && phase !== "workspace_setup")) {
    return "already_resolved"
  }
  return "start"
}

const Parameters = z.object({
  action: z.enum(["status", "begin", "complete", "block", "fail", "unavailable", "defer"]),
  target_url: z.string().min(1).describe("Exact existing root or asset workspace URL"),
  scope_validation_target: z.string().min(1).optional().describe("Absolute HTTP(S) URL of the actual starting asset that passed scope_check; required when completing scope_validation. The program-root workspace URL may be only a policy container."),
  phase: z.enum(PHASES).optional(),
  summary: z.string().max(4000).optional(),
  reason: z.string().max(2000).optional(),
  counts: z.record(z.string(), z.number().finite().nonnegative()).optional(),
  artifacts: z.array(z.string().min(1)).optional(),
})

export const ReconCheckpointTool = Tool.define<typeof Parameters, Tool.Metadata>("recon_checkpoint", {
  description: [
    "Lightweight progress tracking for reconnaissance, not a tool allowlist. Use status when helpful and begin/complete to record progress, but ordinary recon tools are not blocked by stale phase order or missing earlier phase records. If a phase is already running, resume it without beginning it again. Scope checks remain enforced by the runtime.",
    "Suggested workflow: scope_validation → workspace_setup → asset_discovery → live_hosts_ports → url_collection → directory_fuzzing → parameter_discovery → parameter_fuzzing → javascript_analysis → endpoint_inventory → reporting. This is progress guidance, not a gate on ordinary recon tools.",
    "A normal recon run defers vulnerability_testing and proceeds to reporting; only an explicit user request may begin testing after endpoint_inventory. Reopening testing invalidates reporting, which must be regenerated. Never launch scanners/session_scan automatically. Save wordlists/settings/results for directory and parameter phases; link JavaScript sources, request shapes, and correlation evidence for JavaScript analysis. Reporting requires the exact verified artifact reports/recon-final.md.",
    "Keep useful phase records and verified artifact paths, but do not let a missing optional source ledger or stale ordinary phase status block reconnaissance. Scope validation and workspace setup remain required; JavaScript and endpoint inventories should be recorded when produced. Vulnerability testing remains opt-in and requires completed endpoint inventory.",
    "This tool enforces phase order, not request authorization. Verify the saved scope; when it is new/changed or unresolved, call scope_check once for the actual starting asset with target_url selecting the canonical program-root workspace. Complete scope_validation only by supplying scope_validation_target with that exact absolute HTTP(S) asset URL; runtime rechecks and persists it, then revalidates it on resume. Do not check the root container merely because it identifies the workspace. Active-request tools still enforce persisted scope for every concrete request.",
  ].join("\n"),
  parameters: Parameters,
  async execute(params, ctx) {
    try {
      const requestedWorkspace = await TargetMemory.get(params.target_url)
      if (!requestedWorkspace) return { title: "Recon checkpoint unavailable", output: "No existing target workspace. Initialize the canonical target with target_workspace first.", metadata: { saved: false, reason: "workspace_missing" } }
      const allWorkspaces = TargetMemory.list()
      const byID = new Map(allWorkspaces.map((item) => [item.id, item]))
      let workspace = requestedWorkspace
      const visitedParents = new Set<string>()
      while (workspace.parentTargetID && !visitedParents.has(workspace.id)) {
        visitedParents.add(workspace.id)
        const parent = byID.get(workspace.parentTargetID)
        if (!parent) break
        workspace = parent
      }

      const sessionID = Session.root(ctx.sessionID)
      // One resumable run per canonical target workspace, including across new root sessions.
      const runID = reconRunID(workspace.id)
      const filename = "recon-" + runID + ".json"
      const relativePath = "runs/" + filename
      const absolutePath = path.join(workspace.workspacePath, relativePath)
      let run: ReconRun
      try {
        run = parseRun(await fs.readFile(absolutePath, "utf-8"), workspace.id, workspace.targetURL)
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
        run = initialRun(workspace.targetURL, workspace.id, sessionID)
      }
      // The active root session can change after a stop/resume. Keep the manifest's
      // current owner up to date without creating a duplicate run for this target.
      run.sessionID = sessionID

      // A prior "complete" flag is not authorization evidence by itself. Older
      // checkpoints did not persist the actual asset checked, and saved scope can
      // change between runs. Revalidate the recorded starting asset before trusting
      // this checkpoint or allowing any later phase to proceed.
      if (run.phases.scope_validation.status === "complete") {
        const validatedTarget = run.phases.scope_validation.scopeValidationTarget
        let invalidationReason: string | undefined
        if (!validatedTarget) {
          invalidationReason = "The saved scope_validation checkpoint has no recorded starting asset; scope must be checked again."
        } else {
          try {
            const decision = await TargetMemory.checkURLScope(validatedTarget)
            if (!decision.allowed || !decision.workspace) {
              invalidationReason = "The previously validated starting asset no longer passes persisted scope: " + decision.reason
            }
          } catch (error) {
            invalidationReason = "The previously validated starting asset could not be revalidated: " +
              (error instanceof Error ? error.message : String(error))
          }
        }
        if (invalidationReason) {
          run.phases.scope_validation = {
            ...run.phases.scope_validation,
            status: "pending",
            finishedAt: undefined,
            reason: invalidationReason,
          }
          invalidateReconDownstreamPhases("scope_validation", run.phases, invalidationReason)
          run.currentPhase = "scope_validation"
          run.updatedAt = new Date().toISOString()
          await TargetMemory.writeWorkspaceFile(workspace, relativePath, JSON.stringify(run, null, 2) + "\n")
        }
      }

      if (params.action === "status") {
        const lines = PHASES.map((phase) => {
          const record = run.phases[phase]
          return phase + ": " + record.status +
            (record.summary ? " — " + record.summary : "") +
            (record.reason ? " (reason: " + record.reason + ")" : "") +
            (record.artifacts?.length ? " [artifacts: " + record.artifacts.join(", ") + "]" : "")
        })
        return { title: "Recon run status", output: ["Target: " + run.targetURL, "Manifest: " + absolutePath, "Current phase: " + (run.currentPhase ?? "none"), ...lines].join("\n"), metadata: { saved: true, target_id: workspace.id, run_id: runID, manifest: absolutePath, current_phase: run.currentPhase, phases: run.phases } }
      }

      if (!params.phase) return { title: "Recon checkpoint rejected", output: "phase is required for this action.", metadata: { saved: false, reason: "phase_required" } }
      const phase = params.phase
      const record = run.phases[phase]
      if (params.action === "defer" && phase !== "vulnerability_testing") {
        return { title: "Recon checkpoint rejected", output: "Only the optional vulnerability_testing phase may be deferred. Scope validation, workspace setup, discovery, JavaScript analysis, endpoint inventory, and reporting must not be deferred.", metadata: { saved: false, reason: "phase_not_deferable", phase } }
      }

      if (params.action === "begin") {
        const disposition = reconBeginDisposition(record.status, phase)
        if (disposition === "already_resolved") {
          return {
            title: "Recon phase already resolved",
            output: phase + " is already " + record.status + ". Inspect its artifacts; do not repeat expensive work unless new evidence invalidates this checkpoint.",
            metadata: { saved: false, reason: "phase_already_resolved", phase, status: record.status },
          }
        }
        if (phase !== "scope_validation" && phase !== "workspace_setup") {
          // The root workspace can represent a bug-bounty program/policy container,
          // not an in-scope hostname (for example, a program that authorizes unrelated
          // domains). Validate that its saved authorization manifest is configured;
          // individual candidate URLs must still pass checkURLScope before active use.
          let rootScope
          try {
            rootScope = await TargetMemory.getScope(workspace.targetURL)
          } catch (error) {
            return { title: "Recon phase blocked by persisted scope", output: "Cannot begin " + phase + " because the root authorization manifest could not be loaded: " + (error instanceof Error ? error.message : String(error)), metadata: { saved: false, reason: "persisted_scope_invalid" } }
          }
          if (!rootScope || rootScope.status !== "configured" || rootScope.scopeItems.length === 0) {
            return { title: "Recon phase blocked by persisted scope", output: "Cannot begin " + phase + " because the canonical program workspace has no configured, non-empty authorization scope. Configure and review the official scope before continuing.", metadata: { saved: false, reason: "persisted_scope_unconfigured" } }
          }
        }
        // Ordinary recon phases are progress markers, not hard gates. The agent may
        // use any suitable recon capability when useful evidence becomes available.
        // Keep only the explicit testing handoff gated by completed endpoint inventory.
        if (phase === "vulnerability_testing") {
          const required = ["scope_validation", "workspace_setup", "endpoint_inventory"] as const
          const unresolved = required.filter((item) => run.phases[item].status !== "complete")
          if (unresolved.length) {
            return { title: "Testing checkpoint requires endpoint inventory", output: "Begin vulnerability_testing only after scope validation, workspace setup, and endpoint inventory are complete: " + unresolved.map((item) => item + "=" + run.phases[item].status).join(", "), metadata: { saved: false, reason: "testing_prerequisites_unresolved", unresolved } }
          }
        }
        if (disposition === "resume_existing") {
          return {
            title: "Recon phase already running",
            output: phase + " is already running since " + (record.startedAt ?? "an earlier checkpoint") + ". Do not begin it again. Reconcile existing artifacts and resume only unfinished sources/items; do not repeat successful work. When the phase is genuinely finished, call complete with verified artifacts, or use block/fail with a concrete reason.",
            metadata: { saved: false, reason: "phase_already_running", phase, status: record.status, started_at: record.startedAt, artifacts: record.artifacts ?? [] },
          }
        }
        run.phases[phase] = { ...record, status: "running", startedAt: record.startedAt ?? new Date().toISOString(), finishedAt: undefined, reason: undefined, summary: params.summary ?? record.summary }
        if (phase === "vulnerability_testing" && record.status === "deferred") {
          invalidateReconDownstreamPhases(
            phase,
            run.phases,
            "Regenerate this downstream checkpoint after vulnerability_testing was explicitly reopened.",
          )
        }
        run.currentPhase = phase
      } else {
        if (record.status !== "running") {
          return { title: "Recon checkpoint rejected", output: "Phase " + phase + " is " + record.status + ", not running. Call begin first; the manifest was not changed.", metadata: { saved: false, reason: "phase_not_running", phase, status: record.status } }
        }
        if ((params.action === "block" || params.action === "fail" || params.action === "unavailable" || params.action === "defer") && !params.reason?.trim()) {
          return { title: "Recon checkpoint rejected", output: "A reason is required to mark a phase blocked, failed, unavailable, or deferred.", metadata: { saved: false, reason: "reason_required" } }
        }
        const status: ReconPhaseStatus = params.action === "complete" ? "complete" : params.action === "block" ? "blocked" : params.action === "fail" ? "failed" : params.action === "defer" ? "deferred" : "unavailable"
        if (status === "complete" && !params.summary?.trim()) {
          return { title: "Recon checkpoint rejected", output: "A verified summary is required before a phase can be marked complete.", metadata: { saved: false, reason: "summary_required" } }
        }
        if (status === "complete" && phase === "scope_validation") {
          // Scope validation proves the official policy is saved on the canonical
          // program workspace. The root URL itself need not be in scope: the program
          // may authorize unrelated domains. Recon and testing tools must separately
          // authorize each concrete candidate URL against this manifest.
          let scope
          try {
            scope = await TargetMemory.getScope(workspace.targetURL)
          } catch (error) {
            return { title: "Scope validation rejected", output: "Cannot complete scope_validation because the saved authorization manifest is invalid: " + (error instanceof Error ? error.message : String(error)), metadata: { saved: false, reason: "scope_manifest_invalid" } }
          }
          const userConfirmedScope = Boolean(
            scope?.authorizationSource?.startsWith(USER_CONFIRMED_SCOPE_SOURCE) &&
            scope.authorizationReference === null,
          )
          if (!scope || scope.status !== "configured" || scope.scopeItems.length === 0 ||
            !scope.authorizationSource?.trim() ||
            (!scope.authorizationReference?.startsWith("https://") && !userConfirmedScope)) {
            return { title: "Scope validation rejected", output: "Cannot complete scope_validation: configure a non-empty scope manifest with saved authorization provenance. An explicit user-confirmed exact asset is a valid provenance source and does not require a separate policy URL. The root workspace URL itself does not have to be in scope.", metadata: { saved: false, reason: "scope_manifest_unconfigured" } }
          }
          const validationTarget = params.scope_validation_target?.trim()
          if (!validationTarget) {
            return { title: "Scope validation rejected", output: "Cannot complete scope_validation without scope_validation_target: provide the exact absolute HTTP(S) URL that passed scope_check. The program-root workspace URL may be only a policy container.", metadata: { saved: false, reason: "scope_validation_target_required" } }
          }
          let parsedValidationTarget: URL
          try {
            parsedValidationTarget = new URL(validationTarget)
            if ((parsedValidationTarget.protocol !== "http:" && parsedValidationTarget.protocol !== "https:") ||
                parsedValidationTarget.username || parsedValidationTarget.password) throw new Error("target must be a credential-free absolute HTTP(S) URL")
          } catch (error) {
            return { title: "Scope validation rejected", output: "scope_validation_target is invalid: " + (error instanceof Error ? error.message : String(error)), metadata: { saved: false, reason: "scope_validation_target_invalid" } }
          }
          let targetDecision: Awaited<ReturnType<typeof TargetMemory.checkURLScope>>
          try {
            targetDecision = await TargetMemory.checkURLScope(parsedValidationTarget.href)
          } catch (error) {
            return { title: "Scope validation rejected", output: "The starting asset scope check failed: " + (error instanceof Error ? error.message : String(error)), metadata: { saved: false, reason: "scope_validation_check_failed" } }
          }
          if (!targetDecision.allowed || !targetDecision.workspace) {
            return { title: "Scope validation rejected", output: "Cannot complete scope_validation: the starting asset is not authorized by the persisted manifest: " + targetDecision.reason, metadata: { saved: false, reason: "scope_validation_target_out_of_scope", target: parsedValidationTarget.href } }
          }
        }
        if (status === "complete" && phase === "workspace_setup") {
          for (const relative of ["target.json", "workspace.json", "notes.md", "scope/scope.json"]) {
            const candidate = path.join(workspace.workspacePath, relative)
            try {
              const info = await fs.lstat(candidate)
              if (!info.isFile() || info.isSymbolicLink()) throw new Error("not a regular file")
            } catch (error) {
              return { title: "Workspace setup rejected", output: "Cannot mark workspace_setup complete; required workspace file is missing or unsafe: " + relative + " (" + (error instanceof Error ? error.message : String(error)) + ")", metadata: { saved: false, reason: "workspace_integrity_failed", file: relative } }
            }
          }
          for (const relative of ["scope", "assets", "recon", "urls", "directories", "parameters", "requests", "javascript", "endpoints", "testing", "findings", "evidence", "reports", "scans", "runs", "logs", "sessions", "research"]) {
            const candidate = path.join(workspace.workspacePath, relative)
            try {
              const info = await fs.lstat(candidate)
              if (!info.isDirectory() || info.isSymbolicLink()) throw new Error("not a regular directory")
            } catch (error) {
              return { title: "Workspace setup rejected", output: "Cannot mark workspace_setup complete; required workspace directory is missing or unsafe: " + relative + " (" + (error instanceof Error ? error.message : String(error)) + ")", metadata: { saved: false, reason: "workspace_integrity_failed", directory: relative } }
            }
          }
        }
        if (status === "complete" && !["scope_validation", "workspace_setup"].includes(phase) && !params.artifacts?.length) {
          return { title: "Recon checkpoint rejected", output: "This phase requires at least one verified artifact path before it can be marked complete. If the source/tool is genuinely unavailable or there were no applicable assets, use unavailable with a reason.", metadata: { saved: false, reason: "artifact_required" } }
        }
        if (status === "complete" && params.artifacts?.length) {
          const realWorkspace = await fs.realpath(workspace.workspacePath)
          let finalReconReportVerified = false
          for (const artifact of params.artifacts) {
            if (artifact.includes("\\") || artifact.split("/").some((part) => part === "..")) {
              return { title: "Recon checkpoint rejected", output: "Artifact path must remain inside the canonical target workspace: " + artifact, metadata: { saved: false, reason: "unsafe_artifact_path" } }
            }
            const candidate = path.isAbsolute(artifact) ? path.resolve(artifact) : path.resolve(realWorkspace, artifact)
            const relative = path.relative(realWorkspace, candidate)
            if (!relative || relative === "." || relative === ".." || relative.startsWith(".." + path.sep) || path.isAbsolute(relative)) {
              return { title: "Recon checkpoint rejected", output: "Artifact path must point to a file inside the canonical target workspace: " + artifact, metadata: { saved: false, reason: "artifact_outside_workspace" } }
            }
            const resolvedArtifactPath = relative.split(path.sep).join("/")
            const requiredAreas = RECON_PHASE_ARTIFACT_AREAS[phase]
            const flatArtifacts: Partial<Record<ReconPhase, readonly string[]>> = {
              asset_discovery: ["subdomains.txt"],
              live_hosts_ports: ["live-hosts.txt", "ports.txt"],
              url_collection: ["urls.txt"],
              parameter_discovery: ["parameters.txt"],
              parameter_fuzzing: ["parameter-tests.md"],
              javascript_analysis: RECON_PHASE_REQUIRED_FLAT_ARTIFACTS.javascript_analysis ?? [],
              endpoint_inventory: RECON_PHASE_REQUIRED_FLAT_ARTIFACTS.endpoint_inventory ?? [],
              vulnerability_testing: ["findings.md"],
            }
            const isFlatArtifact = !resolvedArtifactPath.includes("/") &&
              Boolean(flatArtifacts[phase]?.includes(resolvedArtifactPath))
            if (requiredAreas && !isFlatArtifact && !requiredAreas.some((area) => resolvedArtifactPath.startsWith(area + "/"))) {
              return { title: "Recon checkpoint rejected", output: "Phase " + phase + " must save its verified output as a top-level canonical file (" + (flatArtifacts[phase]?.join(", ") ?? "none") + ") or under " + requiredAreas.map((area) => area + "/").join(", ") + "; got " + artifact, metadata: { saved: false, reason: "artifact_in_wrong_area", required_areas: requiredAreas, allowed_flat_artifacts: flatArtifacts[phase] ?? [] } }
            }
            let info
            let realArtifact: string
            try {
              info = await fs.lstat(candidate)
              if (info.isSymbolicLink() || !info.isFile()) throw new Error("not a regular file")
              realArtifact = await fs.realpath(candidate)
            } catch (error) {
              return { title: "Recon checkpoint rejected", output: "Artifact is missing, unsafe, or not a regular file: " + artifact + " (" + (error instanceof Error ? error.message : String(error)) + ")", metadata: { saved: false, reason: "artifact_not_verified" } }
            }
            const resolvedRelative = path.relative(realWorkspace, realArtifact)
            if (resolvedRelative === ".." || resolvedRelative.startsWith(".." + path.sep) || path.isAbsolute(resolvedRelative)) {
              return { title: "Recon checkpoint rejected", output: "Artifact resolves outside the canonical target workspace: " + artifact, metadata: { saved: false, reason: "artifact_symlink_escape" } }
            }
            if (phase === "reporting" && resolvedRelative.split(path.sep).join("/") === "reports/recon-final.md") finalReconReportVerified = true
          }
          if (phase === "reporting" && !finalReconReportVerified) {
            return { title: "Recon report rejected", output: "The reporting phase requires a verified reports/recon-final.md artifact. Include that exact path and complete report before marking Recon finished.", metadata: { saved: false, reason: "final_recon_report_required" } }
          }
          const reportedPaths = new Set(params.artifacts.map((artifact) => {
            const candidate = path.isAbsolute(artifact) ? path.resolve(artifact) : path.resolve(realWorkspace, artifact)
            return path.relative(realWorkspace, candidate).split(path.sep).join("/")
          }))
          const missingRequired = missingRequiredReconArtifacts(phase, [...reportedPaths])
          if (missingRequired.length) {
            return {
              title: "Recon checkpoint rejected",
              output: "Cannot complete " + phase + " without its canonical output file(s): " + missingRequired.join(", ") + ". Create/update these files with verified results, including an explicit zero-result or incomplete status when applicable, then retry.",
              metadata: { saved: false, reason: "canonical_artifact_required", phase, missing_artifacts: missingRequired },
            }
          }
          for (const required of RECON_PHASE_REQUIRED_FLAT_ARTIFACTS[phase] ?? []) {
            try {
              const content = await fs.readFile(path.join(realWorkspace, required), "utf-8")
              if (!content.trim()) {
                return {
                  title: "Recon checkpoint rejected",
                  output: "Cannot complete " + phase + ": canonical artifact is empty: " + required + ". Record verified counts or an explicit zero-result/incomplete status.",
                  metadata: { saved: false, reason: "canonical_artifact_empty", phase, artifact: required },
                }
              }
            } catch (error) {
              return {
                title: "Recon checkpoint rejected",
                output: "Cannot read canonical artifact " + required + " for " + phase + ": " + (error instanceof Error ? error.message : String(error)),
                metadata: { saved: false, reason: "canonical_artifact_unreadable", phase, artifact: required },
              }
            }
          }
          // The canonical subdomains inventory is sufficient to record progress.
          // The detailed per-source ledger is optional evidence, not a completion gate;
          // an incomplete source must not prevent the rest of recon from continuing.
        }
        run.phases[phase] = {
          ...record,
          status,
          finishedAt: new Date().toISOString(),
          summary: params.summary?.trim() ?? record.summary,
          reason: params.reason?.trim(),
          counts: params.counts ?? record.counts,
          artifacts: params.artifacts ?? record.artifacts,
          scopeValidationTarget: phase === "scope_validation" && status === "complete"
            ? params.scope_validation_target?.trim()
            : record.scopeValidationTarget,
        }
        run.currentPhase = null
      }

      run.updatedAt = new Date().toISOString()
      await TargetMemory.writeWorkspaceFile(workspace, relativePath, JSON.stringify(run, null, 2) + "\n")
      const indexPath = path.join(workspace.workspacePath, "runs", "index.json")
      let index: { schemaVersion: number; targetURL: string; runs: Array<Record<string, unknown>> }
      try {
        const parsed = JSON.parse(await fs.readFile(indexPath, "utf-8"))
        if (parsed?.schemaVersion !== 1 || parsed.targetURL !== workspace.targetURL || !Array.isArray(parsed.runs)) throw new Error("Invalid run index identity or schema.")
        index = parsed
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error
        index = { schemaVersion: 1, targetURL: workspace.targetURL, runs: [] }
      }
      const entry = { runID, sessionID, manifest: relativePath, currentPhase: run.currentPhase, updatedAt: run.updatedAt, completedPhases: PHASES.filter((item) => run.phases[item].status === "complete").length, resolvedPhases: PHASES.filter((item) => terminal(run.phases[item].status)).length, totalPhases: PHASES.length }
      const existing = index.runs.findIndex((item) => item.runID === runID)
      if (existing >= 0) index.runs[existing] = entry
      else index.runs.push(entry)
      await TargetMemory.writeWorkspaceFile(workspace, "runs/index.json", JSON.stringify(index, null, 2) + "\n")

      return { title: "Recon checkpoint saved", output: ["Target: " + workspace.targetURL, "Phase: " + phase, "Status: " + run.phases[phase].status, "Manifest: " + absolutePath, "Current phase: " + (run.currentPhase ?? "none"), ...(run.phases[phase].artifacts?.length ? ["Artifacts: " + run.phases[phase].artifacts.join(", ")] : []), ...(run.phases[phase].reason ? ["Reason: " + run.phases[phase].reason] : [])].join("\n"), metadata: { saved: true, target_id: workspace.id, run_id: runID, phase, status: run.phases[phase].status, manifest: absolutePath, current_phase: run.currentPhase } }
    } catch (error) {
      return { title: "Recon checkpoint failed", output: error instanceof Error ? error.message : String(error), metadata: { saved: false, error: true } }
    }
  },
})
