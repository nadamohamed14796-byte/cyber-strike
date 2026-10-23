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
  unresolvedReconPrerequisites,
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

  if (ledger.schema_version !== 1 || !Array.isArray(ledger.roots) || !Array.isArray(ledger.sources) || !Array.isArray(ledger.hosts)) {
    return { valid: false, reason: "The source ledger has an unsupported or incomplete schema; preserve it and repair/rebuild the ledger before completing asset_discovery." }
  }
  const roots = ledger.roots
  if (!roots.length || roots.some((root) => typeof root !== "string" || !root.trim()) || new Set(roots).size !== roots.length) {
    return { valid: false, reason: "The source ledger must contain a non-empty, duplicate-free root list." }
  }
  const rootSet = new Set(roots as string[])
  const sourceNames = new Set<string>()
  const pairs = new Map<string, Record<string, unknown>>()
  let gaps = 0

  for (const rawRecord of ledger.sources) {
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
        sourcePairs: ledger.sources.length,
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
    if (["failed", "unavailable", "blocked", "skipped"].includes(status)) {
      gaps++
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
  phase: z.enum(PHASES).optional(),
  summary: z.string().max(4000).optional(),
  reason: z.string().max(2000).optional(),
  counts: z.record(z.string(), z.number().finite().nonnegative()).optional(),
  artifacts: z.array(z.string().min(1)).optional(),
})

export const ReconCheckpointTool = Tool.define<typeof Parameters, Tool.Metadata>("recon_checkpoint", {
  description: [
    "Persist and enforce the ordered reconnaissance run state in the target workspace. This is a workflow control, not a scanner.",
    "Call status before deciding what to do. Call begin before each phase and complete/unavailable/block/fail/defer after it, with real counts, artifact paths, and a concise evidence-based summary or reason. During the default recon-only run, defer vulnerability_testing with a reason so reporting can finish without running vulnerability checks automatically. Only begin that phase after the user explicitly requests targeted testing. Deferred means intentionally postponed, not completed or unavailable.",
    "Phases are ordered: scope_validation → workspace_setup → asset_discovery → live_hosts_ports → url_collection → directory_fuzzing → parameter_discovery → parameter_fuzzing → javascript_analysis → endpoint_inventory → vulnerability_testing → reporting. The handoff is deliberate: after endpoint_inventory, defer vulnerability_testing during a normal recon run, then continue to reporting. Do not run vulnerability scanners or session_scan automatically. Only a later explicit user request may begin vulnerability_testing; reopening it invalidates downstream reporting, which must be regenerated afterward. Every completed phase must supply an artifact under its designated workspace area. Directory/parameter fuzzing must save the wordlist, mode, request settings, and normalized results; JavaScript analysis must link source assets, extracted request shapes, and request-correlation evidence. The reporting phase must save reports/recon-final.md and include that exact path in its checkpoint. Scope validation, workspace setup, and endpoint inventory must be complete, never unavailable. Other discovery phases may be explicitly unavailable with a reason, but blocked/failed phases must be resolved before progressing. Do not rerun completed work without new evidence or an explicit reason. If a phase is already running, resume it without calling begin again. Vulnerability testing cannot begin until endpoint inventory is complete and the user explicitly asks for it.",
    "Do not mark a phase complete just because a command ran. Confirm its output and save artifacts first. Expensive vulnerability scanning must not start before the inventory phases are resolved. Existing run manifests resume across turns for the same target and root session.",
    "Every saved artifact path must be inside this target's canonical workspace. This tool does not authorize requests. If scope_validation is not already complete for the unchanged manifest, run scope_check once for the actual starting asset with target_url selecting the canonical program-root workspace; do not check the root container merely because it is the workspace. Reuse that decision; active request tools still enforce persisted scope for each concrete request.",
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
        const unresolved = unresolvedReconPrerequisites(phase, run.phases)
        if (unresolved.length) {
          return { title: "Recon phase blocked by prerequisites", output: "Cannot begin " + phase + ". Resolve earlier phases first: " + unresolved.map((item) => item + "=" + run.phases[item].status).join(", "), metadata: { saved: false, reason: "prerequisites_unresolved", unresolved } }
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
              asset_discovery: ["scope.txt", "subdomains.txt", "subdomain-sources.json", "recon-summary.md"],
              live_hosts_ports: ["live-hosts.txt", "ports.txt", "recon-summary.md"],
              url_collection: ["urls.txt", "recon-summary.md"],
              parameter_discovery: ["parameters.txt", "recon-summary.md"],
              parameter_fuzzing: ["parameter-tests.md", "recon-summary.md"],
              javascript_analysis: ["javascript-analysis.md", "endpoints.txt", "recon-summary.md"],
              endpoint_inventory: ["endpoints.txt", "recon-summary.md"],
              vulnerability_testing: ["findings.md", "recon-summary.md"],
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
          if (phase === "asset_discovery") {
            const reportedPaths = new Set(params.artifacts.map((artifact) => {
              const candidate = path.isAbsolute(artifact) ? path.resolve(artifact) : path.resolve(realWorkspace, artifact)
              return path.relative(realWorkspace, candidate).split(path.sep).join("/")
            }))
            for (const required of ["subdomain-sources.json", "subdomains.txt"]) {
              if (!reportedPaths.has(required)) {
                return {
                  title: "Asset discovery checkpoint rejected",
                  output: "Cannot complete asset_discovery without both canonical artifacts: subdomain-sources.json and subdomains.txt. A host list alone cannot prove that every root/source task finished; resume the existing source ledger and include both verified paths.",
                  metadata: { saved: false, reason: "discovery_ledger_required", missing_artifact: required },
                }
              }
            }
            try {
              const ledgerPath = path.join(realWorkspace, "subdomain-sources.json")
              const hostsPath = path.join(realWorkspace, "subdomains.txt")
              for (const candidate of [ledgerPath, hostsPath]) {
                const info = await fs.lstat(candidate)
                if (!info.isFile() || info.isSymbolicLink()) throw new Error(path.basename(candidate) + " is not a regular file")
              }
              const validation = validateAssetDiscoveryLedger(
                await fs.readFile(ledgerPath, "utf-8"),
                await fs.readFile(hostsPath, "utf-8"),
              )
              if (!validation.valid) {
                return {
                  title: "Asset discovery checkpoint rejected",
                  output: "Cannot mark asset_discovery complete: " + validation.reason,
                  metadata: { saved: false, reason: "discovery_ledger_incomplete", ...validation },
                }
              }
            } catch (error) {
              return {
                title: "Asset discovery checkpoint rejected",
                output: "Cannot verify the canonical subdomain source ledger and host inventory: " + (error instanceof Error ? error.message : String(error)),
                metadata: { saved: false, reason: "discovery_ledger_verification_failed" },
              }
            }
          }
        }
        run.phases[phase] = {
          ...record,
          status,
          finishedAt: new Date().toISOString(),
          summary: params.summary?.trim() ?? record.summary,
          reason: params.reason?.trim(),
          counts: params.counts ?? record.counts,
          artifacts: params.artifacts ?? record.artifacts,
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
