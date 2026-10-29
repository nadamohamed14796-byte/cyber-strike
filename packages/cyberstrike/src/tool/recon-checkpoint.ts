import fs from "node:fs/promises"
import path from "node:path"
import z from "zod"
import { Session } from "../session"
import { TargetMemory, USER_CONFIRMED_SCOPE_SOURCE, type TargetScope, type Workspace } from "../target"
import {
  RECON_PHASES as PHASES,
  invalidateReconDownstreamPhases,
  unresolvedReconPrerequisites,
  initialReconRun as initialRun,
  parseReconRun as parseRun,
  reconRunID,
  reconScopeFingerprint,
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

/** Load the effective authorization chain for a selected workspace, rejecting broken or cross-root ancestry. */
async function scopeFingerprintForWorkspace(start: Workspace, expectedRootID: string): Promise<string> {
  const byID = new Map(TargetMemory.list().map((item) => [item.id, item]))
  const visited = new Set<string>()
  const scopes: TargetScope[] = []
  let current: Workspace | undefined = start
  let foundExpectedRoot = false
  while (current) {
    if (visited.has(current.id)) throw new Error("target workspace ancestry contains a cycle; scope validation cannot be trusted")
    visited.add(current.id)
    if (current.id === expectedRootID) foundExpectedRoot = true
    const scope = await TargetMemory.getScope(current.targetURL)
    if (!scope || scope.status !== "configured" || scope.scopeItems.length === 0) {
      throw new Error("workspace " + current.targetURL + " has no configured persisted scope")
    }
    scopes.push(scope)
    if (!current.parentTargetID) break
    const parent = byID.get(current.parentTargetID)
    if (!parent) throw new Error("parent target workspace is missing; refusing to weaken inherited scope")
    current = parent
  }
  if (!foundExpectedRoot || current?.id !== expectedRootID) {
    throw new Error("the starting asset resolves to a different canonical program workspace; re-check it under the current root")
  }
  return reconScopeFingerprint(scopes)
}

/** Turn a saved, supported scope entry into one concrete URL candidate for initial checkpoint setup. */
function scopeEntryURL(entry: string): string | undefined {
  let value = entry.trim().replace(/^(?:url|domain|wildcard|api|ip address|cidr)\s*:\s*/i, "")
  if (!value || /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(value) || /^\[?[0-9a-f:.]+\]?\/\d{1,3}$/i.test(value)) return undefined
  if (/^https?:\/\/\*\./i.test(value)) value = value.replace(/^(https?:\/\/)\*\./i, "$1")
  else if (value.startsWith("*.")) value = value.slice(2)
  if (!value || /[*{}]/.test(value)) return undefined
  try {
    const url = new URL(/^https?:\/\//i.test(value) ? value : "https://" + value)
    if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password) return undefined
    if (url.pathname.endsWith("/*")) url.pathname = url.pathname.slice(0, -1)
    return url.href
  } catch {
    return undefined
  }
}

/** Choose a concrete URL authorized by the persisted scope; this is setup convenience, not a policy grant. */
async function findAuthorizedScopeStart(workspace: Workspace, scope: TargetScope) {
  const candidates = [...new Set([workspace.targetURL, ...scope.scopeItems.map(scopeEntryURL).filter((item): item is string => Boolean(item))])]
  for (const candidate of candidates) {
    let url: URL
    try {
      url = new URL(candidate)
    } catch {
      continue
    }
    if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password) continue
    try {
      const decision = await TargetMemory.checkURLScope(url.href)
      if (decision.allowed && decision.workspace) return { target: url.href, decision }
    } catch {
      // An unparseable/unresolvable policy entry is not a usable starting asset.
    }
  }
  return undefined
}

export const RECON_PHASE_ARTIFACT_AREAS: Partial<Record<ReconPhase, readonly string[]>> = {
  asset_discovery: ["assets", "recon"],
  live_hosts_ports: ["recon", "scans"],
  url_collection: ["recon", "urls"],
  directory_fuzzing: ["recon", "directories"],
  parameter_discovery: ["recon", "parameters"],
  parameter_fuzzing: ["recon", "parameters"],
  // New endpoint sidecars live under recon/. Historical endpoints/ artifacts are
  // accepted only when the exact path was already saved in this phase's checkpoint.
  javascript_analysis: ["javascript", "recon", "findings", "testing"],
  endpoint_inventory: ["recon"],
  vulnerability_testing: ["findings", "testing", "evidence"],
  reporting: ["reports"],
}

export const RECON_PHASE_REQUIRED_FLAT_ARTIFACTS: Partial<Record<ReconPhase, readonly string[]>> = {
  // Canonical inventories must exist and be non-empty before a phase can be marked complete.
  // A verified zero-result run must write an explicit status/reason rather than an empty file.
  asset_discovery: ["subdomains.txt"],
  live_hosts_ports: ["live-hosts.txt"],
  url_collection: ["urls.txt"],
  parameter_discovery: ["parameters.txt"],
  parameter_fuzzing: ["parameter-tests.md"],
  // These are the canonical handoff files consumed by endpoint_inventory and final reporting.
  javascript_analysis: ["javascript-analysis.md", "endpoints.txt"],
  endpoint_inventory: ["endpoints.txt"],
}

export function missingRequiredReconArtifacts(phase: ReconPhase, reportedPaths: readonly string[]): string[] {
  const normalized = new Set(reportedPaths.map((item) => item.replace(/\\/g, "/").replace(/^\.\/+/, "")))
  return [...(RECON_PHASE_REQUIRED_FLAT_ARTIFACTS[phase] ?? [])].filter((required) => !normalized.has(required))
}

const CANONICAL_INVENTORY_PHASES = new Set<ReconPhase>([
  "asset_discovery",
  "live_hosts_ports",
  "url_collection",
  "parameter_discovery",
])

/**
 * Reject tool logs/error messages masquerading as canonical inventories.
 * Explicit zero-result/incomplete markers allow truthful empty or partial runs.
 */
export function validateCanonicalInventoryContent(phase: ReconPhase, content: string): { valid: boolean; reason?: string; entries: number } {
  if (!CANONICAL_INVENTORY_PHASES.has(phase)) {
    return { valid: Boolean(content.trim()), reason: content.trim() ? undefined : "artifact is empty", entries: 0 }
  }

  const lines = content.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith("#"))
  const statusLine = /^(?:status\s*:\s*)?(?:zero[- ]results?|no (?:results|assets|hosts|urls|parameters) found|incomplete\s*:|partial\s*:)/i
  const statuses = lines.filter((line) => statusLine.test(line))
  const dataLines = lines.filter((line) => !statusLine.test(line))
  const failureLine = /^(?:\[?failed\]?(?:\b|:|\s|$)|error\b|fatal\b|timeout\b|timed out\b|no input\b|usage:|command not found\b|\{.*"(?:error|failed|exception)".*\})/i
  if (dataLines.some((line) => failureLine.test(line))) {
    return { valid: false, reason: "inventory contains tool failure/error lines; keep those in raw logs and only successful normalized records in the canonical file", entries: 0 }
  }
  if (dataLines.length === 0 && statuses.length === 0) {
    return { valid: false, reason: "inventory contains no data rows or explicit zero-result/incomplete status", entries: 0 }
  }
  if (statuses.length > 0 && dataLines.length > 0) {
    return { valid: false, reason: "inventory mixes status markers with data rows; use data rows only or a single explicit zero-result/incomplete status", entries: 0 }
  }

  const seen = new Set<string>()
  for (const line of dataLines) {
    let normalized = line
    if (phase === "asset_discovery") {
      const host = line.replace(/^\*\./, "").replace(/\.$/, "").toLowerCase()
      if (host.includes("://") || host.includes("/") || host.includes(" ") || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$/.test(host)) {
        return { valid: false, reason: "subdomains.txt contains a non-hostname row: " + line, entries: 0 }
      }
      normalized = host
    } else if (phase === "live_hosts_ports" || phase === "url_collection") {
      try {
        const url = new URL(line.startsWith("http://") || line.startsWith("https://") ? line : "https://" + line)
        if (!["http:", "https:"].includes(url.protocol) || !url.hostname || url.username || url.password || (phase === "url_collection" && !/^https?:\/\//i.test(line))) {
          return { valid: false, reason: "inventory contains an invalid URL/host row: " + line, entries: 0 }
        }
        if (phase === "live_hosts_ports" && (url.pathname !== "/" || url.search || url.hash)) {
          return { valid: false, reason: "live-hosts.txt must contain only a hostname or host:port, not a URL path/query/fragment", entries: 0 }
        }
        normalized = phase === "live_hosts_ports"
          ? url.hostname.toLowerCase() + (url.port ? ":" + url.port : "")
          : url.toString()
      } catch {
        return { valid: false, reason: "inventory contains an invalid URL/host row: " + line, entries: 0 }
      }
    }
    if (seen.has(normalized)) {
      return { valid: false, reason: "inventory contains duplicate normalized entries; deduplicate the canonical list before completion", entries: 0 }
    }
    seen.add(normalized)
  }
  return { valid: true, entries: dataLines.length }
}
export type ReconBeginDisposition = "start" | "resume_existing" | "already_resolved"

export function reconBeginDisposition(status: ReconPhaseStatus, _phase: ReconPhase): ReconBeginDisposition {
  if (status === "running") return "resume_existing"
  // "Unavailable" is not a permanent success: tools may be installed or a
  // different method may become available on resume. "Deferred" is also reopenable.
  if (status === "complete") return "already_resolved"
  return "start"
}

const Parameters = z.object({
  action: z.enum(["status", "begin", "complete", "block", "fail", "unavailable", "defer"]),
  target_url: z.string().min(1).describe("Exact existing root or asset workspace URL"),
  scope_validation_target: z.string().min(1).optional().describe("Optional absolute HTTP(S) starting asset. If omitted, use the root URL when authorized, otherwise select a concrete authorized URL from the persisted scope. Saved scope is reused on resume; active requests still enforce scope independently."),
  phase: z.enum(PHASES).optional(),
  summary: z.string().max(4000).optional(),
  reason: z.string().max(2000).optional(),
  counts: z.record(z.string(), z.number().finite().nonnegative()).optional(),
  artifacts: z.array(z.string().min(1)).optional(),
})

export const ReconCheckpointTool = Tool.define<typeof Parameters, Tool.Metadata>("recon_checkpoint", {
  description: [
    "Tracks the canonical recon run, phase status, prerequisites, and artifact checks; it is not a tool allowlist. Ordinary recon tools may run whenever useful, even if an earlier phase record is stale or missing. If a phase is already running, resume it.",
    "Use status to recover progress and begin/complete/block/fail/unavailable/defer to record outcomes. Follow prerequisites for checkpoint transitions, but do not use phase state to restrict ordinary tool selection. For directory/parameter work, save useful wordlists, settings, and results. Record JavaScript correlation artifacts and verify the exact reports/recon-final.md path before reporting completion.",
    "A normal recon run completes verified endpoint inventory and reporting, while vulnerability_testing stays deferred unless the user explicitly requests testing. Testing requires completed endpoint_inventory; refresh the report after testing. Never launch scanners/session_scan automatically.",
    "Scope and workspace setup remain required. Configure and validate new, changed, or unresolved scope once, then persist and reuse that decision on resume. For a program-root policy container, automatically select a concrete authorized URL from the saved manifest when scope_validation_target is omitted; do not prompt the user to re-enter the same scope. Active-request tools independently enforce every concrete URL and redirect.",
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

      // Reuse the saved authorization decision without asking the operator to repeat scope.
      // Only invalidate it when the persisted authorization chain actually changed or
      // the recorded asset is no longer authorized. Older checkpoints are migrated in place.
      if (run.phases.scope_validation.status === "complete") {
        const scopeValidation = run.phases.scope_validation
        const savedFingerprint = scopeValidation.scopeFingerprint
        let validatedTarget = scopeValidation.scopeValidationTarget
        let invalidationReason: string | undefined
        try {
          const persistedScope = await TargetMemory.getScope(workspace.targetURL)
          if (!persistedScope || persistedScope.status !== "configured" || persistedScope.scopeItems.length === 0) {
            invalidationReason = "The persisted authorization scope is missing or unconfigured."
          } else {
            // A legacy checkpoint without a fingerprint can be migrated silently only
            // when its saved scope predates (or matches) the checkpoint. If the policy
            // was edited afterwards, revalidate once rather than assuming it is unchanged.
            if (!savedFingerprint && scopeValidation.finishedAt && persistedScope.configuredAt &&
                Date.parse(persistedScope.configuredAt) > Date.parse(scopeValidation.finishedAt)) {
              invalidationReason = "The persisted authorization scope was updated after this legacy checkpoint; validate the current saved scope once before resuming."
            }
            if (!invalidationReason && !validatedTarget) {
              const recovered = await findAuthorizedScopeStart(workspace, persistedScope)
              if (recovered) validatedTarget = recovered.target
              else invalidationReason = "The saved checkpoint has no starting asset and no concrete authorized URL could be recovered from the persisted scope."
            }
            if (!invalidationReason && validatedTarget) {
              const decision = await TargetMemory.checkURLScope(validatedTarget)
              if (!decision.allowed || !decision.workspace) {
                invalidationReason = "The previously validated starting asset no longer passes persisted scope: " + decision.reason
              } else {
                const currentFingerprint = await scopeFingerprintForWorkspace(decision.workspace, workspace.id)
                if (savedFingerprint && currentFingerprint !== savedFingerprint) {
                  invalidationReason = "The persisted authorization scope or exclusions changed since this recon run was validated; revalidate scope and downstream phases."
                } else if (!savedFingerprint || validatedTarget !== scopeValidation.scopeValidationTarget) {
                  run.phases.scope_validation = {
                    ...scopeValidation,
                    scopeValidationTarget: validatedTarget,
                    scopeFingerprint: currentFingerprint,
                  }
                  run.updatedAt = new Date().toISOString()
                  await TargetMemory.writeWorkspaceFile(workspace, relativePath, JSON.stringify(run, null, 2) + "\n")
                }
              }
            }
          }
        } catch (error) {
          invalidationReason = "The previously validated starting asset's authorization chain could not be revalidated: " +
            (error instanceof Error ? error.message : String(error))
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
        if (record.status === "unavailable" || record.status === "deferred") {
          invalidateReconDownstreamPhases(
            phase,
            run.phases,
            "Revalidate downstream phases because " + phase + " was reopened after being " + record.status + ".",
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
        if (status === "complete") {
          const unresolved = unresolvedReconPrerequisites(phase, run.phases)
          if (unresolved.length > 0) {
            return {
              title: "Recon checkpoint rejected",
              output: "Cannot complete " + phase + " while required earlier phases remain unresolved: " + unresolved.map((item) => item + "=" + run.phases[item].status).join(", ") + ". Finish each phase or record it as unavailable/deferred with a concrete reason; ordinary recon tools remain usable while progress is repaired.",
              metadata: { saved: false, reason: "phase_prerequisites_unresolved", phase, unresolved },
            }
          }
        }
        let validatedScopeFingerprint: string | undefined
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
          let parsedValidationTarget: URL
          let targetDecision: Awaited<ReturnType<typeof TargetMemory.checkURLScope>>
          if (validationTarget) {
            try {
              parsedValidationTarget = new URL(validationTarget)
              if ((parsedValidationTarget.protocol !== "http:" && parsedValidationTarget.protocol !== "https:") ||
                  parsedValidationTarget.username || parsedValidationTarget.password) throw new Error("target must be a credential-free absolute HTTP(S) URL")
            } catch (error) {
              return { title: "Scope validation rejected", output: "scope_validation_target is invalid: " + (error instanceof Error ? error.message : String(error)), metadata: { saved: false, reason: "scope_validation_target_invalid" } }
            }
            try {
              targetDecision = await TargetMemory.checkURLScope(parsedValidationTarget.href)
            } catch (error) {
              return { title: "Scope validation rejected", output: "The starting asset scope check failed: " + (error instanceof Error ? error.message : String(error)), metadata: { saved: false, reason: "scope_validation_check_failed" } }
            }
          } else {
            const recovered = await findAuthorizedScopeStart(workspace, scope)
            if (!recovered) {
              return { title: "Scope validation needs a concrete asset", output: "No concrete authorized starting URL could be selected from the persisted scope. Add an exact in-scope asset to the saved manifest; the same scope does not need to be re-entered.", metadata: { saved: false, reason: "scope_validation_target_unresolved" } }
            }
            parsedValidationTarget = new URL(recovered.target)
            targetDecision = recovered.decision
          }
          if (!targetDecision.allowed || !targetDecision.workspace) {
            return { title: "Scope validation rejected", output: "Cannot complete scope_validation: the starting asset is not authorized by the persisted manifest: " + targetDecision.reason, metadata: { saved: false, reason: "scope_validation_target_out_of_scope", target: parsedValidationTarget.href } }
          }
          try {
            validatedScopeFingerprint = await scopeFingerprintForWorkspace(targetDecision.workspace, workspace.id)
          } catch (error) {
            return {
              title: "Scope validation rejected",
              output: "Cannot complete scope_validation because the starting asset's effective authorization chain is invalid: " + (error instanceof Error ? error.message : String(error)),
              metadata: { saved: false, reason: "scope_validation_workspace_mismatch" },
            }
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
          for (const relative of ["scope", "assets", "runs"]) {
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
            // Preserve a legacy endpoints/ artifact only when the same path is already
            // recorded for this phase; new outputs must use the canonical recon/ area.
            const isPreviouslyRecordedLegacyEndpoint = (
              phase === "javascript_analysis" || phase === "endpoint_inventory"
            ) && resolvedArtifactPath.startsWith("endpoints/") && (record.artifacts ?? []).some((saved) => {
              const savedPath = path.isAbsolute(saved) ? path.resolve(saved) : path.resolve(realWorkspace, saved)
              return path.relative(realWorkspace, savedPath).split(path.sep).join("/") === resolvedArtifactPath
            })
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
            if (requiredAreas && !isFlatArtifact && !isPreviouslyRecordedLegacyEndpoint && !requiredAreas.some((area) => resolvedArtifactPath.startsWith(area + "/"))) {
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
          if (phase === "javascript_analysis") {
            // A non-empty markdown summary alone is not proof that JavaScript was
            // collected and analyzed. Require at least one non-empty source file in
            // the canonical javascript/ directory, or a valid captured-asset index
            // whose referenced files exist inside the same target workspace.
            const javascriptRoot = path.join(realWorkspace, "javascript")
            let hasJavaScriptEvidence = false
            const indexPath = path.join(javascriptRoot, "captured-index.json")
            try {
              const indexInfo = await fs.lstat(indexPath)
              if (!indexInfo.isFile() || indexInfo.isSymbolicLink()) throw new Error("captured index is not a regular file")
              const index = JSON.parse(await fs.readFile(indexPath, "utf-8"))
              if (index?.schemaVersion !== 1 || index?.targetURL !== workspace.targetURL || !Array.isArray(index.assets)) {
                throw new Error("captured index has an invalid schema or target identity")
              }
              for (const asset of index.assets) {
                if (typeof asset?.file !== "string" || asset.file.includes("\\") || asset.file.split("/").some((part: string) => part === "..")) continue
                const candidate = path.resolve(realWorkspace, asset.file)
                const relative = path.relative(realWorkspace, candidate)
                if (!relative || relative === ".." || relative.startsWith(".." + path.sep) || path.isAbsolute(relative)) continue
                try {
                  const info = await fs.lstat(candidate)
                  if (info.isFile() && !info.isSymbolicLink() && info.size > 0) {
                    hasJavaScriptEvidence = true
                    break
                  }
                } catch {
                  // A missing indexed asset does not count as evidence.
                }
              }
            } catch (error) {
              if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
                return { title: "JavaScript checkpoint rejected", output: "Cannot verify captured JavaScript evidence: " + (error instanceof Error ? error.message : String(error)), metadata: { saved: false, reason: "javascript_evidence_index_invalid" } }
              }
            }
            if (!hasJavaScriptEvidence) {
              const pending: string[] = [javascriptRoot]
              while (pending.length && !hasJavaScriptEvidence) {
                const directory = pending.pop()!
                let entries
                try {
                  entries = await fs.readdir(directory, { withFileTypes: true })
                } catch {
                  continue
                }
                for (const entry of entries) {
                  const candidate = path.join(directory, entry.name)
                  if (entry.isSymbolicLink()) continue
                  if (entry.isDirectory()) {
                    if (candidate !== javascriptRoot) pending.push(candidate)
                    continue
                  }
                  if (!entry.isFile() || !/\.(?:m?js|cjs|map)$/i.test(entry.name)) continue
                  try {
                    const info = await fs.lstat(candidate)
                    if (info.isFile() && !info.isSymbolicLink() && info.size > 0) {
                      hasJavaScriptEvidence = true
                      break
                    }
                  } catch {
                    // Ignore files that disappeared while checking.
                  }
                }
              }
            }
            if (!hasJavaScriptEvidence) {
              return {
                title: "JavaScript checkpoint rejected",
                output: "Cannot mark javascript_analysis complete: no non-empty JavaScript/source-map asset was verified under javascript/. Collect and save the in-scope response bodies, then run correlate_javascript. If the target genuinely exposes no JavaScript assets, mark this phase unavailable with that evidence instead of claiming completion.",
                metadata: { saved: false, reason: "javascript_evidence_missing", phase },
              }
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
              if (required === "subdomains.txt" || required === "live-hosts.txt" || required === "urls.txt" || required === "parameters.txt") {
                const inventory = validateCanonicalInventoryContent(phase, content)
                if (!inventory.valid) {
                  return {
                    title: "Recon checkpoint rejected",
                    output: "Cannot complete " + phase + ": " + required + " is not a valid canonical inventory: " + inventory.reason + ". Preserve raw tool output separately, repair the merged inventory, or explicitly record a verified zero-result/incomplete state.",
                    metadata: { saved: false, reason: "canonical_inventory_invalid", phase, artifact: required, entries: inventory.entries },
                  }
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
          // Source-level detail is not a completion gate;
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
          scopeFingerprint: phase === "scope_validation" && status === "complete"
            ? validatedScopeFingerprint
            : record.scopeFingerprint,
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
