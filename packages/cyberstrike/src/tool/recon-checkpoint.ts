import fs from "node:fs/promises"
import path from "node:path"
import { createHash } from "node:crypto"
import z from "zod"
import { Session } from "../session"
import { TargetMemory } from "../target"
import { Tool } from "./tool"

const PHASES = [
  "scope_validation",
  "workspace_setup",
  "asset_discovery",
  "live_hosts_ports",
  "url_collection",
  "javascript_analysis",
  "endpoint_inventory",
  "vulnerability_testing",
  "reporting",
] as const

export type ReconPhase = typeof PHASES[number]
type Phase = ReconPhase
export type ReconPhaseStatus = "pending" | "running" | "complete" | "blocked" | "failed" | "unavailable"

export type ReconPhaseRecord = {
  status: ReconPhaseStatus
  startedAt?: string
  finishedAt?: string
  summary?: string
  reason?: string
  counts?: Record<string, number>
  artifacts?: string[]
}

type ReconRun = {
  schemaVersion: 1
  targetURL: string
  targetID: string
  sessionID: string
  createdAt: string
  updatedAt: string
  currentPhase: Phase | null
  phases: Record<Phase, ReconPhaseRecord>
}

const Parameters = z.object({
  action: z.enum(["status", "begin", "complete", "block", "fail", "unavailable"]),
  target_url: z.string().min(1).describe("Exact existing root or asset workspace URL"),
  phase: z.enum(PHASES).optional(),
  summary: z.string().max(4000).optional(),
  reason: z.string().max(2000).optional(),
  counts: z.record(z.string(), z.number().finite().nonnegative()).optional(),
  artifacts: z.array(z.string().min(1).max(1000)).max(100).optional(),
})

function initialRun(targetURL: string, targetID: string, sessionID: string): ReconRun {
  const phases = Object.fromEntries(PHASES.map((phase) => [phase, { status: "pending" as const }])) as Record<Phase, ReconPhaseRecord>
  const now = new Date().toISOString()
  return { schemaVersion: 1, targetURL, targetID, sessionID, createdAt: now, updatedAt: now, currentPhase: null, phases }
}

function parseRun(raw: string, workspaceID: string, targetURL: string): ReconRun {
  const parsed = JSON.parse(raw) as ReconRun
  if (
    parsed?.schemaVersion !== 1 ||
    parsed.targetID !== workspaceID ||
    parsed.targetURL !== targetURL ||
    typeof parsed.sessionID !== "string" ||
    !parsed.phases ||
    !PHASES.every((phase) => parsed.phases[phase] && ["pending", "running", "complete", "blocked", "failed", "unavailable"].includes(parsed.phases[phase].status))
  ) throw new Error("Recon run manifest has invalid identity or schema; refusing to overwrite it.")
  return parsed
}

function terminal(status: ReconPhaseStatus): boolean {
  return status === "complete" || status === "unavailable"
}

/** Pure prerequisite check shared by the runtime gate and unit tests. */
export function unresolvedReconPrerequisites(phase: ReconPhase, phases: Record<ReconPhase, ReconPhaseRecord>): ReconPhase[] {
  const earlier = PHASES.slice(0, PHASES.indexOf(phase))
  const unresolved = earlier.filter((item) => !terminal(phases[item].status))
  if (phase !== "scope_validation" && phase !== "workspace_setup" && phases.scope_validation.status !== "complete" && !unresolved.includes("scope_validation")) {
    unresolved.unshift("scope_validation")
  }
  return unresolved
}

/**
 * Fail-closed runtime gate used by active web-recon programs. It resolves child
 * asset workspaces to the canonical root and checks the durable run manifest.
 */
export async function reconPhaseGate(
  workspace: import("../target").Workspace,
  requiredPhase: ReconPhase,
): Promise<{ allowed: boolean; reason: string; manifestPath: string }> {
  const all = TargetMemory.list()
  const byID = new Map(all.map((item) => [item.id, item]))
  let root = workspace
  const seen = new Set<string>()
  while (root.parentTargetID && !seen.has(root.id)) {
    seen.add(root.id)
    const parent = byID.get(root.parentTargetID)
    if (!parent) break
    root = parent
  }
  const runID = createHash("sha256").update(root.id).digest("hex").slice(0, 20)
  const manifestPath = path.join(root.workspacePath, "runs", "recon-" + runID + ".json")
  let run: ReconRun
  try {
    run = parseRun(await fs.readFile(manifestPath, "utf-8"), root.id, root.targetURL)
  } catch (error) {
    return { allowed: false, reason: "No valid recon checkpoint manifest exists for the root target (" + (error instanceof Error ? error.message : String(error)) + ").", manifestPath }
  }
  if (run.phases[requiredPhase].status !== "running") {
    return { allowed: false, reason: "Required phase " + requiredPhase + " must be explicitly started; current status is " + run.phases[requiredPhase].status + ".", manifestPath }
  }
  const unresolved = unresolvedReconPrerequisites(requiredPhase, run.phases)
  if (unresolved.length) {
    return { allowed: false, reason: "Required earlier phases are unresolved: " + unresolved.map((phase) => phase + "=" + run.phases[phase].status).join(", "), manifestPath }
  }
  return { allowed: true, reason: "phase gate passed", manifestPath }
}

export const ReconCheckpointTool = Tool.define<typeof Parameters, Tool.Metadata>("recon_checkpoint", {
  description: [
    "Persist and enforce the ordered reconnaissance run state in the target workspace. This is a workflow control, not a scanner.",
    "Call status before deciding what to do. Call begin before each phase and complete/unavailable/block/fail after it, with real counts, artifact paths, and a concise evidence-based summary or reason.",
    "Phases are strictly ordered: scope_validation → workspace_setup → asset_discovery → live_hosts_ports → url_collection → javascript_analysis → endpoint_inventory → vulnerability_testing → reporting. A later phase cannot begin until all earlier phases are complete or explicitly unavailable. Blocked/failed phases must be retried or explicitly resolved; they cannot be silently skipped.",
    "Do not mark a phase complete just because a command ran. Confirm its output and save artifacts first. Expensive vulnerability scanning must not start before the inventory phases are resolved. Existing run manifests resume across turns for the same target and root session.",
    "Every saved artifact path must be inside this target's canonical workspace. This tool does not authorize requests; use scope_check and the persisted scope policy for every active request.",
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
      const runID = createHash("sha256").update(workspace.id).digest("hex").slice(0, 20)
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
      const phaseIndex = PHASES.indexOf(phase)

      if (params.action === "begin") {
        if (phase !== "scope_validation" && phase !== "workspace_setup") {
          const scopeDecision = await TargetMemory.checkURLScope(workspace.targetURL)
          if (!scopeDecision.allowed || scopeDecision.workspace?.id !== workspace.id) {
            return { title: "Recon phase blocked by persisted scope", output: "Cannot begin " + phase + " because the canonical target workspace does not pass its current persisted scope gate: " + scopeDecision.reason, metadata: { saved: false, reason: "persisted_scope_rejected", scope_reason: scopeDecision.reason } }
          }
        }
        const unresolved = unresolvedReconPrerequisites(phase, run.phases)
        if (unresolved.length) {
          return { title: "Recon phase blocked by prerequisites", output: "Cannot begin " + phase + ". Resolve earlier phases first: " + unresolved.map((item) => item + "=" + run.phases[item].status).join(", "), metadata: { saved: false, reason: "prerequisites_unresolved", unresolved } }
        }
        if (record.status === "complete" || record.status === "unavailable") {
          return { title: "Recon phase already resolved", output: phase + " is already " + record.status + ". Inspect its artifacts; do not repeat expensive work unless new evidence invalidates this checkpoint.", metadata: { saved: false, reason: "phase_already_resolved", phase, status: record.status } }
        }
        run.phases[phase] = { ...record, status: "running", startedAt: record.startedAt ?? new Date().toISOString(), finishedAt: undefined, reason: undefined, summary: params.summary ?? record.summary }
        run.currentPhase = phase
      } else {
        if (record.status !== "running") {
          return { title: "Recon checkpoint rejected", output: "Phase " + phase + " is " + record.status + ", not running. Call begin first; the manifest was not changed.", metadata: { saved: false, reason: "phase_not_running", phase, status: record.status } }
        }
        if ((params.action === "block" || params.action === "fail" || params.action === "unavailable") && !params.reason?.trim()) {
          return { title: "Recon checkpoint rejected", output: "A reason is required to mark a phase blocked, failed, or unavailable.", metadata: { saved: false, reason: "reason_required" } }
        }
        const status: ReconPhaseStatus = params.action === "complete" ? "complete" : params.action === "block" ? "blocked" : params.action === "fail" ? "failed" : "unavailable"
        if (status === "complete" && !params.summary?.trim()) {
          return { title: "Recon checkpoint rejected", output: "A verified summary is required before a phase can be marked complete.", metadata: { saved: false, reason: "summary_required" } }
        }
        if (status === "complete" && phase === "scope_validation") {
          const decision = await TargetMemory.checkURLScope(workspace.targetURL)
          if (!decision.allowed || decision.workspace?.id !== workspace.id) {
            return { title: "Scope validation rejected", output: "Cannot mark scope_validation complete: the persisted scope gate did not authorize the canonical target URL. " + decision.reason, metadata: { saved: false, reason: "scope_validation_failed", scope_reason: decision.reason } }
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
        }
        if (status === "complete" && !["scope_validation", "workspace_setup"].includes(phase) && !params.artifacts?.length) {
          return { title: "Recon checkpoint rejected", output: "This phase requires at least one verified artifact path before it can be marked complete. If the source/tool is genuinely unavailable or there were no applicable assets, use unavailable with a reason.", metadata: { saved: false, reason: "artifact_required" } }
        }
        if (status === "complete" && params.artifacts?.length) {
          const realWorkspace = await fs.realpath(workspace.workspacePath)
          for (const artifact of params.artifacts) {
            if (artifact.includes("\\") || artifact.split("/").some((part) => part === "..")) {
              return { title: "Recon checkpoint rejected", output: "Artifact path must remain inside the canonical target workspace: " + artifact, metadata: { saved: false, reason: "unsafe_artifact_path" } }
            }
            const candidate = path.isAbsolute(artifact) ? path.resolve(artifact) : path.resolve(realWorkspace, artifact)
            const relative = path.relative(realWorkspace, candidate)
            if (!relative || relative === "." || relative === ".." || relative.startsWith(".." + path.sep) || path.isAbsolute(relative)) {
              return { title: "Recon checkpoint rejected", output: "Artifact path must point to a file inside the canonical target workspace: " + artifact, metadata: { saved: false, reason: "artifact_outside_workspace" } }
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
      const entry = { runID, sessionID, manifest: relativePath, currentPhase: run.currentPhase, updatedAt: run.updatedAt, completedPhases: PHASES.filter((item) => terminal(run.phases[item].status)).length, totalPhases: PHASES.length }
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
