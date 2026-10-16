import fs from "node:fs/promises"
import path from "node:path"
import { createHash } from "node:crypto"
import { TargetMemory, type Workspace } from "./index"

export const RECON_PHASES = [
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

export type ReconPhase = typeof RECON_PHASES[number]
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

export type ReconRunManifest = {
  schemaVersion: 1
  targetURL: string
  targetID: string
  sessionID: string
  createdAt: string
  updatedAt: string
  currentPhase: ReconPhase | null
  phases: Record<ReconPhase, ReconPhaseRecord>
}

export function reconRunID(targetID: string): string {
  return createHash("sha256").update(targetID).digest("hex").slice(0, 20)
}

export function initialReconRun(targetURL: string, targetID: string, sessionID: string): ReconRunManifest {
  const phases = Object.fromEntries(RECON_PHASES.map((phase) => [phase, { status: "pending" as const }])) as Record<ReconPhase, ReconPhaseRecord>
  const now = new Date().toISOString()
  return { schemaVersion: 1, targetURL, targetID, sessionID, createdAt: now, updatedAt: now, currentPhase: null, phases }
}

export function parseReconRun(raw: string, workspaceID: string, targetURL: string): ReconRunManifest {
  const parsed = JSON.parse(raw) as ReconRunManifest
  if (
    parsed?.schemaVersion !== 1 ||
    parsed.targetID !== workspaceID ||
    parsed.targetURL !== targetURL ||
    typeof parsed.sessionID !== "string" ||
    !parsed.phases ||
    !RECON_PHASES.every((phase) => parsed.phases[phase] && ["pending", "running", "complete", "blocked", "failed", "unavailable"].includes(parsed.phases[phase].status))
  ) throw new Error("Recon run manifest has invalid identity or schema; refusing to overwrite it.")
  return parsed
}

function terminal(status: ReconPhaseStatus): boolean {
  return status === "complete" || status === "unavailable"
}

/** Pure prerequisite check shared by the runtime gate and unit tests. */
export function unresolvedReconPrerequisites(
  phase: ReconPhase,
  phases: Record<ReconPhase, ReconPhaseRecord>,
): ReconPhase[] {
  const earlier = RECON_PHASES.slice(0, RECON_PHASES.indexOf(phase))
  const unresolved = earlier.filter((item) =>
    item === "scope_validation" || item === "workspace_setup" ||
    (phase === "vulnerability_testing" && item === "endpoint_inventory")
      ? phases[item].status !== "complete"
      : !terminal(phases[item].status),
  )
  if (phase !== "scope_validation" && phase !== "workspace_setup" && phases.scope_validation.status !== "complete" && !unresolved.includes("scope_validation")) {
    unresolved.unshift("scope_validation")
  }
  return unresolved
}

/** Fail-closed runtime gate for active scanner and web-recon tools. */
export async function reconPhaseGate(
  workspace: Workspace,
  requiredPhase: ReconPhase,
): Promise<{ allowed: boolean; reason: string; manifestPath: string }> {
  const byID = new Map(TargetMemory.list().map((item) => [item.id, item]))
  let root = workspace
  const seen = new Set<string>()
  while (root.parentTargetID && !seen.has(root.id)) {
    seen.add(root.id)
    const parent = byID.get(root.parentTargetID)
    if (!parent) break
    root = parent
  }
  const manifestPath = path.join(root.workspacePath, "runs", "recon-" + reconRunID(root.id) + ".json")
  let run: ReconRunManifest
  try {
    run = parseReconRun(await fs.readFile(manifestPath, "utf-8"), root.id, root.targetURL)
  } catch (error) {
    return {
      allowed: false,
      reason: "No valid recon checkpoint manifest exists for the root target (" + (error instanceof Error ? error.message : String(error)) + ").",
      manifestPath,
    }
  }
  if (run.phases[requiredPhase].status !== "running") {
    return {
      allowed: false,
      reason: "Required phase " + requiredPhase + " must be explicitly started; current status is " + run.phases[requiredPhase].status + ".",
      manifestPath,
    }
  }
  const unresolved = unresolvedReconPrerequisites(requiredPhase, run.phases)
  if (unresolved.length) {
    return {
      allowed: false,
      reason: "Required earlier phases are unresolved: " + unresolved.map((phase) => phase + "=" + run.phases[phase].status).join(", "),
      manifestPath,
    }
  }
  return { allowed: true, reason: "phase gate passed", manifestPath }
}
