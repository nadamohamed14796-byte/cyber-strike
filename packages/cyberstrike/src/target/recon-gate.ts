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
  "directory_fuzzing",
  "parameter_discovery",
  "parameter_fuzzing",
  "javascript_analysis",
  "endpoint_inventory",
  "vulnerability_testing",
  "reporting",
] as const

export type ReconPhase = typeof RECON_PHASES[number]
export type ReconPhaseStatus = "pending" | "running" | "complete" | "blocked" | "failed" | "unavailable" | "deferred"

export type ReconPhaseRecord = {
  status: ReconPhaseStatus
  startedAt?: string
  finishedAt?: string
  summary?: string
  reason?: string
  counts?: Record<string, number>
  artifacts?: string[]
  /** Exact starting asset whose persisted scope check justified this checkpoint. */
  scopeValidationTarget?: string
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
  const phases = parsed?.phases as Partial<Record<ReconPhase, ReconPhaseRecord>> | undefined
  const validStatus = (record: ReconPhaseRecord | undefined) =>
    !!record && ["pending", "running", "complete", "blocked", "failed", "unavailable", "deferred"].includes(record.status)
  // Three phases were added as explicit checkpoints. Older manifests are migrated
  // in memory, and downstream completion is invalidated from the earliest missing phase.
  const introducedPhases = ["directory_fuzzing", "parameter_discovery", "parameter_fuzzing"] as const
  const stableLegacyPhases = RECON_PHASES.filter((phase) => !(introducedPhases as readonly string[]).includes(phase))
  const hasLegacyPhaseSet = !!phases && stableLegacyPhases.every((phase) => validStatus(phases[phase]))
  const invalidIntroducedPhase = !!phases && introducedPhases.some((phase) =>
    Object.prototype.hasOwnProperty.call(phases, phase) && !validStatus(phases[phase]),
  )
  if (
    parsed?.schemaVersion !== 1 ||
    parsed.targetID !== workspaceID ||
    parsed.targetURL !== targetURL ||
    typeof parsed.sessionID !== "string" ||
    !hasLegacyPhaseSet ||
    invalidIntroducedPhase
  ) throw new Error("Recon run manifest has invalid identity or schema; refusing to overwrite it.")
  if (!phases) throw new Error("Recon run manifest has no phase records; refusing to overwrite it.")

  const missingPhases = introducedPhases.filter((phase) => !Object.prototype.hasOwnProperty.call(phases, phase))
  if (missingPhases.length) {
    for (const phase of missingPhases) {
      phases[phase] = {
        status: "pending",
        reason: "New required recon phase: " + phase + ". Existing downstream completion must be revalidated.",
      }
    }
    const earliestMissing = Math.min(...missingPhases.map((phase) => RECON_PHASES.indexOf(phase)))
    for (const phase of RECON_PHASES.slice(earliestMissing + 1)) {
      const previous = phases[phase]
      if (previous && previous.status !== "pending") {
        phases[phase] = {
          ...previous,
          status: "pending",
          finishedAt: undefined,
          reason: "Re-run required after adding earlier recon phase(s): " + missingPhases.join(", ") + ".",
        }
      }
    }
  }
  parsed.phases = phases as Record<ReconPhase, ReconPhaseRecord>
  return parsed
}

function terminal(status: ReconPhaseStatus): boolean {
  return status === "complete" || status === "unavailable" || status === "deferred"
}

/** Reset downstream checkpoints when a previously deferred phase is explicitly reopened. */
export function invalidateReconDownstreamPhases(
  phase: ReconPhase,
  phases: Record<ReconPhase, ReconPhaseRecord>,
  reason: string,
): ReconPhase[] {
  const index = RECON_PHASES.indexOf(phase)
  const downstream = RECON_PHASES.slice(index + 1)
  for (const item of downstream) phases[item] = { status: "pending", reason }
  return downstream
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

/** Pure execution decision used by the runtime gate and unit tests.
 *
 * The checkpoint owns workflow order and prerequisites, not a phase-to-tool
 * allowlist. The phase inferred from a CLI name or tool wrapper is advisory.
 * Normal recon/support tools may contribute to the single active checkpoint;
 * actions classified as vulnerability testing still require that explicit
 * checkpoint to be active after endpoint inventory is complete.
 */
export function reconPhaseExecutionDecision(
  requiredPhase: ReconPhase,
  phases: Record<ReconPhase, ReconPhaseRecord>,
): { allowed: boolean; reason: string } {
  // The checkpoint tracks progress; it must not restrict ordinary recon tools to
  // a preassigned phase or block useful collection because a prior phase is stale.
  // Authorization is still enforced by reconPhaseGate and each request-level tool.
  if (requiredPhase !== "vulnerability_testing") {
    return {
      allowed: true,
      reason: "ordinary reconnaissance tools are not restricted by checkpoint phase or prerequisite status",
    }
  }

  // Vulnerability testing remains explicitly opt-in and must follow endpoint inventory.
  if (phases.vulnerability_testing.status !== "running") {
    return {
      allowed: false,
      reason: "Vulnerability testing is opt-in; explicitly begin vulnerability_testing only after endpoint_inventory is complete and the user has requested targeted testing.",
    }
  }
  if (phases.scope_validation.status !== "complete" ||
      phases.workspace_setup.status !== "complete" ||
      phases.endpoint_inventory.status !== "complete") {
    return {
      allowed: false,
      reason: "Vulnerability testing requires completed scope validation, workspace setup, and endpoint inventory.",
    }
  }
  return { allowed: true, reason: "explicit vulnerability-testing checkpoint and prerequisites passed" }
}

/** Checkpoint gate for explicit vulnerability-testing tools.
 *
 * Ordinary recon callers must enforce persisted scope for each concrete request;
 * their availability does not depend on a checkpoint file or phase status.
 */
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

  // Request-level scope checks happen in each caller before this gate. Do not
  // require a phase manifest for ordinary recon collectors such as subfinder,
  // crt.sh lookups, URL collection, and passive fingerprinting.
  if (requiredPhase !== "vulnerability_testing") {
    return {
      allowed: true,
      reason: "ordinary recon tools are not blocked by checkpoint status; request-level scope checks remain required",
      manifestPath,
    }
  }

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
  if (run.phases.scope_validation.status !== "complete") {
    return {
      allowed: false,
      reason: "Target scope validation must be completed before recon tools can run.",
      manifestPath,
    }
  }
  if (requiredPhase === "vulnerability_testing" && run.phases.vulnerability_testing.status !== "running") {
    return {
      allowed: false,
      reason: "Vulnerability testing is opt-in. The recon handoff leaves this phase deferred; explicitly begin vulnerability_testing only after the user requests targeted testing.",
      manifestPath,
    }
  }

  const decision = reconPhaseExecutionDecision(requiredPhase, run.phases)
  return { ...decision, manifestPath }
}
