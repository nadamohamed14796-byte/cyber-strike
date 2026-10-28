import fs from "node:fs/promises"
import path from "node:path"
import { createHash } from "node:crypto"
import { TargetMemory, type TargetScope, type Workspace } from "./index"

export const RECON_PHASES = [
  "scope_validation",
  "workspace_setup",
  "asset_discovery",
  "live_hosts_ports",
  "url_collection",
  "javascript_analysis",
  "parameter_discovery",
  "directory_fuzzing",
  "endpoint_inventory",
  "parameter_fuzzing",
  "vulnerability_testing",
  "reporting",
] as const

export type ReconPhase = typeof RECON_PHASES[number]
export type ReconPhaseStatus = "pending" | "running" | "complete" | "partial" | "blocked" | "failed" | "unavailable" | "deferred"

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
  /** Fingerprint of the authorization rules that were validated for this run. */
  scopeFingerprint?: string
}

export type ReconRunManifest = {
  schemaVersion: 1
  /** Version of the ordered recon lifecycle. Missing means a pre-adaptive workflow manifest. */
  phaseOrderVersion?: 2
  targetURL: string
  targetID: string
  sessionID: string
  createdAt: string
  updatedAt: string
  currentPhase: ReconPhase | null
  phases: Record<ReconPhase, ReconPhaseRecord>
}

type ScopeFingerprintInput = Pick<TargetScope,
  "targetURL" | "status" | "scopeItems" | "excludedItems" | "authorizationSource" | "authorizationReference"
>

/** Stable fingerprint of the effective authorization chain; item ordering alone is not a change. */
export function reconScopeFingerprint(input: ScopeFingerprintInput | readonly ScopeFingerprintInput[]): string {
  const scopes: readonly ScopeFingerprintInput[] = Array.isArray(input)
    ? input as readonly ScopeFingerprintInput[]
    : [input as ScopeFingerprintInput]
  const canonical = scopes.map((scope) => ({
    targetURL: scope.targetURL,
    status: scope.status,
    scopeItems: [...scope.scopeItems].sort(),
    excludedItems: [...scope.excludedItems].sort(),
    authorizationSource: scope.authorizationSource,
    authorizationReference: scope.authorizationReference,
  }))
  return createHash("sha256").update(JSON.stringify(canonical)).digest("hex")
}

export function reconRunID(targetID: string): string {
  return createHash("sha256").update(targetID).digest("hex").slice(0, 20)
}

export function initialReconRun(targetURL: string, targetID: string, sessionID: string): ReconRunManifest {
  const phases = Object.fromEntries(RECON_PHASES.map((phase) => [phase, { status: "pending" as const }])) as Record<ReconPhase, ReconPhaseRecord>
  const now = new Date().toISOString()
  return { schemaVersion: 1, phaseOrderVersion: 2, targetURL, targetID, sessionID, createdAt: now, updatedAt: now, currentPhase: null, phases }
}

export function parseReconRun(raw: string, workspaceID: string, targetURL: string): ReconRunManifest {
  const parsed = JSON.parse(raw) as ReconRunManifest
  const phases = parsed?.phases as Partial<Record<ReconPhase, ReconPhaseRecord>> | undefined
  const validStatus = (record: ReconPhaseRecord | undefined) =>
    !!record && ["pending", "running", "complete", "partial", "blocked", "failed", "unavailable", "deferred"].includes(record.status)
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
  const needsPhaseOrderMigration = parsed.phaseOrderVersion !== 2
  if (missingPhases.length || needsPhaseOrderMigration) {
    for (const phase of missingPhases) {
      phases[phase] = {
        status: "pending",
        reason: "New required recon phase: " + phase + ". Existing downstream completion must be revalidated.",
      }
    }
    // A newly introduced path-discovery phase can discover JavaScript assets that
    // were not in the earlier URL set. Revalidate JS and everything downstream when
    // migrating a manifest that has no directory_fuzzing checkpoint.
    const earliestMissing = missingPhases.length
      ? Math.min(...missingPhases.map((phase) => RECON_PHASES.indexOf(phase)))
      : RECON_PHASES.length
    // A changed lifecycle invalidates JS and every later phase, but preserves verified
    // discovery inventories. A newly added directory phase also invalidates JS because
    // its results can reveal additional bundles that were not in the old URL set.
    const revalidateFrom = needsPhaseOrderMigration || missingPhases.includes("directory_fuzzing")
      ? RECON_PHASES.indexOf("javascript_analysis")
      : earliestMissing + 1
    const resumeFrom = needsPhaseOrderMigration || missingPhases.includes("directory_fuzzing")
      ? RECON_PHASES.indexOf("javascript_analysis")
      : earliestMissing
    const migrationReason = needsPhaseOrderMigration
      ? "Re-run required after recon workflow order migration to phaseOrderVersion 2."
      : "Re-run required after adding earlier recon phase(s): " + missingPhases.join(", ") + "."
    for (const phase of RECON_PHASES.slice(revalidateFrom)) {
      const previous = phases[phase]
      if (previous && previous.status !== "pending") {
        phases[phase] = {
          ...previous,
          status: "pending",
          finishedAt: undefined,
          reason: migrationReason,
        }
      }
    }
    parsed.currentPhase = RECON_PHASES[resumeFrom] ?? null
    parsed.updatedAt = new Date().toISOString()
    parsed.phaseOrderVersion = 2
  }
  parsed.phaseOrderVersion = 2
  parsed.phases = phases as Record<ReconPhase, ReconPhaseRecord>
  return parsed
}

/** Reset downstream checkpoints when a previously deferred phase is explicitly reopened. */
export function invalidateReconDownstreamPhases(
  phase: ReconPhase,
  phases: Record<ReconPhase, ReconPhaseRecord>,
  reason: string,
): ReconPhase[] {
  const index = RECON_PHASES.indexOf(phase)
  const downstream = RECON_PHASES.slice(index + 1)
  for (const item of downstream) {
    // Mark downstream results stale without dropping their evidence links/counts.
    // Their artifacts may still be useful while the corresponding phases are rerun.
    phases[item] = {
      ...phases[item],
      status: "pending",
      startedAt: undefined,
      finishedAt: undefined,
      reason,
    }
  }
  return downstream
}

/**
 * Preserve the planned phase order without trapping the run: ordinary earlier
 * phases resolve as complete, partial, unavailable, or deferred. Failed/blocked
 * work must be retried once with a material change or explicitly handed off.
 * Scope, workspace, and the endpoint inventory for active testing remain hard gates.
 */
function terminal(status: ReconPhaseStatus): boolean {
  return status === "complete" || status === "partial" || status === "unavailable" || status === "deferred"
}

export function unresolvedReconPrerequisites(
  phase: ReconPhase,
  phases: Record<ReconPhase, ReconPhaseRecord>,
): ReconPhase[] {
  const index = RECON_PHASES.indexOf(phase)
  const earlier = RECON_PHASES.slice(0, index)
  const unresolved: ReconPhase[] = []

  if (phase !== "scope_validation" && phases.scope_validation.status !== "complete") {
    unresolved.push("scope_validation")
  }
  if (phase !== "scope_validation" && phase !== "workspace_setup" &&
      phases.workspace_setup.status !== "complete") {
    unresolved.push("workspace_setup")
  }

  for (const prior of earlier) {
    if (prior === "scope_validation" || prior === "workspace_setup") continue
    // Optional active tests are not prerequisites for a recon-only report. A
    // started/failed test still needs an explicit outcome before the report.
    if (phase === "reporting" &&
        (prior === "parameter_fuzzing" || prior === "vulnerability_testing") &&
        phases[prior].status === "pending") continue
    // A user may request vulnerability testing without separately requesting
    // parameter fuzzing; pending means it was not part of this run.
    if (phase === "vulnerability_testing" && prior === "parameter_fuzzing" &&
        phases[prior].status === "pending") continue
    if ((phase === "parameter_fuzzing" || phase === "vulnerability_testing") &&
        prior === "endpoint_inventory") {
      if (phases.endpoint_inventory.status !== "complete") unresolved.push("endpoint_inventory")
      continue
    }
    if (!terminal(phases[prior].status)) unresolved.push(prior)
  }

  return [...new Set(unresolved)]
}

/** Pure execution decision used by the runtime gate and unit tests.
 *
 * The checkpoint owns workflow order and prerequisites, not a phase-to-tool
 * allowlist. The phase inferred from a CLI name or tool wrapper is advisory.
 * Normal recon/support tools may contribute to the single active checkpoint;
 * active parameter fuzzing and vulnerability testing require their explicit
 * checkpoint to be active after scope, workspace, and endpoint inventory are complete.
 */
export function reconPhaseStartDecision(
  phase: ReconPhase,
  phases: Record<ReconPhase, ReconPhaseRecord>,
): { allowed: boolean; reason: string; unresolved: ReconPhase[] } {
  const unresolved = unresolvedReconPrerequisites(phase, phases)
  if (unresolved.length > 0) {
    return {
      allowed: false,
      reason: "Checklist is waiting for earlier phase(s) to be resolved: " +
        unresolved.map((item) => item + "=" + phases[item].status).join(", "),
      unresolved,
    }
  }
  return { allowed: true, reason: "earlier phases are verified or explicitly handed off; hard safety prerequisites passed", unresolved: [] }
}

export function reconPhaseExecutionDecision(
  requiredPhase: ReconPhase,
  phases: Record<ReconPhase, ReconPhaseRecord>,
): { allowed: boolean; reason: string } {
  // The checkpoint tracks progress; it must not restrict ordinary recon tools to
  // a preassigned phase or block useful collection because a prior phase is stale.
  // Authorization is still enforced by reconPhaseGate and each request-level tool.
  if (requiredPhase !== "parameter_fuzzing" && requiredPhase !== "vulnerability_testing") {
    return {
      allowed: true,
      reason: "ordinary reconnaissance tools are not restricted by checkpoint phase or prerequisite status",
    }
  }

  // Active parameter fuzzing and vulnerability testing are opt-in and must follow the endpoint inventory.
  const phaseLabel = requiredPhase === "vulnerability_testing" ? "vulnerability-testing" : requiredPhase
  if (phases[requiredPhase].status !== "running") {
    return {
      allowed: false,
      reason: requiredPhase === "vulnerability_testing"
        ? "Vulnerability testing is opt-in; explicitly begin vulnerability-testing only after endpoint_inventory is complete and the user has requested active testing."
        : phaseLabel + " is opt-in; explicitly begin " + phaseLabel + " only after endpoint_inventory is complete and the user has requested active testing.",
    }
  }
  const unresolved = unresolvedReconPrerequisites(requiredPhase, phases)
  if (unresolved.length > 0) {
    return {
      allowed: false,
      reason: phaseLabel + " requires earlier phases to be completed or explicitly handed off: " +
        unresolved.map((item) => item + "=" + phases[item].status).join(", "),
    }
  }
  return { allowed: true, reason: "explicit " + phaseLabel + " checkpoint and prerequisites passed" }
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

  // Request-level scope checks happen in each caller before this gate. Ordinary
  // recon collectors do not need a phase manifest; active testing phases do.
  if (requiredPhase !== "parameter_fuzzing" && requiredPhase !== "vulnerability_testing") {
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
      reason: "Target scope validation must be completed before vulnerability testing can run. Ordinary reconnaissance tools are not blocked by this testing checkpoint.",
      manifestPath,
    }
  }
  if ((requiredPhase === "parameter_fuzzing" || requiredPhase === "vulnerability_testing") && run.phases[requiredPhase].status !== "running") {
    return {
      allowed: false,
      reason: requiredPhase + " is opt-in. The recon handoff leaves active-testing phases deferred; explicitly begin " + requiredPhase + " only after the user requests active testing.",
      manifestPath,
    }
  }

  const decision = reconPhaseExecutionDecision(requiredPhase, run.phases)
  return { ...decision, manifestPath }
}
